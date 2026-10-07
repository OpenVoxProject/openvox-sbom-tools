require 'fileutils'
require 'rubygems/package'
require 'stringio'
require 'tmpdir'
require 'zlib'

require_relative '../sbom-tools'
require_relative 'exec'
require_relative 'http'

module OpenVox::SBOMTools
  # The source tarball lein-ezbake builds and the openvox-server and
  # openvoxdb builds publish. Next to the uberjar it carries
  # ext/ezbake.manifest with the dependency tree lein resolved, the
  # install.sh that installs the classpath jars, and the gem lists the
  # package build vendors.
  class EzbakeTarball
    ARTIFACTS_URL = 'https://artifacts.voxpupuli.org'.freeze
    CACHE_DIR = File.join(Dir.home, '.cache', 'openvox-sbom-tools', 'archives').freeze

    MANIFEST = '/ext/ezbake.manifest'.freeze
    INSTALL_SCRIPT = '/install.sh'.freeze
    GEM_INSTALL_SCRIPT = '/ext/build-scripts/install-vendored-gems.sh'.freeze
    GEM_LIST = %r{/ext/build-scripts/[^/]*gem-list[^/]*\.txt\z}
    UBERJAR = %r{\A[^/]+/[^/]+\.jar\z}

    BOUNCYCASTLE = 'org.bouncycastle'.freeze
    BOUNCYCASTLE_ENTRY = %r{(\A|/)org/bouncycastle/}

    # The classpath jars are only known by file name, so their groups are
    # looked up here. An unknown jar fails the run rather than ship nameless.
    CLASSPATH_JAR_GROUPS = {
      /\Abc(pkix|tls|util)?-fips\z/ => BOUNCYCASTLE,
    }.freeze

    MavenArtifact = Struct.new(:group, :artifact, :version, :extension)
    RubyGem = Struct.new(:name, :version)

    # Downloads the tarball of a project tag once into the cache
    def self.fetch(project, tag, fips:)
      suffix = fips ? '-fips_build' : ''
      name = "#{project}-#{tag}#{suffix}.tar.gz"
      path = File.join(CACHE_DIR, name)

      unless File.exist?(path)
        FileUtils.mkdir_p(CACHE_DIR)
        url = "#{ARTIFACTS_URL}/#{project}/#{tag}/#{name}"
        $stderr.puts "Downloading #{url}"
        OpenVox::SBOMTools::HTTP.get_file(url, "#{path}.part")
        File.rename("#{path}.part", path)
      end

      new(path)
    end

    attr_reader :path

    def initialize(path)
      @path = path
      @entries = {}

      gzip = Zlib::GzipReader.new(StringIO.new(File.binread(path)))
      Gem::Package::TarReader.new(gzip).each { |entry| @entries[entry.full_name] = entry.read }
      gzip.close
    end

    # Every maven artifact the package ships, the uberjar contents plus the
    # jars installed next to it. The FIPS build keeps the regular
    # BouncyCastle jars on the lein classpath only to install gems, excludes
    # them from the uberjar and installs the FIPS jars next to it. The
    # uberjar listing proves which case applies.
    def shipped_jars(fips:)
      jars = dependency_tree
      classpath_jars = installed_classpath_jars
      in_tree = jars.any? { |jar| jar.group == BOUNCYCASTLE }
      bouncycastle_entries = uberjar_entries.grep(BOUNCYCASTLE_ENTRY)

      if fips
        unless bouncycastle_entries.empty?
          raise "The FIPS uberjar in #{@path} still contains BouncyCastle classes, such as #{bouncycastle_entries.first}"
        end
        raise "No BouncyCastle FIPS jar is installed by #{@path}" if classpath_jars.none? { |jar| jar.group == BOUNCYCASTLE }

        jars = jars.reject { |jar| jar.group == BOUNCYCASTLE }
      elsif in_tree != bouncycastle_entries.any?
        raise "The manifest and the uberjar in #{@path} disagree about BouncyCastle"
      end

      jars + classpath_jars
    end

    # Each gem list names one gem and version per line, with comment lines
    # starting with a hash sign. The lists the gem install script reads
    # must all be present.
    def gems
      lists = @entries.keys.grep(GEM_LIST)
      if @entries.keys.any? { |name| name.end_with?(GEM_INSTALL_SCRIPT) }
        read(GEM_INSTALL_SCRIPT).scan(/install_gems "\$\{DIR\}\/([^"]+)"/).flatten.each do |file|
          raise "The gem list #{file} is missing from #{@path}" if lists.none? { |list| list.end_with?("/#{file}") }
        end
      end

      lists.flat_map do |list|
        @entries.fetch(list).lines.map(&:strip).filter_map do |line|
          next if line.empty? || line.start_with?('#')

          name, version, rest = line.split
          raise "Cannot read a gem and version from #{line.inspect} in #{list}" if version.nil? || rest

          RubyGem.new(name:, version:)
        end
      end
    end

    # private

    def read(suffix)
      names = @entries.keys.select { |entry_name| entry_name.end_with?(suffix) }
      raise KeyError, "Expected one entry ending with #{suffix} in #{@path}, found #{names.inspect}" unless names.size == 1

      @entries.fetch(names.first)
    end

    # Below the "Dependency tree:" heading the manifest lists the resolved
    # tree as nested lein coordinates such as
    # [org.eclipse.jetty/jetty-server "12.1.12"], at times followed by
    # attributes such as :exclusions, :scope or :extension "pom". A bare
    # name is an artifact whose group is its own name. A classifier names
    # a second file of the same artifact and version, which the SBOM
    # lists once.
    def dependency_tree
      heading, tree = read(MANIFEST).split(/^Dependency tree:\n/, 2)
      raise "No dependency tree heading in the manifest of #{@path}" if tree.nil? || heading.nil?

      artifacts = tree.lines.map(&:chomp).reject(&:empty?).map do |line|
        match = line.match(/\A\s*\[(?<name>[^\s"\]]+) "(?<version>[^"]+)"(?<attributes>.*)\z/)
        raise "Cannot read a dependency from #{line.inspect} in the manifest of #{@path}" if match.nil?

        group, artifact = match[:name].split('/', 2)
        extension = match[:attributes][/:extension "([^"]+)"/, 1]
        MavenArtifact.new(group:, artifact: artifact || group, version: match[:version], extension:)
      end
      raise "No dependencies in the manifest of #{@path}" if artifacts.empty?

      artifacts.uniq
    end

    # install.sh copies the classpath jars that ship with the package into
    # place with lines such as
    # install -m 0644 "ext/classpath-jars/bc-fips-1.0.2.6.jar" "/opt/.../jars/"
    # and every classpath jar the script mentions must be read that way.
    def installed_classpath_jars
      script = read(INSTALL_SCRIPT)
      files = script.scan(%r{install -m \d+(?: -[og] \S+)* "ext/classpath-jars/([^"]+\.jar)"}).flatten.uniq
      mentioned = script.scan(%r{ext/classpath-jars/([^"\s]+\.jar)}).flatten.uniq
      raise "Cannot read the install lines for #{(mentioned - files).inspect} in the install.sh of #{@path}" unless (mentioned - files).empty?

      files.map do |file|
        match = file.match(/\A(?<artifact>.+)-(?<version>\d[^-]*)\.jar\z/)
        raise "Cannot read an artifact and version from the classpath jar #{file}" if match.nil?

        group = CLASSPATH_JAR_GROUPS.find { |pattern, _| pattern.match?(match[:artifact]) }&.last
        raise "No group known for the classpath jar #{file}, add it to CLASSPATH_JAR_GROUPS" if group.nil?

        MavenArtifact.new(group:, artifact: match[:artifact], version: match[:version], extension: nil)
      end
    end

    def uberjar_entries
      names = @entries.keys.grep(UBERJAR)
      raise "Expected one uberjar at the top of #{@path}, found #{names.inspect}" unless names.size == 1

      Dir.mktmpdir('openvox-sbom-tools') do |dir|
        jar = File.join(dir, File.basename(names.first))
        File.binwrite(jar, @entries.fetch(names.first))
        result = OpenVox::SBOMTools::Exec.exec('jar', 'tf', jar)
        raise "Listing the uberjar #{jar} with the jar tool failed. #{result.stderr}" unless result.success?

        entries = result.stdout.lines.map(&:chomp)
        raise "The jar tool listed nothing in the uberjar #{jar}" if entries.empty?

        entries
      end
    end
  end
end
