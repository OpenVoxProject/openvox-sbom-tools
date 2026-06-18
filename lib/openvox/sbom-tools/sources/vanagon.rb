require 'fileutils'
require 'json'
require 'rubygems/version'
require 'stringio'

require_relative '../data'
require_relative '../sources'

module OpenVox::SBOMTools::Sources
  # Abstract base class for Vanagon data
  #
  # For each subclass, you must:
  #
  #  - Assign a value to @first_tag
  #  - Assign an Array to @projects
  #  - Implement the platform_list method
  class Vanagon
    CACHE_DIR = File.join(Dir.home, '.cache', 'openvox-sbom-tools').freeze

    attr_reader :data_file, :cache_dir

    def initialize(data_file, repo:)
      @data_file = data_file
      @repo      = repo
      @cache_dir = FileUtils.mkdir_p(File.join(CACHE_DIR, repo)).first

      init_repo
    end

    def update!
      $stderr.puts "Checking: #{@data_file}"

      repo_tags = list_tags
      data_tags = if File.exist?(@data_file)
                    OpenVox::SBOMTools::Data[File.basename(@data_file)].keys
                  else
                    []
                  end

      tags_to_sync = repo_tags - data_tags

      if tags_to_sync.empty?
        $stderr.puts "Data file up to date: #{@data_file}"
        return
      end

      all_data =  if File.exist?(@data_file)
                    OpenVox::SBOMTools::Data[File.basename(@data_file)]
                  else
                    {}
                  end

      tags_to_sync.each do |tag|
        all_data[tag] = component_info(tag)
      end

      File.write(@data_file, JSON.pretty_generate(all_data))
    end

    # private

    def list_tags
      tags = exec('git', 'tag', '--sort=creatordate', workdir: @cache_dir)
      tags = tags.split("\n")

      tags[tags.find_index(@first_tag)..-1]
    end

    # Sometimes the version is a git ref so extract
    # actual version numbers. Fall back to 0 if nothing
    # usable is found so everything is comparable.
    def parse_version(ver)
      Gem::Version.new(ver.to_s[/\d+(?:\.\d+)+/] || 0)
    end

    def component_info(tag)
      $stderr.puts "Checking out tag #{tag}..."
      exec('git', 'checkout', tag, workdir: @cache_dir)

      project_data = {}

      @projects.each do |project|
        $stderr.puts "Processing project #{project}"
        project_data[project] = {}

        all_platforms = exec('bundle', 'exec', 'vanagon', 'list', '-l',
                              workdir: @cache_dir).split("\n")
        project_platforms = platform_list(tag, project)

        # Platforms will be the intersection of what is available in
        # this check-out and the list from shared-actions
        platforms = all_platforms & project_platforms

        platforms.each do |platform|
          $stderr.puts "  #{platform}"
          output = exec('bundle', 'exec', 'vanagon', 'inspect',
                        project, platform, workdir: @cache_dir)

          platform_data = JSON.parse(output)
          project_data[project][platform] = platform_data.map { |h| [h['name'], h['version'] || h.dig('options', 'ref')] }.to_h
        end
      end

      component_data = project_data.values
                                   .flat_map(&:values).flatten    # [{comp1 => ver1}, {comp2 => ver2}, ...]
                                   .flat_map(&:to_a)              # [[comp1, ver1], [comp2, ver2], ...]
                                   .group_by(&:first)             # { comp1 => [[comp1, ver1], [comp1, ver2], ...], ... }
                                   .transform_values do |pairs|   # { comp1 => verN, ... }
                                     pairs.max_by { |_, ver| parse_version(ver) }.last
                                   end

      { 'components' => component_data, 'projects' => project_data }
    end

    def platform_list(tag, project)
      raise NotImplementedError
    end

    def init_repo
      if Dir.empty?(@cache_dir)
        exec('git', 'clone', "https://github.com/#{@repo}", @cache_dir)
      else
        exec('git', 'fetch', 'origin', '--tags', '--prune', '--prune-tags',
             workdir: @cache_dir)
      end
    end

    # TODO: Should be in a utility module.
    def exec(*command_line, workdir: nil)
      out = StringIO.new
      out_r, out_w = IO.pipe

      opts = {out: out_w, err: $stderr}
      opts[:chdir] = workdir unless workdir.nil?

      pid = Process.spawn(*command_line, opts)

      out_w.close
      reader = Thread.new do
        while line = out_r.gets
          out << line
        end
      end

      Process.wait(pid)
      reader.join

      out.string
    end
  end
end
