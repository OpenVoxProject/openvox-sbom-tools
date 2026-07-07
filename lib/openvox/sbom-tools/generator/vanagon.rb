require 'json'
require 'rubygems/version'
require 'rubygems/requirement'

require_relative '../generator'
require_relative '../data'
require_relative '../sbom-ext'

module OpenVox::SBOMTools::Generator
  class Vanagon
    # Metadata for C libraries.
    #
    # CPE is used to match against CVEs published to nvd.nist.gov
    # PURL is used to detect when new releases (git tags) are published.
    METADATA = {
      'augeas'   => {cpe:  'cpe:2.3:a:augeas:augeas:%{version}:*:*:*:*:*:*:*',
                     purl: {type: 'github',
                            namespace: 'hercules-team'}},
      'curl'     => {cpe:  'cpe:2.3:a:haxx:curl:%{version}:*:*:*:*:*:*:*',
                     purl: {type: 'github',
                            namespace: 'curl'}},
      'libffi'   => {cpe:  'cpe:2.3:a:libffi_project:libffi:%{version}:*:*:*:*:*:*:*',
                     purl: {type: 'github',
                            namespace: 'libffi'}},
      'libxml2'  => {cpe:  'cpe:2.3:a:xmlsoft:libxml2:%{version}:*:*:*:*:*:*:*',
                     purl: {type: 'github',
                            namespace: 'gnome'}},
      'libyaml'  => {cpe:  'cpe:2.3:a:pyyaml:libyaml:%{version}:*:*:*:*:*:*:*',
                     purl: {type: 'github',
                            namespace: 'yaml'}},
      'openssl'  => {cpe:  'cpe:2.3:a:openssl:openssl:%{version}:*:*:*:*:*:*:*',
                     purl: {type: 'github',
                            namespace: 'openssl'}},
      'readline' => {cpe:  'cpe:2.3:a:openssl:openssl:%{version}:*:*:*:*:*:*:*'},
      'ruby'     => {cpe:  'cpe:2.3:a:ruby-lang:ruby:%{version}:*:*:*:*:*:*:*',
                     purl: {type: 'github',
                            namespace: 'ruby'}},
    }

    # Updates to gems bundled with Ruby
    #
    # Key is a tuple of runtime version constraints, then ruby version
    # constraints. Value is a list of updates.
    BUNDLED_GEM_UPDATES = {
      [['>= 2026.05.11.1'], ['~> 3.2']] => {'net-imap' => '0.4.24',
                                            'erb'      => '4.0.3.1'},
      [['>= 2026.06.24.1'], ['~> 3.2']] => {'net-imap' => '0.6.4.1'},
    }

    def initialize(file, project, tag)
      @file    = file
      @project = project
      @tag     = tag
    end

    def generate!
      sbom = make_sbom(@project, @tag)

      File.write(@file, sbom.output)
    end

    # private

    def make_sbom(project, tag)
      sbom = Sbom::Data::Sbom.new
      # A sub-sbom for gems contained with ruby.
      ruby_sbom = Sbom::Data::Sbom.new

      meta = Sbom::Data::Document.new
      meta.name = project
      meta.metadata_version = tag

      sbom.add_document(meta)

      project_components = OpenVox::SBOMTools::Data.vanagon_components(project, tag)
      runtime_name    = project_components.keys.find {|k| k =~ /-runtime$/}
      runtime_version = Gem::Version.new(project_components[runtime_name])

      project_components.each do |name, version|
        # version-less components are usually internal project build steps
        next if version.nil?

        # OpenSSL and Ruby have versions baked into the name as they
        # are the components that tend to differ between major releases.
        name = 'openssl' if name =~ /^openssl-\d/
        name = 'ruby' if name =~ /^ruby-\d/

        pkg = Sbom::Data::Package.new

        if name.match?(/rubygem-.*/)
          pkg.name = name.split('-')[1..-1].join('-')
          pkg.version = version
          pkg.generate_purl(type: 'gem')
        else
          pkg.name = name
          pkg.version = version

          if (pkg_meta = METADATA[name])
            pkg.generate_purl(**pkg_meta[:purl]) if pkg_meta.key?(:purl)
            pkg.set_cpe(format(pkg_meta[:cpe], version:)) if pkg_meta.key?(:cpe)
          end
        end

        # Populate sub-BOM for Ruby
        if name == 'ruby'
          pkg.package_type = 'platform'
          ruby_version = Gem::Version.new(version)

          gems = OpenVox::SBOMTools::Data.std_gems(version)

          BUNDLED_GEM_UPDATES.each do |(runtime_requirement, ruby_requirement), update|
            runtime_requirement = Gem::Requirement.new(*runtime_requirement)
            ruby_requirement = Gem::Requirement.new(*ruby_requirement)

            if runtime_requirement.satisfied_by?(runtime_version) && ruby_requirement.satisfied_by?(ruby_version)
              gems.merge!(update)
            end
          end

          gems.each do |gem_name, gem_version|
            gem = Sbom::Data::Package.new
            gem.name = gem_name
            gem.version = gem_version
            gem.generate_purl(type: 'gem')

            ruby_sbom.add_package(gem)
          end
        end

        sbom.add_package(pkg)
      end

      ruby_gen = Sbom::Generator.new(sbom_type: :cyclonedx, format: :json)
      ruby_gen.generate('ruby', ruby_sbom)
      ruby_info = ruby_gen.to_h

      generator = Sbom::Generator.new(sbom_type: :cyclonedx, format: :json)
      generator.generate(project, sbom)

      # Hackish, but the SBOM library does not currently support
      # nested component lists.
      ruby = generator.to_h['components'].find {|c| c['name'] == 'ruby'}
      ruby['components'] = ruby_info['components']

      generator
    end
  end
end
