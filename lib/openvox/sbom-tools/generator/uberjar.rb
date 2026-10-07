require_relative '../generator'
require_relative '../ezbake_tarball'
require_relative '../sbom-ext'

module OpenVox::SBOMTools::Generator
  # SBOM for an application shipped as an uberjar, such as openvox-server
  # and openvoxdb, read from the tarball its build published. A project
  # argument ending in -fips names the FIPS build.
  class Uberjar
    def initialize(file, project, tag)
      @file    = file
      @fips    = project.end_with?('-fips')
      @project = project.delete_suffix('-fips')
      @tag     = tag
    end

    def generate!
      tarball = OpenVox::SBOMTools::EzbakeTarball.fetch(@project, @tag, fips: @fips)
      $stderr.puts "Reading #{tarball.path}"

      File.write(@file, make_sbom(tarball.shipped_jars(fips: @fips), tarball.gems).output)
    end

    # private

    def make_sbom(jars, gems)
      sbom = Sbom::Data::Sbom.new

      meta = Sbom::Data::Document.new
      meta.name = @project
      meta.metadata_version = @tag
      sbom.add_document(meta)

      jars.each do |jar|
        add_package(sbom, jar.artifact, jar.version,
                    type: 'maven', namespace: jar.group, qualifiers: {'type' => jar.extension || 'jar'})
      end
      gems.each do |gem|
        add_package(sbom, gem.name, gem.version, type: 'gem')
      end

      generator = Sbom::Generator.new(sbom_type: :cyclonedx, format: :json)
      generator.generate(@project, sbom)

      # The sbom library has no properties on the top level component, so
      # the variant goes in after generation, like the nested Ruby
      # components of the vanagon generator.
      variant = @fips ? 'fips' : 'standard'
      generator.to_h['metadata']['component']['properties'] = [{'name' => 'openvox:variant', 'value' => variant}]

      generator
    end

    # The sbom library keeps one package per name and version, so a second
    # package under the same key must be the same one.
    def add_package(sbom, name, version, **purl)
      pkg = Sbom::Data::Package.new
      pkg.name = name
      pkg.version = version
      pkg.generate_purl(**purl)

      @purls ||= {}
      known = @purls[[name, version]]
      raise "#{known} and #{pkg.purl} would both be listed as #{name} #{version}" if known && known != pkg.purl

      @purls[[name, version]] = pkg.purl
      sbom.add_package(pkg)
    end
  end
end
