require 'json'

require_relative '../sbom-tools'
require_relative 'generator'

module OpenVox::SBOMTools
  module SBOM
    DATA_DIR = File.expand_path('sbom', __dir__).freeze

    module_function

    def file_name(project, tag)
      format('%<project>s_%<tag>s.cdx.json', project:, tag:)
    end

    def file_path(project, tag)
      File.join(DATA_DIR, file_name(project, tag))
    end

    def read_file(project, tag)
      File.read(file_path(project, tag))
    end

    def [](project, tag)
      generate!(project, tag)

      JSON.parse(read_file(project, tag))
    end

    def generate!(project, tag)
      file = file_path(project, tag)

      if File.exist?(file)
        $stderr.puts "SBOM already exists: #{file}"
      else
        $stderr.puts "Generating SBOM: #{file}"

        generator = case project
                    when 'openvox-agent', 'openbolt'
                      OpenVox::SBOMTools::Generator::Vanagon.new(file, project, tag)
                    when 'openvox-server', 'openvoxdb'
                      OpenVox::SBOMTools::Generator::Uberjar.new(file, project, tag)
                    end

        generator.generate!
      end
    end
  end
end
