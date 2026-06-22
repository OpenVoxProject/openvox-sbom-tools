require 'purl'

require_relative '../sbom-tools'
require_relative 'sbom'

module OpenVox::SBOMTools
  module Report
    module_function

    def components(project, tag)
      sbom = OpenVox::SBOMTools::SBOM[project, tag]

      extract_components = lambda do |bom|
        bom['components'].map do |c|
          map = {version: c['version']}
          map[:name] = if c.key?('purl')
                         Purl.parse(c['purl']).versionless.to_s
                       else
                         c['name']
                       end

          if c.key?('components')
            [map, extract_components.call(c)]
          else
            map
          end
        end
      end

      extract_components.call(sbom).flatten
    end
  end
end
