require_relative '../sbom-tools'

module OpenVox::SBOMTools
  module Sources
    require_relative 'sources/github'

    require_relative 'sources/runtime'
    require_relative 'sources/openvox-agent'
  end
end
