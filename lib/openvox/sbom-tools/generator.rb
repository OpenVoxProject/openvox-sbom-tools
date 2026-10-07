require_relative '../sbom-tools'

module OpenVox::SBOMTools
  module Generator
    require_relative 'generator/uberjar'
    require_relative 'generator/vanagon'
  end
end
