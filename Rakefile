require_relative 'lib/openvox/sbom-tools'

namespace :vox do
  namespace :sbom do
    desc "Update data files containing component versions."
    task :update_data, [:file] do |_, args|
      OpenVox::SBOMTools::Data.update!(args[:file])
    end
  end
end
