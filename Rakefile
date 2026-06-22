require_relative 'lib/openvox/sbom-tools'
require_relative 'lib/openvox/sbom-tools/markdown-tables'

namespace :vox do
  namespace :sbom do
    desc "Update data files containing component versions."
    task :update_data, [:file] do |_, args|
      OpenVox::SBOMTools::Data.update!(args[:file])
    end

    desc "Generate SBOM for project and tag."
    task :gen, [:project, :tag] do |_, args|
      OpenVox::SBOMTools::SBOM.generate!(args[:project], args[:tag])
    end

    desc "Print components for project and tag."
    task :components, [:project, :tag] do |_, args|
      data = OpenVox::SBOMTools::Report.components(args[:project], args[:tag])
      data = data.sort_by {|c| c[:name] }.map {|c| [c[:name], c[:version]]}

      labels = ['Component', 'Version']
      table = OpenVox::SBOMTools::MarkdownTables.make_table(labels, data,
                                                            align: %w[l l],
                                                            is_rows: true)

      $stdout.puts OpenVox::SBOMTools::MarkdownTables.plain_text(table)
    end
  end
end
