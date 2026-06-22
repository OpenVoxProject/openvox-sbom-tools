require_relative 'lib/openvox/sbom-tools'
require_relative 'lib/openvox/sbom-tools/markdown-tables'

def validate_project!(project)
  valid_projects = %w[openvox-agent openbolt]

  unless valid_projects.include?(project)
    raise ArgumentError,
          format('The only valid project arguments for this task are: %<projects>s',
                 projects: valid_projects.join(', '))
  end
end

namespace :vox do
  namespace :sbom do
    desc "Update data files containing component versions."
    task :update_data, [:file] do |_, args|
      OpenVox::SBOMTools::Data.update!(args[:file])
    end

    desc "Generate SBOM for project and tag."
    task :gen, [:project, :tag] do |_, args|
      validate_project!(args[:project])

      OpenVox::SBOMTools::SBOM.generate!(args[:project], args[:tag])
    end

    desc "Print components for project and tag."
    task :components, [:project, :tag] do |_, args|
      validate_project!(args[:project])

      data = OpenVox::SBOMTools::Report.components(args[:project], args[:tag])
      data = data.sort_by {|c| c[:name] }.map {|c| [c[:name], c[:version]]}

      labels = ['Component', 'Version']
      table = OpenVox::SBOMTools::MarkdownTables.make_table(labels, data,
                                                            align: %w[l l],
                                                            is_rows: true)

      $stdout.puts OpenVox::SBOMTools::MarkdownTables.plain_text(table)
    end

    desc "Print component changes between project tags."
    task :component_diff, [:project, :from, :to] do |_, args|
      validate_project!(args[:project])

      data = OpenVox::SBOMTools::Report.component_diff(args[:project],
                                                       args[:from],
                                                       args[:to])
      data = data.sort_by {|c| c.first}

      labels = ['Component', 'Old Version', 'New Version']
      table = OpenVox::SBOMTools::MarkdownTables.make_table(labels, data,
                                                            align: %w[l l l],
                                                            is_rows: true)

      $stdout.puts OpenVox::SBOMTools::MarkdownTables.plain_text(table)
    end

    desc "Print CVEs reported for project and tag."
    task :cves, [:project, :tag, :linkify] do |_, args|
      validate_project!(args[:project])
      args.with_defaults(linkify: false)

      data = OpenVox::SBOMTools::Report.cves(args[:project], args[:tag])
      # Sort by package name, then by CVSS score. Score positions are
      # swapped to create descending order.
      data.sort! {|a, b| [a[:affects].to_s, b[:score]&.to_f] <=> [b[:affects].to_s, a[:score]&.to_f]}

      data = if args[:linkify]
               data.map do |c|
                 [format('[%<id>s](%<url>s)', c),
                  c[:score] || 'N/A',
                  format('`%<affects>s`', c)]
               end
             else
               data.map {|c| [c[:id], c[:score] || 'N/A', c[:affects]]}
             end

      labels = ['Identifier', 'CVSS 3.1 Score', 'Affects']
      table = OpenVox::SBOMTools::MarkdownTables.make_table(labels, data,
                                                            align: %w[l c l],
                                                            is_rows: true)

      $stdout.puts OpenVox::SBOMTools::MarkdownTables.plain_text(table)
    end

    desc "Print CVEs fixes between project tags."
    task :cves_fixed, [:project, :from, :to, :linkify] do |_, args|
      validate_project!(args[:project])
      args.with_defaults(linkify: false)

      data = OpenVox::SBOMTools::Report.cves_fixed(args[:project], args[:from], args[:to])
      # Sort by package name, then by CVSS score. Score positions are
      # swapped to create descending order.
      data.sort! {|a, b| [a[:resolved_by].to_s, b[:score]&.to_f] <=> [b[:resolved_by].to_s, a[:score]&.to_f]}

      data = if args[:linkify]
               data.map do |c|
                 [format('[%<id>s](%<url>s)', c),
                  c[:score] || 'N/A',
                  format('`%<resolved_by>s`', c)]
               end
             else
               data.map {|c| [c[:id], c[:score] || 'N/A', c[:resolved_by]]}
             end

      labels = ['Identifier', 'CVSS 3.1 Score', 'Resolved By']
      table = OpenVox::SBOMTools::MarkdownTables.make_table(labels, data,
                                                            align: %w[l c l],
                                                            is_rows: true)

      $stdout.puts OpenVox::SBOMTools::MarkdownTables.plain_text(table)
    end
  end
end
