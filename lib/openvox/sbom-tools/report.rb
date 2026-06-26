require 'json'
require 'purl'
require 'rubygems/version'
require 'rubygems/requirement'

require_relative '../sbom-tools'
require_relative 'exec'
require_relative 'sbom'

module OpenVox::SBOMTools
  module Report
    # Some versions of puppet-runtime carry patches or other fixes
    # that Grype does not recognize.
    RUNTIME_CVE_FIXES = {
      # Augeas CVE, fixed by applying a patch in:
      #   https://github.com/OpenVoxProject/puppet-runtime/commit/4a025e26cdb38e479d1e07d75144c14eb76da909
      '>= 2025.09.04.1' => %w[CVE-2025-2588],
      # LibXML2 CVEs, fixed by upgrading to 2.15.3 in:
      #   https://github.com/OpenVoxProject/puppet-runtime/commit/95e89907f35bdab9e75de61b7cdd3433ae1b749f
      '>= 2026.05.11.1' => %w[CVE-2025-6021 CVE-2025-6170],
    }

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

    def component_diff(project, from, to)
      from = components(project, from)
      to   = components(project, to)

      diff = [from, to].flatten.group_by {|c| c[:name]}.map do |name, data|
        versions = data.map {|d| d[:version]}

        if versions.count > 2
          # There should only be one component of a given name in each
          # release
          $stderr.puts format('WARN: Multiple components named %<name>s found.', name:)
          next
        elsif versions.count == 1
          if to.find {|c| c[:name] == name}
            [name, 'Added', versions[0]]
          else
            [name, versions[0], 'Removed']
          end
        elsif versions.uniq.count == 1
          # No change.
          next
        else
          [name, *versions]
        end
      end

      diff.compact
    end

    def cves(project, tag)
      sbom_path = OpenVox::SBOMTools::SBOM.file_path(project, tag)

      cve_report = OpenVox::SBOMTools::Exec.exec('grype', '--by-cve',
                                                 '--output=cyclonedx-json',
                                                 sbom_path)

      # TODO Handle failures.
      data = JSON.parse(cve_report.stdout)

      cves = data['vulnerabilities'].map do |vuln|
        id = vuln['id']
        url = if id.start_with?('CVE-')
                # Prefer NVD records for assigned CVE IDs.
                format('https://nvd.nist.gov/vuln/detail/%<id>s', id:)
              else
                # Could be something else. Like GitHub.
                vuln['source']['url']
              end
        score = vuln['ratings'].find {|r| r['method'] == 'CVSSv31'}&.dig('score')
        affects = Purl.parse(vuln['affects'].first['ref'])
        # Grype echos PURLs back with data duplicated into the qualifiers
        # hash. Empty this out to tidy output up.
        affects.instance_variable_set(:@qualifiers, {})

        {id:, url:, score:, affects:}
      end

      runtime_component = data['components'].find {|c| c['name'] =~ /-runtime$/}
      runtime_version   = Gem::Version.new(runtime_component['version'])

      fixed_cves = RUNTIME_CVE_FIXES.flat_map do |fix_version, ids|
        if Gem::Requirement.new(fix_version).satisfied_by?(runtime_version)
          ids
        else
          []
        end
      end

      cves.reject! {|c| fixed_cves.include?(c[:id])}

      cves
    end

    def cves_fixed(project, from, to)
      sbom = OpenVox::SBOMTools::SBOM[project, to]
      cves_before = cves(project, from)
      cves_after  = cves(project, to)

      extract_purls = lambda do |bom|
        bom['components'].map do |c|
          purl = if c.key?('purl')
                   Purl.parse(c['purl'])
                 else
                   nil
                 end

          if c.key?('components')
            [purl, extract_purls.call(c)]
          else
            purl
          end
        end.compact
      end

      purls = extract_purls.call(sbom).flatten

      ids_after = cves_after.map {|c| c[:id]}
      fixed = cves_before.select {|c| ! ids_after.include?(c[:id]) }

      fixed.each do |cve|
        cve[:resolved_by] = purls.find {|c| cve[:affects].versionless == c.versionless}
      end

      fixed
    end
  end
end
