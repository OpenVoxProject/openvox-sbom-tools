require_relative '../sbom-tools'
require_relative 'sources'

module OpenVox::SBOMTools
  module Data
    DATA_DIR = File.expand_path('data', __dir__).freeze

    DATA_FILES = {
      'ruby_default_gems.json' => {repo: 'janlelis/stdgems',
                                   branch: 'main',
                                   path: 'default_gems.json'},
      'ruby_bundled_gems.json' => {repo: 'janlelis/stdgems',
                                   branch: 'main',
                                   path: 'bundled_gems.json'},

      'platforms.json' => {repo: 'OpenVoxProject/shared-actions',
                           branch: 'main',
                           path: 'platforms.json'},

      'runtime_component_info.json' => {repo: 'OpenVoxProject/puppet-runtime',
                                        branch: 'main',
                                        path: 'component_info.json'},
    }

    module_function

    def file_path(name)
      File.join(DATA_DIR, name)
    end

    def read_file(name)
      File.read(file_path(name))
    end

    def update!(specific_file = nil)
      DATA_FILES.each do |name, opts|
        next unless specific_file.nil? || name == specific_file

        file = file_path(name)
        source = OpenVox::SBOMTools::Sources::GitHub.new(file, **opts)

        source.update!
      end
    end
  end
end
