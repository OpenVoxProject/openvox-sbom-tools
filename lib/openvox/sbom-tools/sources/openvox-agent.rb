require_relative 'vanagon'

module OpenVox::SBOMTools::Sources
  class OpenVoxAgent < Vanagon
    def initialize(data_file, repo:, path:)
      @first_tag = '8.23.0'
      @projects = %w[openvox-agent]

      super
    end

    def platform_list(tag, project)
      # TODO: Memoize so that JSON is not re-parsed every time.
      platforms = OpenVox::SBOMTools::Data['platforms.json']

      case tag
      when /^8/
        platforms['8.x']['vanagon']
      else
        platforms['main']['vanagon']
      end
    end
  end
end
