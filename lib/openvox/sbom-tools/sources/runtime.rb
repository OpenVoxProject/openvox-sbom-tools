require_relative 'vanagon'

module OpenVox::SBOMTools::Sources
  class Runtime < Vanagon
    def initialize(data_file, repo:)
      @first_tag = '202501081'
      @projects = %w[agent-runtime-main
                     agent-runtime-8.x
                     openbolt-runtime]

      super
    end

    def platform_list(tag, project)
      # TODO: Memoize so that JSON is not re-parsed every time.
      platforms = OpenVox::SBOMTools::Data['platforms.json']

      # TODO: Make sure this is tru going all the way back to 202510080
      case project
      when 'agent-runtime-8.x', 'openbolt-runtime'
        platforms['8.x']['vanagon']
      else
        platforms['main']['vanagon']
      end
    end
  end
end
