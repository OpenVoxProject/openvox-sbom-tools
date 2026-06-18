require 'digest/sha1'
require 'json'
require 'net/http'
require 'openssl'
require 'uri'

require_relative '../sources'

module OpenVox::SBOMTools::Sources
  class GitHub
    attr_reader :data_file

    def initialize(data_file, repo:, branch: 'main', path:)
      @data_file = data_file
      @repo    = repo
      @branch  = branch
      @path    = path
    end

    def update!
      $stderr.puts "Checking: #{@data_file}"
      local_sha   = git_hash
      remote_stat = github_stat

      if local_sha == remote_stat[:sha]
        $stderr.puts "Data file up to date: #{@data_file}"
        return
      end

      download_file(remote_stat[:download_url])
    end

    # private

    def git_hash
      return nil unless File.exist?(@data_file)

      content = File.read(@data_file)

      # Git header format: "blob [bytesize]\0[content]"
      header = "blob #{content.bytesize}\0"

      Digest::SHA1.hexdigest(header + content)
    end

    def github_stat
      url = URI.parse("https://api.github.com/repos/#{@repo}/contents/#{@path}?ref=#{@branch}")

      request = Net::HTTP::Get.new(url)
      request['Accept'] = 'application/vnd.github+json'

      response = Net::HTTP.start(url.hostname, url.port, use_ssl: true) do |http|
        http.request(request)
      end

      if response.code == '200'
        json = JSON.parse(response.body)
        { sha: json['sha'], download_url: json['download_url'] }
      else
        $stderr.puts "GitHub API Error: #{response.code} - #{response.body}"
        nil
      end
    end

    def download_file(download_url)
      url     = URI.parse(download_url)
      request = Net::HTTP::Get.new(url)

      Net::HTTP.start(url.hostname, url.port, use_ssl: true) do |http|
        http.request(request) do |response|
          case response
          when Net::HTTPSuccess
            # Open file in write-binary mode and stream the body segments
            File.open(@data_file, 'wb') do |file|
              response.read_body do |chunk|
                file.write(chunk)
              end
            end

            $stderr.puts "Downloaded - #{download_url}"
          when Net::HTTPRedirection
            # GitHub frequently redirects requests to its underlying asset
            # servers. Recurse using the new location provided
            # in the 'location' header.
            redirect_url = response['location']
            $stderr.puts "Following redirect to: #{redirect_url}"
            download_file(redirect_url)
          else
            raise "Failed to download file. HTTP Status: #{response.code} - #{response.message}"
          end
        end
      end
    end
  end
end
