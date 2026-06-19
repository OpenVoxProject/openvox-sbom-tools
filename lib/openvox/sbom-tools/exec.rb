require_relative '../sbom-tools'

module OpenVox::SBOMTools
  Result = Struct.new(:status, :stdout, :stderr) do
    def success?
      !!status&.success?
    end
  end

  module Exec
    module_function

    def exec(*command_line, workdir: nil)
      out = StringIO.new
      err = StringIO.new
      out_r, out_w = IO.pipe
      err_r, err_w = IO.pipe

      opts = {out: out_w, err: err_w}
      opts[:chdir] = workdir unless workdir.nil?

      pid = Process.spawn(*command_line, opts)

      out_w.close
      err_w.close

      out_reader = Thread.new do
        while line = out_r.gets
          out << line
        end
      end

      err_reader = Thread.new do
        while line = err_r.gets
          err << line
        end
      end

      _, status = Process.wait2(pid)
      out_reader.join
      err_reader.join

      Result.new(status:, stdout: out.string, stderr: err.string)
    end
  end
end
