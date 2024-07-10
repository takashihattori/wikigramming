module Hiki
  class Command
    def call_scheme(exp1, exp2 = nil, limit = 1)
      io = IO.popen "cd /home/hattori; ulimit -t #{limit}; /usr/local/bin/gosh -l./wikigramming/data/wiki.scm 2>&1", 'r+'
      io.puts "(set! *load-path* '(\"./wikigramming/data/text\"))"
      if exp2
        io.puts exp2
      end
      io.puts "(wiki-eval #{exp1})"
      io.puts '(exit)'
      result = io.gets
      output = io.gets
      if result && output
        output = output.chomp
        if output[0] == 34 && output[-1] == 34  # double quote
          output = output[1..-2].gsub('\n', "\n")
        end
        return result.chomp, output
      else
        return "ERROR", "Scheme interpreter is aborted.  Maybe time limit is exceeded."
      end
    end
  end
end
