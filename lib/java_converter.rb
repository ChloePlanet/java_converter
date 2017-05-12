require "java_converter/version"

module JavaConverter
  class << self
    def convert_file_to_hex(java_file_path)
      compile_java(java_file_path)
      format_class(java_file_path.gsub(".java", ".class"))

      file = File.new(java_file_path.gsub(".java", ".class.min"),"rb")
      data = file.read
      data.unpack("H*")[0]
    end

    private
    
    def compile_java(file_path)
      system "javac -cp ./lib/lib:. #{file_path}"
    end

    def format_class(file_path)
      system "python3 ./lib/javaclass_format/format_class.py #{file_path}"
    end
  end
end