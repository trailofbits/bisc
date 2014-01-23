module BISC
  module ELF
    class StringTable
      def initialize(header, isource)
        @header = header
        @contents = isource.read(
          header['sh_offset'].value,
          header['sh_size'].value,
        )
      end

      def string_at_offset(offset)
        stop_index = @contents.index("\0", offset)
        @contents[offset...stop_index]
      end

      alias :[] :string_at_offset

    end
  end
end

