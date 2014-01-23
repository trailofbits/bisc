require 'rex/elfparsey'
require 'bisc/elf/string_table'

module BISC
  module ELF
    class Executable

      attr_accessor :elf, :header, :isource, :sections, :imports, :segments

      def initialize(path)
        @elf = Rex::ElfParsey::Elf.new_from_file(path, true)
        @header = @elf.elf_header
        @isource = @elf.isource
        @sections = {}
        @imports = {}
        @segments = @elf.program_header

        _load_sections
        _load_dynstr
        _load_symbol_table
        _load_plt
      end

      private

      def _load_sections
        str_header = ELF32_SHDR_LSB.make_struct
        str_header.from_s(@isource.read(
          @header.e_shoff + @header.e_shstrndx * @header.e_shentsize,
          @header.e_shentsize
        ))

        str_table = StringTable.new(str_header, @isource)

        @header.e_shnum.times do |i|
          shdr = ELF32_SHDR_LSB.make_struct
          shdr.from_s(@isource.read(
            @header.e_shoff + i * @header.e_shentsize,
            @header.e_shentsize,
          ))

          name = str_table[shdr['sh_name'].value]
          @sections[name] = shdr
        end
      end

      def _load_symbol_table
        shdr = @sections['.dynsym']
        num_entries = shdr['sh_size'].value / shdr['sh_entsize'].value
        @symbols = num_entries.times.map do |i|
          ent = ELF32_SYM_LSB.make_struct
          ent.from_s(@isource.read(
            shdr['sh_offset'].value + i * shdr['sh_entsize'].value,
            shdr['sh_entsize'].value,
          ))
          ent
        end
      end

      def _load_plt
        shdr = @sections['.rel.plt']
        num_entries = shdr['sh_size'].value / shdr['sh_entsize'].value
        num_entries.times do |i|
          ent = ELF32_REL_LSB.make_struct
          ent.from_s(@isource.read(
            shdr['sh_offset'].value + i * shdr['sh_entsize'].value,
            shdr['sh_entsize'].value,
          ))

          index = ELF32_R_SYM.call(ent['r_info'].value)
          sym = @symbols[index]
          name = @dynstr[sym['st_name'].value]
          @imports[name] = ent['r_offset'].value
        end
      end

      def _load_dynstr
        shdr = @sections['.dynstr']
        @dynstr = StringTable.new(shdr, @isource)
      end

      ELF32_SHDR_LSB = Rex::Struct2::CStructTemplate.new(
        ['uint32v', 'sh_name', 0],
        ['uint32v', 'sh_type', 0],
        ['uint32v', 'sh_flags', 0],
        ['uint32v', 'sh_addr', 0],
        ['uint32v', 'sh_offset', 0],
        ['uint32v', 'sh_size', 0],
        ['uint32v', 'sh_link', 0],
        ['uint32v', 'sh_info', 0],
        ['uint32v', 'sh_addralign', 0],
        ['uint32v', 'sh_entsize', 0],
      )

      ELF32_SYM_LSB = Rex::Struct2::CStructTemplate.new(
        ['uint32v', 'st_name', 0],
        ['uint32v', 'st_value', 0],
        ['uint32v', 'st_size', 0],
        ['uint8', 'st_info', 0],
        ['uint8', 'st_other', 0],
        ['uint16v', 'st_shndx', 0],
      )

      ELF32_REL_LSB = Rex::Struct2::CStructTemplate.new(
        ['uint32v', 'r_offset', 0],
        ['uint32v', 'r_info', 0],
      )

      ELF32_R_SYM = -> (val) { val >> 8 }
      ELF32_R_TYPE = -> (val) { val & 0xff }
      ELF32_R_INFO = -> (sym, type) { (sym << 8) + (type & 0xff) }

    end
  end
end

