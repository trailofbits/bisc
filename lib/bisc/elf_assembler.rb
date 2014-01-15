require 'rex/elfparsey'
require 'rex/elfscan'
require 'bisc/assembler'
require 'bisc/elf/executable'

module BISC
  class ELFAssembler < Assembler

    PF_X = (1 << 0)
    PF_W = (1 << 1)
    PT_LOAD = Rex::ElfParsey::ElfBase::PT_LOAD

    #
    # Add and ELF module for to be scanned for usable instructions
    #
    def add_module(path)
      elf = BISC::ELF::Executable.new(path)
      elfname = File.basename(path)
      @modules[elfname] = elf

      if elf.header.e_type == Rex::ElfParsey::ElfBase::ET_DYN
        raise(Error,"#{path} is ASLR enabled...")
      end

      scanner = Rex::ElfScan::Scanner::RegexScanner.new(elf.elf)
      elf.segments.each do |header|
        next unless header.p_type == PT_LOAD && header.p_flags & PF_X == PF_X

        PATTERNS.keys.each do |pattern|
          re = Regexp.new("#{pattern}(\\xC3)", nil, 'n')
          scanner.regex = re
          hits = scanner.scan_segment(header)

          hits.each do |hit|
            address = elf.elf.rva_to_offset(hit[0])
            bytes = hit[1][0]
            matchdata = re.match([bytes].pack('H*'))

            if matchdata
              sym = PATTERNS[pattern].call(matchdata)

              if @instructions[sym] == nil
                @instructions[sym] = []
              end

              @instructions[sym].push(address)
            end
          end
        end
      end

      # Add slack space
      elf.segments.each do |header|
        next unless header.p_type == PT_LOAD && header.p_flags & PF_W == PF_W
        slack_begin = header.p_vaddr + header.p_memsz;
        slack_end = (slack_begin + header.p_align) & ~(header.p_align - 1)
        @slack_space.push([slack_begin, slack_begin, slack_end])
      end
    end


    def get_iat_pointer(fn_name)
      @modules.values.each do |mod|
        return mod.imports[fn_name] if mod.imports.include? fn_name
      end
    end

  end
end


