#
# BISC - Borrowed Instructions Synthetic Computation
#
# Copyright (c) 2010 Dino Dai Zovi (ddz@theta44.org)
#
# Bisc is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# Bisc is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Bisc.  If not, see <http://www.gnu.org/licenses/>.
#

require 'bisc/version'

require 'rex/peparsey'
require 'rex/pescan'
require 'rex/arch/x86'

module BISC

# The BISC class is used to scan PE modules for instruction sequences
# and unused data space that may be borrowed and used to construct
# return-oriented programs.
class Assembler
  class Error < RuntimeError
  end

  REG32 = [:EAX, :ECX, :EDX, :EBX, :ESP, :EBP, :ESI, :EDI]

  #
  # Build regex for instructions of the form:
  # 1-byte opcode | mod_rm
  #
  opcodes = {
    0x11 => 'ADC',
    0x01 => 'ADD',
    0x21 => 'AND',
    0x89 => 'MOV',
    0x09 => 'OR',
    0x19 => 'SBB',
    0x29 => 'SUB',
    0x31 => 'XOR',
  }

  op1modrm_regex = '(' + opcodes.keys.map { |opcode|
    '\x%.2x|\x%.2x' % [opcode, opcode + 2]
  }.join('|') + ')[\x00-\x3f\xc0-\xff]'
  
  #
  # Hash table of regex => decoder functions
  #
  PATTERNS = {
    op1modrm_regex => lambda { |matchdata|
      buffer = matchdata[0]
      opcode, mod_rm = buffer.unpack('CC')
      displacement = nil
      
      r32_1 = REG32[(mod_rm >> 3) & 0x7]
      r32_0 = REG32[mod_rm & 0x7]
      
      case mod_rm
      when 0x00..0x3F
        # [r32], r32
        operand_0 = "[#{r32_0}]"
        operand_1 = r32_1.to_s
        
      when 0xC0..0xFF
        # r32, r32
        operand_0 = r32_0.to_s
        operand_1 = r32_1.to_s
        
      end
      
      # Return symbol indicating instruction operation and form
      if (opcode & 2) == 2
        sym = "#{opcodes[opcode & ~2]} #{operand_1}, #{operand_0}".intern
      else
        sym = "#{opcodes[opcode & ~2]} #{operand_0}, #{operand_1}".intern
      end
      
      return sym
    },
    
    # inc r32
    '([\x40-\x47])' => lambda { |matchdata|
      opcode = matchdata[1].unpack('C')[0]
      dest_reg32 = REG32[opcode - 0x40]
      
      return "INC #{dest_reg32}".intern
    },
    
    # dec r32
    '([\x48-\x4f])' => lambda { |matchdata|
      opcode = matchdata[1].unpack('C')[0]
      dest_reg32 = REG32[opcode - 0x48]
      
      return "DEC #{dest_reg32}".intern
    },
    
    # pop r32
    '([\x58-\x5f])' => lambda { |matchdata|
      opcode = matchdata[1].unpack('C')[0]
      dest_reg32 = REG32[opcode - 0x58]
      
      return "POP #{dest_reg32}".intern
    },
    
    # push r32
    '([\x50-\x57])' => lambda { |matchdata|
      opcode = matchdata[1].unpack('C')[0]
      dest_reg32 = REG32[opcode - 0x50]
      
      return "PUSH #{dest_reg32}".intern
    },
    
    # add esp, N synthetic instruction
    '([\x59-\x5f]+)' => lambda { |matchdata|
      n_pops = matchdata[1].length
      
      return "ADD ESP, #{n_pops * 4}".intern
    },
    
    # xchg r32, r32
    '((\x87[\xc0-\xff])|[\x90-\x97])' => lambda { |matchdata|
      if matchdata[2]
        mod_rm = matchdata[2].unpack('C')[0]
        
        dst_reg32 = REG32[(mod_rm >> 3) & 0x7]
        src_reg32 = REG32[mod_rm & 0x7]
        
        return "XCHG #{dst_reg32}, #{src_reg32}".intern
      else
        opcode = matchdata[1].unpack('C')[0]
        dst_reg32 = REG32[opcode - 0x90]
        
        return "XCHG EAX, #{dst_reg32}".intern
      end
    },
    
    # int 3
    '(\xCC)' => lambda { |matchdata| return 'INT3'.intern },
    
    # nop
    '(\x90)' => lambda { |matchdata| return 'NOP'.intern }
  }

  #
  # Create a new BISC object to assist in creating return-oriented programs
  # 
  def initialize(libraries)
    #
    # Track the modules that we've been given
    #
    @modules = {}

    #
    # Keep a hash table of dissassembled instruction mnemonics 
    # ("PUSH EAX") to array of addresses where that instruction
    # followed by a return can be
    # found.
    #
    @instructions = {}

    #
    # Record the amount of slack space between the last of .data
    # space that is requested and the size rounded up to the nearest
    # multiple of the page size.  We can safely use this slack space
    # for temporary scratch storage.
    #
    @slack_space = []

    libraries.each { |lib| add_module(lib) }
  end

  #
  # Add a PE module (DLL or EXE) to be scanned for usable instructions
  #
  def add_module(path)
    pe = Rex::PeParsey::Pe.new_from_file(path, true)
    pename = File.basename(path)
    @modules[pename] = pe

    #
    # Check for DYNAMICBASE flag in DllCharacteristics
    #
    if (pe.hdr.opt.DllCharacteristics & 0x40) == 0x40
      raise(Error,"#{path} is ASLR enabled...")
    end

    #
    # Apply regular expressions to .text sections in PE modules
    #
    pe.all_sections.each { |section|
      if section.name == '.text'
        scanner = Rex::PeScan::Scanner::RegexScanner.new(pe)
        
        PATTERNS.keys.each { |pattern|
          re = Regexp.new("#{pattern}(\xC3)", nil, 'n')
          scanner.regex = re
          hits = scanner.scan_section(section)
          
          hits.each { |hit|
            address = pe.rva_to_vma(hit[0])
            bytes = hit[1][0]
            matchdata = re.match([bytes].pack('H*'))
            
            if matchdata
              sym = PATTERNS[pattern].call(matchdata)
              
              if @instructions[sym] == nil
                @instructions[sym] = []
              end
              
              @instructions[sym].push(address)
            end
          }
        }
      end
    }

    #
    # Add slack space from .data segment to our data segments list
    #
    pe.sections.each { |section|
      if section.name == '.data'
        slack_begin =
          pe.rva_to_vma(section.base_rva) +
          section._section_header.v['Misc']
        slack_end = (slack_begin + 4096) & ~(4096 - 1)

        # Record slack space as [begin, allocated_position, end]
        @slack_space.push([slack_begin, slack_begin, slack_end])
      end
    }
  end

  #
  # Return an array of all unique instructions observed in the scanned
  # modules followed by 'ret' instructions.
  #
  def instructions
    @instructions.keys
  end

  #
  # Lookup an address of the given instruction as found in a module's .text
  # section followed by a 'ret' instruction.
  #
  def [](s)
    case s
    when Symbol
      addresses = @instructions[s]

      unless addresses
        raise(Error,"Instruction #{s} not found")
      end

      return addresses[0]
    when String
      addresses = @instructions[s.intern]

      unless addresses
        raise(Error,"Instruction #{s} not found")
      end

      return addresses[0]
    else
      raise(Error,"Name must be either a Symbol or a String")
    end
  end
  
  #
  # Allocate memory from scratch space
  #
  def allocate(n_bytes)
    @slack_space.each { |s|
      slack_begin, slack_current, slack_end = s

      if (slack_current + n_bytes) < slack_end
        s[1] = slack_current + n_bytes
        return slack_current
      end
    }

    return nil
  end

  #
  # Lookup an import's function pointer in an IAT and return its address
  #
  def get_iat_pointer(dll_name, function_name)
    @modules.values.each { |pe|
      pe.imports.each { |import|
        if import.name.casecmp(dll_name) == 0
          import.entries.each_with_index { |entry, i|
            if entry.name.casecmp(function_name) == 0
              rva = _get_iat_vma(pe, dll_name)
              
              return rva + (i * 4)
            end
          }
        end
      }
    }
    
    return nil
  end

  def _get_iat_vma(pe, fordll)
    #
    # Parse import tables (manually b/c peparsey throws away data we need)
    #
    idata_entry = pe._optional_header['DataDirectory'][1]
    rva = idata_entry.v['VirtualAddress']
    size = idata_entry.v['Size']
    
    idata = pe._isource.read(pe.rva_to_file_offset(rva), size)
    while idata.length >= Rex::PeParsey::PeBase::IMAGE_IMPORT_DESCRIPTOR_SIZE
      descriptor = Rex::PeParsey::PeBase::IMAGE_IMPORT_DESCRIPTOR.make_struct
      descriptor.from_s(idata)
      idata = descriptor.leftover
      
      dllname =
        pe._isource.read_asciiz(pe.rva_to_file_offset(descriptor.v['Name']))
      
      if dllname.casecmp(fordll) == 0
        iat_rva = descriptor.v['FirstThunk']
        iat_vma = pe.rva_to_vma(iat_rva)
        return iat_vma
      end
    end
    
    return nil
  end


  #
  # Assemble a return-oriented program.  The program should be an
  # array of strings corresponding to borrowed instructions and 32-bit
  # immediate values.  The program array can contain an arbitrary
  # depth of nested arrays of the same value types as it will be
  # flattened before being assembled.
  #
  def assemble(program)
    p = program.flatten.map do |i|
      i.kind_of?(String) ? self[i] : i
    end

    return p.pack('V*')
  end

  def print_instructions()
    @instructions.keys.map(&:to_s).sort.each do |i|
      addresses = ''

      @instructions[i.to_sym].first(5).each do |a|
        addresses << ('0x%x ' % a)
      end
      
      puts "#{i} #{addresses}"
    end
end
end
end
