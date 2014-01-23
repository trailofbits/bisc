#!/usr/bin/env ruby

lib = File.expand_path('../../lib', __FILE__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)

require 'bisc'

bisc = BISC::ELFAssembler.new(ARGV)

lpVar = bisc.allocate(4)
lppExit = bisc.get_iat_pointer('exit')

NOPS = [ "NOP" ] * 500
Main = [
  "POP ECX", lpVar,
  "POP EAX", 0x01,
  "MOV [ECX], EAX",
  "POP ECX", lppExit,
  "MOV EAX, [ECX]",
  "PUSH EAX", "NOP", 0x02,
  "NOP", "NOP"
]

print bisc.assemble(NOPS + Main)

