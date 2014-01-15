#!/usr/bin/env ruby

lib = File.expand_path('../../lib', __FILE__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)

require 'bisc'

bisc = BISC::ELFAssembler.new(ARGV)

pVar = bisc.allocate(4)
free = bisc.get_iat_pointer('free')

Main = [
  pVar,
  free,
  "NOP",
]

print bisc.assemble(Main)

