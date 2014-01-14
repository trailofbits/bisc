#!/usr/bin/env ruby

lib = File.expand_path('../../lib', __FILE__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)

require 'bisc'

bisc = BISC::Assembler.new(ARGV)

pVar = bisc.allocate(4)

Main = [
  pVar,
  "INT3",
]

print bisc.assemble(Main)

