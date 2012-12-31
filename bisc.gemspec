# -*- encoding: utf-8 -*-

lib = File.expand_path('../lib', __FILE__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)
require 'bisc/version'

Gem::Specification.new do |gem|
  gem.name          = "bisc"
  gem.version       = BISC::VERSION
  gem.license       = 'GPLv3'
  gem.authors       = ["Dino A. Dai Zovi"]
  gem.email         = ["ddz@theta44.org"]
  gem.description   = %q{Borrowed Instructions Synthetic Computation}
  gem.summary       = %q{Borrowed Instructions Synthetic Computation}
  gem.homepage      = "https://github.com/trailofbits/bisc#readme"

  gem.files         = `git ls-files`.split($/)
  gem.executables   = gem.files.grep(%r{^bin/}).map{ |f| File.basename(f) }
  gem.test_files    = gem.files.grep(%r{^(test|spec|features)/})
  gem.require_paths = ["lib"]

  gem.add_dependency 'librex', '~> 0.0'
  gem.add_dependency 'metasm', '~> 1.0'
end
