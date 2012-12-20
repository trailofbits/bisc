# BISC: Borrowed Instructions Synthetic Computation

For an example of how to use BISC, see src/CreateThreadStage.rb. This
BISC program creates a new thread to run an embedded machine code
payload and then runs a "parent" payload in the current thread.

I haven't tested it in a while and it's probably broken in some way,
but it still serves as a code example of how BISC is to be used.

BISC programs are built from a cygwin shell:

    ./examples/CreateThreadStage.rb ./Shockwave-11.5.6r606/*.dll > CreateThreadStage.rop

Testing must be done from a Windows CMD.exe shell:

    ./data/test-rop.exe CreateThreadStage.rop ./Shockwave-11.5.6r606/*.dll

## License

BISC - Borrowed Instructions Synthetic Computation

Copyright (c) 2010 Dino Dai Zovi (ddz@theta44.org)

Bisc is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

Bisc is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with Bisc.  If not, see <http://www.gnu.org/licenses/>.
