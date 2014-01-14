## BISC: Borrowed Instructions Synthetic Computation

[![Code Climate](https://codeclimate.com/github/trailofbits/bisc.png)](https://codeclimate.com/github/trailofbits/bisc)

BISC is a ruby library for demonstrating how to build [borrowed-instruction]
programs. BISC aims to be simple, analogous to a traditional assembler,
minimize behind-the-scenes magic, and let users write simple macros.
BISC was developed for [Practical Return-oriented Programming] at
Blackhat USA 2010 and has been used for [Assured Exploitation] trainings since
then. 

For an example of how to use BISC, see [examples/CreateThreadStage.rb].
This BISC program creates a new thread to run an embedded machine code
payload and then runs a "parent" payload in the current thread.

BISC programs are built from a cygwin shell:

    ./examples/CreateThreadStage.rb ./Shockwave-11.5.6r606/*.dll > CreateThreadStage.rop

Testing must be done from a Windows CMD.exe shell:

    ./data/test-rop.exe CreateThreadStage.rop ./Shockwave-11.5.6r606/*.dll

[borrowed-instruction]: http://users.suse.com/~krahmer/no-nx.pdf
[Practical Return-oriented Programming]: http://users.suse.com/~krahmer/no-nx.pdf 
[Assured Exploitation]: http://www.trailofbits.com/training/#assured-exploitation
[examples/CreateThreadStage.rb]: https://github.com/trailofbits/bisc/blob/master/examples/CreateThreadStage.rb
