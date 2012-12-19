BISC: Borrowed Instructions Synthetic Computation
====

For an example of how to use BISC, see src/CreateThreadStage.rb. This
BISC program creates a new thread to run an embedded machine code
payload and then runs a "parent" payload in the current thread.

I haven't tested it in a while and it's probably broken in some way,
but it still serves as a code example of how BISC is to be used.

BISC programs are built from a cygwin shell:

$ ./CreateThreadStage.rb ./Shockwave-11.5.6r606/*.dll > CreateThreadStage.rop

Testing must be done from a Windows CMD.exe shell:

> ./test-rop.exe CreateThreadStage.rop ./Shockwave-11.5.6r606/*.dll