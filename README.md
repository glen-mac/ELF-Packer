# Simple Polymorphic x86\_64 Runtime Code Segment Cryptor
--
## *These are not the bytes you are looking for*

This little project is a simple polymorphic runtime cryptor for x86_64 ELF binaries on linux. I wrote this for the extended digital forensics course at my university, but thought I would share publically because why not - learning and things.

## What does it do?

The script will search for a region of nulls in the provided binary that is large enough to fit the assembly stub - which it will place in this region of nulls. The entry point in the ELF header is then changed to the start of this stub, such that the stub is the first thing that is executed when the binary is run. Once the stub has completed execution, there is an absolute jump to the original entry point for the binary to continue ordinary execution.

The stub is a simple XOR encryptor for the **.text** section of the binary, which does a byte by byte xor to make disassembling it impossible - although trivial to bypass as it is only a simple XOR. 

The stub however will (my making a new file) modify the executable on every execution to use a new random XOR byte such that the hash of the binary will change on each execution - hence polymorphic.

## Where to go?

This was just for a small assessment task, so was mainly just a fun task. Although there are some issues with it such as:
- Only support for 64 bit binaries (easy fix - just rewrite the stub assembly - the rest of the code will work for 32/64 bit ELFs)
- Too simple "encryption" - although was just for POC

## Can I see it in action?

Sure can!

Check out [https://asciinema.org/a/zLnjq83Zx8Qv2TdFv0UUyxHrK](https://asciinema.org/a/zLnjq83Zx8Qv2TdFv0UUyxHrK) to see me running a simple hello world binary through the cryptor, and showing the different hash on each execution.
