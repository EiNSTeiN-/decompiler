""" Host module

The disassembly work is offloaded to host programs. The host provides the following functionalities:
- Delimit the control flow of single functions correctly.
- Provide disassembler output: instruction size, mnemonic, number of operands, operands types.
- Optionally provide translation from location to name (for functions, global locations, etc)

This module also provide a native interface in the host program that can display
the decompiler output.

"""
