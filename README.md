decompiler ![Build Status](https://api.travis-ci.org/EiNSTeiN-/decompiler.svg)
==============

A multi-backends decompiler written in python. It currently supports IDA and Capstone.

### Usage with Capstone

Install [Capstone](http://capstone-engine.org/)'s Python bindings like followings:

    $ sudo pip install capstone

Then try out the decompiler:

```python
from capstone import *
from decompiler import *
from host import dis
from output import c

# Create a Capstone object, which will be used as disassembler
md = Cs(CS_ARCH_X86, CS_MODE_32)

# Define a bunch of bytes to disassemble
code = "\x55\x89\xe5\x83\xec\x28\xc7\x45\xf4\x00\x00\x00\x00\x8b\x45\xf4\x8b\x00\x83\xf8\x0e\x75\x0c\xc7\x04\x24\x30\x87\x04\x08\xe8\xd3\xfe\xff\xff\xb8\x00\x00\x00\x00\xc9\xc3"

# Create the capstone-specific backend; it will yield expressions that the decompiler is able to use.
disasm = dis.available_disassemblers['capstone'].create(md, code, 0x1000)

# Create the decompiler
dec = decompiler_t(disasm, 0x1000)

# Transform the function until it is decompiled
dec.step_until(step_decompiled)

# Tokenize and output the function as string
print(''.join([str(o) for o in c.tokenizer(dec.function).tokens]))
```

The snippet of code above should output:
```c
func() {
   s0 = 0;
   if (*s0 == 14) {
      s2 = 134514480;
      3830();
   }
   return 0;
}
```

Much like Capstone itself, the capstone backend does not know what address is a string, and has no concept of named location. This is why `3830()` and `134514480` appear as they do in the decompiled code above. You can give this information to the disassembler backend for a prettier output:

```python
disasm.add_string(134514480, "string")
disasm.add_name(3830, "func_3830")
print(''.join([str(o) for o in c.tokenizer(dec.function).tokens]))
```

Now the decompiled output is:

```c
func() {
   s0 = 0;
   if (*s0 == 14) {
      s2 = 'string';
      func_3830();
   }
   return 0;
}
```

### Current status

It is currently capable of decompiling small functions with fairly simple control flow. It may also be able to decompile larger functions by pure luck. It shows what can be done in a few thousand lines of python.

Test binaries are provided in tests/.

### How does it work?

This project is based on [a paper by van Emmerik](http://www.backerstreet.com/decompiler/vanEmmerik_ssa.pdf) titled Static Single Assignment for Decompilation.

### Roadmap

This project could use some improvements in the following areas:

* more instructions are needed. currently this decompiler supports a very limited number of x86/x64 instructions.
* there is currently no attempt at data type analysis, which would be necessary in order to produce a recompilable output, or even a more correct output.
* add support for different types of assemblies (ARM, etc).
* add support for more calling conventions. currently, only SystemV x64 ABI (x64 linux gcc) is supported. under other compilers, function calls will be displayed without parameters.
* add a GUI for renaming variables, inverting if-else branches, and other easy things.
* when possible, functions called from the one being decompiled should be analysed to determine function arguments and restored registers.

