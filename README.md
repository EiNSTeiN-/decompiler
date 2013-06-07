ida-decompiler
==============

An IDA plugin that attempts to decompile a function. Written in Python.

### What is it?

This is an IDA plugin which can decompile one function at a time. To try it in IDA, place your cursor on a function, and execute the plugin. The decompiled function will appear in the output window.

### Current status

It is currently capable of decompiling small functions with fairly simple control flow. It may also be able to decompile larger functions by pure luck. It shows what can be done in a few thousand lines of python.

Test binaries are provided in tests/. For example, the fib.c program contains two small functions which decompile to the following:

```c
sub_4005cc() {
   *(esp) = a0;
   v2 = 0;
   .__isoc99_scanf(0, "%d", &v3);
   .puts("Fibonacci series", &v3);
   v4 = 1;
   while (v4 <= v3) {
      v0 = Fibonacci(v2);
      .printf(0, "%d\n", v0);
      v2++;
      v4++;
   }
   return 0;
}

Fibonacci() {
   *(esp) = a0;
   v5 = a1;
   v6 = a2;
   if (v6) {
      if (v6 != 1) {
         v2 = Fibonacci(v6 - 1);
         v0 = Fibonacci(v6 - 2, v2);
         v1 = v0 + v2;
      }
      else {
         v1 = 1;
      }
   }
   else {
      v1 = 0;
   }
   return v1;
}
```

### How does it work?

#### Phase 1: SSA form

The first analysis phase takes care of transforming every instruction into a form very close to static single assignment form. For example, `add eax, 1` becomes `eax = eax + 1`. Instructions that affect more than one memory location (such as push, pop, leave, etc) are expanded into their more basic representation, such that `pop edi` becomes `edi = *(esp)` followed by `esp = esp + 4`.

This phase also attempt to track modifications to the eflags register. All status bits are supported, although only zf, cf, of and sf have a proper decompiled representation, and the af and pf eflags will be displayed as `PARITY(...)` or `ADJUST(...)`. Modifications to eflags are tracked by emitting assignments to special registers (named %eflags.*). When a jump instruction is later encountered, the corresponding condition is emitted using eflags as operands, for example, jz is emitted as `if(%eflags.zf == 0)`. Unused eflags are then eliminated as dead code, and used ones are propagated the normal way when replacing uses by definitions.

#### Phase 2: definition-use tracking

The second analysis phase attempts to tracks definition-use chains. When an assignation takes place, a new def-use chain is created. All following uses of this register is attached to the chain until a subsequent assignation to the same register takes place. This enables the analysis of which register are 'active' at a specific location during the execution of the function.

For example:
```
eax = 18
edi = *(esp - 4)
edi = edi + eax
eax = edi
```

In this example, line 1 assigns `eax`, line 2 assigns `edi`, then on line 3 both previous definitions of `edi` and `eax` are used and assigned to `edi`. On line 4, the new definition of `edi` is assigned to a `eax`.

This could be re-written as follows:
```
v1 = 18
v2 = *(esp - 4)
v3 = v2 + v1
v4 = v3
```

#### Phase 3: simplification

In this phase, def-use chains are simplified by replacing uses by their definitions until a definition has no more uses, at which point it is eliminated as dead code.

Intuitively, the example above can be simplified as follows:
```
v4 = *(esp - 4) + 18
```

In this phase, expressions tend to become more complex as they are combined together, so further transformations are applied in an attempt to limit expression size and keep readability, such that `v1 - 4 + 4` becomes `v1`, etc.

#### Phase 4: control flow combining

In this phase, the basic control blocks are combined together to form more complex control blocks. Basic algorithm are applied iteratively in an attempt to make more complex statements such as if, while, do-while from simple `if(...) goto` constructs.

In this phase, the following combination would be done:
```
loc_405098:
   if(v1 < 1) {
      goto loc_4050a0;
   }
   goto loc_4050f0;

loc_4050a0:
   v1 = 1;
   goto loc_4050f0;

loc_4050f0:
   return v1;
```

would be transformed into:

```
loc_405098:
   if(v1 < 1) {
      v1 = 1;
   }
   return v1;
```

### TODO

This project could use some improvements in the following areas:

- more instructions are needed. currently this decompiler supports a very limited number of x86/x64 instructions.
- there is currently no attempt at data type analysis, which would be necessary in order to produce a recompilable output, or even a more correct output.
- add support for different types of assemblies (ARM, etc).
- add support for more calling conventions. currently, only SystemV x64 ABI (x64 linux gcc) is supported. under other compilers, function calls will be displayed without parameters.
- add a GUI for renaming variables, inverting if-else branches, and other easy stuff.
- when possible, functions called from the one being decompiled should be analysed to determine function arguments and restored registers.

