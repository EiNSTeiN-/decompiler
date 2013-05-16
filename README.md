ida-decompiler
==============

An IDA plugin that attempts to decompile a function. Written in Python.

### What is it?

This is an IDA plugin which can decompile one function at a time. To try it in IDA, place your cursor on a function, and execute the plugin. The decompiled function will appear in the output window.

### Current status

It is currently capable of decompiling small functions with fairly simple control flow. It may also be able to decompile larger functions by pure luck. It shows what can be done in only ~2600 lines of python.

Test binaries are provided in tests/. For example, the fib.c program contains two small functions which decompile to the following:

```c
sub_4005cc() {
   *(esp) = a0;
   v2 = 0;
   .__isoc99_scanf(0, '%d', &v3);
   .puts('Fibonacci series', &v3);
   v4 = 1;
   while (v4 <= v3) {
      v0 = Fibonacci(v2);
      .printf(0, '%d\n', v0);
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

The first analysis plase takes care of transforming every instruction into its equivalent static single assignment form. For example, `add eax, 1` becomes `eax = eax + 1`. Instructions that affect more than one memory location (such as push, pop, leave, etc) are expanded into their more basic representation, such that `pop edi` becomes `edi = *(esp)` followed by `esp = esp + 4`.

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

- the code in its current form is very tightly coupled together; parts of it need to be abstracted to a more maintainable form.
- def-use chains are hard to work with in the current form; needs a rethink & rewrite
- more instructions are needed. currently this decompiler supports a very limited number of x86/x64 instructions.
- it appears necessary that phase 1 needs a better way to track which statements affect the control flow (cmp, test, etc) and how to make up a proper conditional expression from those statements.
- there is currently no attempt at data type analysis, which would be necessary in order to produce a recompilable output, or even a more correct output.
