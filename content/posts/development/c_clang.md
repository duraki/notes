---
title: "C Programming Language"
url: /dev/c
---

The C is a programming language with low-level access to memory and processor instructions alongside the support for system-level programming. It is commonly used for developing operating systems, embedded systems, and performance-critical applications. The high-level abstractions provided by C make it a versatile language for system programming and is therefore used extensively in system-level development and writing compilers for all other languages.

## Variable Types

The C programming language supports several variable types, including:

- `int`: integer type
- `float`: floating-point type
- `double`: double-precision floating-point type
- `char`: character type
- `void`: no type

Now, these primitive types in C like `float`, `int`, `char`, etc. are only supposed to be native to the architecture on which the program is compiled/running, the one that is used in the code simply gives "hints" to the compiler of what you want to do, but they have to fit in a native element as used by assembly, to be able to operate on values larger than what your platform natively can handle, otherwise you are supposed to use a multiple precision library that does it in a "platform-friendly way", like `gmp` that works integrally with `gcc`.

In embedded systems, it's _preferred to always use_ `int32_t`, `uint8_t` types to represent signed integers, unsigned integers, and pointers. When making a cross-platform/cross-compiling code that handles memory you need an: (_usually `unsiged`_) `integer` type **that is guaranteed to line up with pointer types within the system**. The `long` types are not well-defined. That's the point. The type sizes change based on the platform/architecture. So `long` can literally be equal to an `int` type on some platforms and on others it can be a different size. You must specify the type sizes (specifically `int` vs `long`) using `#ifdef` macro, to figure out what applies to a type at compile time.

The origins behind the different variable sizes of a C integer types is entirely due to requirements of portability/cross-compatibility between platforms. For example, the above mentioned `char` type can be equivalent to a `long long` type on other platforms, **but all those have to fit inside any machine/architecture**, and **even those** _that can only handle a single size of element_ that is `48 bits` wide. This is it has to only guarantee one unknown factor, a `long` type variable that each other compiling step could be the same size or bigger of the defined, (_but never a smaller one_), and therefore `int` is being the most common/natural size to define for that platform and operation (i.e. _there is no guarantee that `int` is the same size even in the same compiled program, only that `short =< int =< long`_), therefore `int` means "_give me whatever size please_", kind of similar to what `void*` type represents.

## What is the benefit of C Programming Language

Well, **interopability is one of the main benefits of C programming language**. The _libraries written in C_ programming language _are just a wrapper for the syscalls that actually connect to the kernel_. The kernel is entirely language agnostic, but has a method that is specific to each `CPU/ISA`, and is ported to that architecture so it enables a function call to a "protected kernel runtime level on that ISA" (in `x86_64` that is: to load the function arguments and a code that specifies the function to be called into specific registers and then execute the `SYSCALL` instruction, but since this is specific to `x86_64`, different methods are used for other `CPU/ISA` such as `arm`, `risc-v`, `MIPS`, `PPC`, and even `x86_32`).

If you want to compile and create an executable without using the C libraries and their ABI, the answer is simple: **implement the kernel interface directly**. If you don't want to implement them all directly with your equivalent of an `asm()` directive, just implement one generic syscall instruction in your compiler that will spit out the right instructions for each architecture/operating system you want to support, and then make a wrapped functions for each of the kernel routines you want to access. This is needed for interoperability with the kernel, if you really need to access the kernel directly per specific architecture/operating system.

## But no, really, the  `long long long var_types*`?

In short, the essence of understanding is:

```c
size_t // : unsigned integer type than can address any offset within any memory section.
ssize_t // :signed integer that covers at least [−1, ½(SIZE_MAX−1)] (NB!, the only negative value that is guaranteed to supported is −1)
rsize_t // :intersection of size_t and ssize_t.
intptr_t // :signed integer type that express any memory address and uses two's complement.
uintptr_t // :unsigned version of intptr_t.
ptrdiff_t // :this one is a real mess.
intmax_t // :signed integer type that covers the largest possible integer value
long long // :signed integer type that covers the largest possible integer value on the platform (typically 64 bits)
__int128_t // :signed integer type that covers the largest possible integer value on the platform (typically 128 bits)
```

Hope it makes it clear, I really tried my best :-) Need private consultation and teaching your team best development practices, contact the agency [DCSECURITY.us](https://dcsec.us) and the representative of [durakiconsulting LLC](https://durakiconsulting.com) - and yes - the founder is _you've guessed_ it, [Halis Duraki](https://linkedin.com/in/duraki) who is also the author of these notes you are reading.
