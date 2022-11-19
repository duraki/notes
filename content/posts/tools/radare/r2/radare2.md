---
title: "radare2"
---

[radare2](https://www.radare.org/) (commonly refered as `r2`) is UNIX-like reverse engineering framework and command-line toolset. r2 is a complete rewrite of radare. It provides a set of libraries, tools and plugins to ease reverse engineering tasks. 

The radare project started as a simple command-line hexadecimal editor focused on forensics. Today, r2 is a featureful low-level command-line tool with support for scripting. r2 can edit files on local hard drives, view kernel memory, and debug programs locally or via a remote gdb server. r2's wide architecture support allows you to analyze, emulate, debug, modify, and disassemble any binary.

**Installation**

You can either use `r2env` Python package, or install via `brew`:

```
# => prefered way if you need to switch between different versions
$ pip install -U r2env
$ r2env init
$ r2env add radare2@git

# => standalone brew package
$ brew install radare2
```

**Usage**

All r2 tools and commands support printing the output in different formats by appending a character at the end or using the `-r` (`*r2`) and `-j` (json) flags. Check out the manpages and help messages for more information (`man r2`).

radare2:

```
# => loading binary in CLI and executing r2 REPL commands  
$ r2 /bin/ls   # open the binary in read-only mode
# > aaa          # same as r2 -A, analyse the binary
# > afl          # list all functions (try aflt, aflm)
# > px 32        # print 32 byte hexdump current block
# > s sym.main   # seek to the given offset (by flag name, number, ..)
# > f~foo        # filter flags with ~grep (same as |grep)
# > iS;is        # list sections and symbols (same as rabin2 -Ss)
# > pdf; agf     # print function and show control-flow-graph in ascii-art
# > oo+;w hello  # reopen in rw mode and write a string in the current offset
# > ?*~...       # interactive filter all command help messages
# > q            # quit
```

rasm2:

```
$ rasm2 -L                 # list all supported assembler/disassembler/emulator plugins
$ rasm2 -a arm -b 64 'nop' # assemble a nop in 64-bit ARM
$ rasm2 -d 90              # disassemble 0x90; nop, if you're using x86
```

rabin2

```
$ rabin2 -s /bin/ls # list symbols in a binary
$ rabin2 -z /bin/ls # find strings
```

rax2

```
$ rax2 '10+0x20' # compute the result
$ rax2 -k 10+32  # keep the same base as input (10)
$ rax2 -h        # convert between (hex, octal, decimal.. bases)
```

**Plugins**

Many plugins are included in r2 by default. But you can extend its capabilities by using the r2pm package manager.

```
$ r2pm -s <word> # search package by word
$ r2pm -ci <pkg> # install a package
```

**Scripting**

There are native API bindings available for many programming languages, but it is recommended to use [r2pipe](https://github.com/radareorg/radare2-r2pipe) which is a simple interface to execute r2 commands and get the output in result.

```
import r2pipe
r2 = r2pipe.open("/bin/ls")
print(r2.cmd("pd 10"))
r2.quit()
```

**Resources**

* [r2 Book](https://book.rada.re/)
* [Usage](https://github.com/radareorg/radare2/blob/master/USAGE.md)
* [manpages](https://github.com/radareorg/radare2/blob/master/man)