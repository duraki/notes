---
title: "Rebuilding Native ARM64 Binaries"
---

Building native M1/M2 ARM64 binaries via [Ghidra](/ghidra-and-related) requires a bit different approach than traditional Ghidra's `**Export Program**` option. Unlike Export Program option which can be invoked from Ghidra explorer menu to create a binary file containing bytes of file block and respective changes or patches to the target, this approach will use [Gradle](https://gradle.org/install/) instead.

Start by installing Gradle via Homebrew:

```
# install gradle with all deps
$ brew install gradle       # requires XCode CLI Tools installed

$ clang -v                  # clang is included in the XCode CLI Tools
# Homebrew clang version 15.0.7
# Target: arm64-apple-darwin22.3.0
# ...
```

Navigate to Ghidra's `support` folder, and run the script; use oneliner below and just paste it in the Terminal shell:

```
# Setting ENV via oneliner that finds Ghidra Homebrew path
$ GHIDRADIR="$(brew info ghidra | grep -i "homebrew/Caskroom" | grep "PUBLIC" | sed s/ghidraRun// | sed s/Binary// | sed s/\(// | sed s/\)// | sed 's/ //g')support"
$ cd $GHIDRADIR
```

Run `buildNatives` script in above directory to complete proper Ghidra installation. This will keep usability of Ghidra performant, without Apple's Gatekeeper *fizzling* or throwing warnings:

```
$ pwd               # => $GHIDRADIR
                    # tty should be in previously setted GHIDRADIR ENV directory

$ ./buildNatives    # => this will build native Ghidra utils for arm
Building natives in Ghidra...
Welcome to Gradle 8.0.2!
> Configure project :Debugger-swig-lldb
> Configure project :Decompiler
> Configure project :PDB
> Configure project :DemanglerGnu
# BUILD SUCCESSFUL ...
```

You can also check [instructions on Ghidra Scripting](/ghidra-scripts) pagenotes.
