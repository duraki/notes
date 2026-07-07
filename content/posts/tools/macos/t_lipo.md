---
title: "lipo"
---

With `lipo`, you can create or operate on a universal MachO file:

* Convert a universal binary to a single architecture file
* Convert single architecture file to a universal binary

```
Syntax
      lipo [input_file]... [-arch arch_type input_file]... [-arch_blank arch_type]...
              { -info | -detailed_info }
                 [-output output_file] Operation
                    [-segalign arch_type value]

        where Operation is one of:
           [-create] [-arch_blank arch_type]
           [-thin arch_type]
           [-extract arch_type] ...
           [-extract_family arch_type] ...
           [-remove arch_type] ...
           [-replace arch_type file_name] ...
           [-verify_arch arch_type ...]
```

**Examples:**

```
# => Display information about a BINARY
$ cd /Applications
$ lipo Stickies.app/Contents/MacOS/Stickies -info

# => Convert a binary to i386 binary
$ lipo Stickies.app/Contents/MacOS/Stickies -thin i386 -output Stickies.app/Contents/MacOS/Stickies.i386
```
