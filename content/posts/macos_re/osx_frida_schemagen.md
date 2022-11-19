---
title: "Generate Frida Class"
---

This explains usage of toolchain for generating JSON definitions for Objective-C classes, commonly used during Frida hooking.

* [ ] todo: fork `macschema` and extend it to support custom classes

The macschema tool has several subcommands for downloading topics from Apple documentation and parsing topics into schemas. The commands will assume they can use two directories in the working directory: api and doc, where schemas and topics are downloaded and saved as JSON.

To pull and show a schema, which will download relevant topics and parse into schema:

```
$ macschema pull appkit/nswindow --show
```

Other commands:

```
$ macschema
Generates JSON definitions for Apple APIs

Usage:
  macschema [command]

Available Commands:
  crawl       Downloads topics linked from a topic to doc dir
  fetch       Download a topic to doc dir
  help        Help about any command
  pull        Generate a schema in api dir fetching topics if needed

Flags:
  -h, --help          help for macschema
      --lang string   use language (default "objc")
      --show          show resulting JSON to stdout
  -v, --version       version for macschema

Use "macschema [command] --help" for more information about a command.
```

---

You can dump Objective-C messages in a `tree`-style format using [objtree](https://github.com/hot3eed/objtree) package. It will trace all ObjC methods within the scope of a method or function (symbolicated or by relative address). Stack-depth can be filtered by preference choice via command-line arguments. It includes all `frida-trace` goodies: spawn or attach to pid, connect remotely via frida-server, etc.

Example:

```
$ objtree <some_process> -m "-[InterestingClass interestingMethod:withArg:]"
$ objtree <some_process> -i LibFoo!bar
$ objtree <some_process> -i generate_interesting_value -L 6     # => match the function name in all modules
$ objtree <some_process> -a <offset> # offset is target method relative offset to 'process' base address
```

Usage:

```
$ objtree
Usage: objtree [options] target

Options:
  --version             show program's version number and exit
  -h, --help            show this help message and exit
  -D ID, --device=ID    connect to device with the given ID
  -U, --usb             connect to USB device
  -R, --remote          connect to remote frida-server
  -H HOST, --host=HOST  connect to remote frida-server on HOST
  -f FILE, --file=FILE  spawn FILE
  -F, --attach-frontmost
                        attach to frontmost application
  -n NAME, --attach-name=NAME
                        attach to NAME
  -p PID, --attach-pid=PID
                        attach to PID
  --stdio=inherit|pipe  stdio behavior when spawning (defaults to “inherit”)
  --aux=option          set aux option when spawning, such as “uid=(int)42”
                        (supported types are: string, bool, int)
  --runtime=qjs|v8      script runtime to use
  --debug               enable the Node.js compatible script debugger
  --squelch-crash       if enabled, will not dump crash report to console
  -O FILE, --options-file=FILE
                        text file containing additional command line options
  -m OBJC_METHOD        include OBJC_METHOD
  -i FUNCTION           include FUNCTION
  -a FUNCTION_OFFSET    add FUNCTION_OFFSET, relative to binary base
  -L STACK_DEPTH        trace functions up to STACK_DEPTH, default is 8
  -o OUTPUT, --output=OUTPUT
                        dump output to file OUTPUT
```

---

This part of the notes explains how to use `cycript` to expose private enums by using native `NSStringFrom*` functions. Enums are typically reverse engineered by monitoring side effects of values. Understanding what this values really are, can help developers write better, more maintainable code. Credits for the trick goes to [leptos-null/PrivateEnums](https://github.com/leptos-null/PrivateEnums).

Instructions:

```
# => dumps a list of all NSStringFrom* functions, some parts of dumped data are type(struct), not type(enum)
$ grep "NSStringFrom" $THEOS/sdks/iPhoneOS10.2.sdk/System/Library/*Frameworks/*.framework/*.tbd

# => open the iPhoneOS simulator in Hopper and check that the extracted function 
#    is for a fixed point numerical value, and not a struct
$ hoppv5 /Library/XCode/Simulator/<IPHONE_SIMULATOR_BINARY>

# => on the iOS device, use cycript to call the function. Compare the cycript 
#   output with Hopper disassembly, and ensure all classes have been exhausted
```

---

**References**

- [macschema](https://github.com/progrium/macschema) `brew install progrium/taps/macschema` 