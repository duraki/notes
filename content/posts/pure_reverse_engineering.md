---
title: "Pure Reverse Engineering"
---

Some [RE Tricks and Tips](/reverse-engineering-tricks-and-tips) have been shared here. Otherwise, check references at the bottom of these notes.

Use [Byteman](/byteman) to instrument compiled Java application and `*.jar` files. A [sample script](/byteman-scripts) has been included in the notes.

### Hopper Disassembler

In case Hopper Disassembler is `Not Responding` (sometimes due to large binary/analysis), you can:

* Wait a bit more, close all unused apps, especially (Chrome) tabs
* Open Activity Monitor and check Hopper Disassembler process details
* If nothing works, use the command below to purge all unused virtual memory

```
$ purge

# => ... wait a bit
# =>     hopper disas. should be unfrezzed and responding
```

**References**

* [Debugging iOS binaries with lldb](https://kov4l3nko.github.io/blog/2016-04-27-debugging-ios-binaries-with-lldb/)
* [Bypass Flutter SSL Pinning (2021)](https://github.com/horangi-cyops/flutter-ssl-pinning-bypass)
* [Frida Android Function Enumerator and Dumper](https://github.com/tomelic/ffe)


