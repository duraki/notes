---
title: "Pure Reverse Engineering"
---

Some [RE Tricks and Tips](/reverse-engineering-tricks-and-tips) have been shared here. Otherwise, check references at the bottom of these notes.

Use [Byteman](/byteman) to instrument compiled Java application and `*.jar` files. A [sample script](/byteman-scripts) has been included in the notes.

### MacOS and iOS Commpage

It's not strange to see seemingly-random address being used as a call handler, instead of actual functions and methods, while reversing and debugging in iOS and MacOS environments. For example, here is a sample Hopper pseudo code disassembly of `/usr/bin/log` MacOS internal utility:

{{< details "Expand Pseudo Disassembly" >}}
```c
int sub_10001b3fc(int arg, int arg1, int arg2) {
    rdi = argO;
    rax = rdi | 0x80000000;
    if (* (int32_t *) 0x7fffffe00048 >= 0x0) {
        rax = rdi;
    }
    rbx = 0x8000000 & *(int32_t *)0x7fffffe00048;
    rbx = rbx | rax;
    if (os_log_type_enabled (*__os_log_default, 0x0) != 0x0) {
        var 20 = 0x4000100
        *(int32_t *) (&var_20 + 0×4) = rbx;
        _os_log_imp1(__mh_execute_header, *__os_log_default, 0x0, "Changed system mode to Ox%X", &var_20, 0x8);
    }
    if (host_set_atm_diagnostic_flag (mach_host_self(), rbx) == 0x0) {
        var_10 = **_
        rax = *
        _stack_chk_guard;
        _stack_chk_guard;
        rax = *rax;
        if (rax != var 10) {
           rax = __stack_chk_fail();
        }
    }
    else {
        rax = errx(0x4a, "Unable to set global diagnostic flag");
        return rax;
    }
}
```
{{< /details >}}

Skimming through above pseudocode, you will most likely see usage of memory addresses as a system and method calls, such is use of `0x7fffffe00048`. You might wonder what this is - and its normal, these addresses must be mapped to somewhere, otherwise the app. would fault.

The addresses `0x7fffffe00048 ... 0x7fffffe00048` are the addresses mapped in the [`commpage`](https://newosxbook.com/src.jl?tree=xnu&file=/osfmk/arm/commpage/commpage.c).

{{< details "About Apple XNU Commpage" >}}
Commpage is a special memory structure that is always located at the same address in all macOS processes (tasks). The commpage on macOS serves a purpose similar to [Linux vsyscall](https://lwn.net/Articles/446528/): that is, it's a chunk of data and code that's [shared and mapped](https://flylib.com/books/en/3.126.1.96/1/) into every process at a fixed address, therefore reducing the number of roundtrips to the kernel. On macOS, this mapping is provided by the `xnu` kernel.

* 32-bit systems: `0xFFFF0000-0XFFFF4000`
* 64-bit systems: `0x7FFFFFE00000-0X7FFFFFE00048`
{{< /details >}}

Commpage Address Space:

| **Architecture Type** | **Base Address**   | **End Address**    |
| --------------------- | ------------------ | ------------------ |
| 32-bit                | **0xFFFF0000**     | **0XFFFF4000**     |
| 64-bit                | **0x7FFFFFE00000** | **0X7FFFFFE00048** |
*  

Many system functions are issued via XNU's `commpage`, as an examples [`__commpage_gettimeofday`](https://opensource.apple.com/source/Libc/Libc-1082.50.1/sys/gettimeofday.c.auto.html) for `gettimeofday(...)` via its' [wrapper](https://opensource.apple.com/source/xnu/xnu-3789.41.3/libsyscall/wrappers/__commpage_gettimeofday.c.auto.html).

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

## Windows Reverse Engineering

* [FindEXEC](https://github.com/DosX-dev/FindEXEC) - sorting script, sorts exe/dll based on category (NET/Native/etc.)
* [EasyHook](https://github.com/EasyHook/EasyHook) - a hooking engine for DLLs and .NET (3.5|4.0) assemblies 
* [frida-scripts for WindowsNT](https://github.com/davuxcom/frida-scripts) - Inject JS and C# into Windows apps

## Binary Data Reverse Engineering

* [binkit](https://github.com/ohjeongwook/binkit) -  Binary Reverse Engineering Data Science Kit
* [symbolizer](https://github.com/0vercl0k/symbolizer) - A fast execution trace symbolizer for Windows
* [binocle](https://github.com/sharkdp/binocle) - Graphic Tool to visualize binary data

**References**

* [Debugging iOS binaries with lldb](https://kov4l3nko.github.io/blog/2016-04-27-debugging-ios-binaries-with-lldb/)
* [Bypass Flutter SSL Pinning (2021)](https://github.com/horangi-cyops/flutter-ssl-pinning-bypass)
* [Frida Android Function Enumerator and Dumper](https://github.com/tomelic/ffe)
* [static-arm-bins](https://github.com/therealsaumil/static-arm-bins) - statically compiled ARM binaries for debugging
