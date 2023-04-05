---
title: "iOS Reverse Engineering"
---

**Restart SpringBoard if iPhone crashed**

```
$ killall SpringBoard
$ killall -SIGSEGV SpringBoard ^  // Safe Mode
```

**Print iOS Logs from Terminal**

```
$ tail -f /var/log/syslog
```

**Using `class-dump`, or `dsdump`**

```
$ class-dump -S -s -H App -o /path/to/headers/App/    // old way
$ dsdump App  // new way
```

**Install offloaded `*IPA` files**

```
# requires:
#   brew install libimobiledevice
#   brew install ideviceinstaller

$ ideviceinstaller -i <path_to_ipa_file>
```

**`frida-server` crashing on iPhone device**

If your `frida-server` is crashing on the iPhone test device, you can try to:

* Reset `frida-server` on test device (*requires gawk*):

```
# from your "iPhone:" device, such is via SSH tunnel

$ apt install gawk
$ FRIDA_PID=$(ps aux | grep frida-server | grep -v grep | awk '{print $2}'); kill -9 $FRIDA_PID; frida-server -l 0.0.0.0
```

* Inject Frida Gadget in the iOS app. and engage from non-jailbroken iDevice
* Upgrade to latest [Frida](https://frida.re) version

**Memory modification on Jailed iPhone devices**

[ipa-medit](https://github.com/aktsk/ipa-medit) is a memory search and patch tool for resigned `*ipa` without jailbreaking. It supports iOS apps running on iPhone and Apple Silicon Mac. It was created for mobile game security testing. Many mobile games have jailbreak detection, but `ipa-medit` does not require jailbreaking, so memory modification can be done without bypassing the jailbreak detection. Similar tool exists for Android named `apk-medit`. The target `.ipa` file must be signed with a certificate installed on your computer. If you want to modify memory on third-party applications, please use a tool such as [ipautil](https://github.com/aktsk/ipautil) for re-signing.

Usage:

```
# => using iPhone requirs you to provide executable file path from *ipa and the Bundle ID
$ unzip SomeGame.ipa
$ ipa-medit -bin="./Payload/SomeGame.ipa/SomeGame" -id="com.durakiconsulting.game"
```

Commands:

```
# find          Search the specified integer on memory.
#               By default, only Integer types are search when targeting iOS apps running on iPhone
> find 999986
> find [string|word|dword|qword] 999994
  # Success to halt process
  # Scanning: 0x00000001025e4000-0x00000001025e8000
  # ...
  # Found: 1!!
  # Address: 0x10a2feea0

# filter        Filter previous search results that match the current search results.
> filter 999842

# patch         Write the specified value on the address found by search.
> patch 10

# attach       Attach to the target process.
> atach

# detach       Detach from the attached process.
> detach

# ps           Get information about the target process. It will only work if you are targeting an iOS app running on an iPhone.
> ps
  # SBProcess: pid = 926, state = running, threads = 37, executable = tap1000000
  # State: Running
  # thread #1: tid = 0x545ee, 0x00000001bd6552d0 libsystem_kernel.dylib`mach_msg_trap + 8, queue = 'com.apple.main-thread'
...

# exit         Exit ipa-medit (shortcut: Ctrl-D).
> exit
```

Use official documentation to read [troubleshooting](https://github.com/aktsk/ipa-medit#trouble-shooting) guide.

**Common iOS RE tools**

* [ClassDumpRuntime](https://github.com/leptos-null/ClassDumpRuntime) - create human readable interfaces from ObjC runtime
* [SwiftDump](https://github.com/neil-wu/SwiftDump) - extract Swift Object from Mach-O file, supports Swift 5

... commonly for *debugging*

```
$ brew install lldb
```

... commonly for *hooking*

* Cydia Substrate
* Theos

... via *Cydia and `apt-get*` (non-jailed)

```
Cydia:
  - OpenSSH, OpenSSL
  - tcpdump # https://mcapollo.github.io/Public/
  - python, pip # https://mcapollo.github.io/Public/
  - AppSync # https://cydia.akemi.ai/?page/net.angelxwind.appsyncunified
  - Cycript # https://cydia.saurik.com/package/cycript/
  - Apple File Conduit # https://cydia.saurik.com/package/com.saurik.afc2d/
  - syslog # https://cydia.saurik.com/package/syslogd/
apt-get
  - adv-cmds (finger, fingerd, lsvfs, last, md, ps)
  - file-cmds (chflags, compress, ipcrm, ipcs, pax)
  - basic-cmds (msg, uudecode, uuencode, write)
  - shell-cmds (killall, mktemp, renice, time, which)
  - system-cmds (iostat, login, passwd, sync, sysctl)
  - diskdev-cmds (mount, quota, fsck, fstyp, fdisk, tunefs)
  - network (arp, ifconfig, netstat, route, traceroute)
  - syslog (syslogon, syslogoff); /var/log/syslog
  - wget, ncdu, lsof, file, less
  - gdb (ar, nm, objdump, ranlib, strip, addr2line, gdb, objdump)
```

### Related iOS Notes~

* [Frida & Objection Tutorial](/frida-objection-tutorial#ios-tutorial)
* [LLDB](/lldb-for-ios)
* [Pure Reverse Engineering](/pure-reverse-engineering)
* [Cycript](/cycript)
* [Decrypt IPA from AppStore](/decrypt-ipa-from-appstore)
* [iOS Jailbreak Bypass](/jailbreak-bypass)
* [iOS Static Analysis](/ios-static-analysis)

**References**

* [iOS Private Frameworks](https://www.theiphonewiki.com/wiki//System/Library/PrivateFrameworks), [Latest Listing](https://developer.limneos.net/?ios=14.4)
* [iOS Pentesting Checklist](https://book.hacktricks.xyz/mobile-pentesting/ios-pentesting-checklist)
* [iOS WebViews Debugging](https://book.hacktricks.xyz/mobile-pentesting/ios-pentesting/ios-webviews)
* [iOS CheatSheet](https://owasp.org/www-pdf-archive/OWASPIreland-Limerick-Day_20131031_iOSCheatSheet-OanaCornea.pdf)
* [Reverse Engineering Tools](https://iphonedevwiki.net/index.php/Reverse_Engineering_Tools)
* [iOS Static Analysis](https://trelis24.github.io/2018/03/27/Pentesting-iOS-Static/)
* [iOS Internals and Security Testing](https://github.com/vadimszzz/iOS-Internals-and-Security-Testing)
* [iOS Hacking Resources](https://github.com/Siguza/ios-resources)
* [iOS 16.x Class Headers Dump](https://headers.cynder.me/index.php?sdk=ios/16.0)
