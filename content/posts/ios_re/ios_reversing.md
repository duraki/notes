---
title: "iOS Reverse Engineering"
---

The notes at [Objective-C RevEng](/objective-c-re) provides introduction to all Objective-C related Reverse Engineering techniques and tactics you might use during [macOS Reverse Engineering](/macos-reverse-engineering) or otherwise, during iOS app. reversing.

**Restart SpringBoard if iPhone crashed**

```
$ killall SpringBoard
$ killall -SIGSEGV SpringBoard ^  // Safe Mode
```

**Print iOS Logs from Terminal**

```
$ tail -f /var/log/syslog
```

**Use `mobdevim` to interact with iOS device**

The [`mobdevim`](https://github.com/DerekSelander/mobdevim) utility written by Derek S. is great little tool that allows us to query and interact with iOS (iPhone) device from our MacOS Host. This utility needs to be compiled by cloning the repository and building it from the XCode. Alterantively, there is an outdated [compiled version](https://github.com/DerekSelander/mobdevim/blob/main/compiled/mobdevim) of it, but I don't recommend using it. Instead, build the XCode Project and copy the built executable `mobdevim` to your `$PATH` directory, ie:

```
$ cp $HOME/Library/Developer/Xcode/.../.../mobdevim ~/.config/bin/
```

Do note that you need to have DDI (*XCode Developer Disk Images*) specific to your iOS version running on the iPhone device. For example, if I'm running iOS 16.7, I'd need a DDI for that iOS version. Some DDI's are available on [this GitHub](https://github.com/mspvirajpatel/Xcode_Developer_Disk_Images) repository. If you can't find DDI you need, then connect your iPhone device to MacOS and build a simple iOS app targeting your iPhone device, which will automatically copy and provision the DDI you need on your HostOS. The provisioned DDI should be visible in the XCode directory:

```
$ ls -la /Applications/Xcode.app/Contents/Developer/Platforms/iPhoneOS.platform/DeviceSupport
# drwxrwxr-x   4 root  wheel  128 Apr 18  2024 16.1
# drwxr-xr-x   4 root  wheel  128 Apr 18  2024 16.4
```

You can see that I have iOS 16.4 DDI already, which would proably work for iOS 16.7 as well, therefore, we can upload the DDI for the `mobdevim`:

```
        # to mount the DDI
$ mobdevim -I /Applications/Xcode.app/Contents/Developer/Platforms/iPhoneOS.platform/DeviceSupport/16.4/DeveloperDiskImage.dmg.signature \
              /Applications/Xcode.app/Contents/Developer/Platforms/iPhoneOS.platform/DeviceSupport/16.4/DeveloperDiskImage.dmg
## Connected to: "XXXXX XXXXXX’s iPhone" (XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX) USB
## DDI mounted to /Developer! |============[REDACTED]============| ETA 100%

        # to later unmount the DDI
$ mobdevim -M       # Unmount
```

Now you can use `mobdevim`, with a few examples shown below:

```
$ mobdevim -F   # list all available connections (USB/WiFi/...)
# [ 1] xxxxxxxx-xxxxxxxxxxxxxxxx ("xxxxxxxx-xxxxxxxxxxxxxxxx") WIFI
# [ 2] xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx ("xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx") USB
# [ 3] xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx ("xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx") WIFI

$ mobdevim -U   # prefer device connection over USB
# Connected to: "XXXXX XXXXXX’s iPhone" (XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX) USB
#             or use:
# mobdevim -W   # prefer device connection over use WiFi
# Connected to: "..."

$ mobdevim -f   # get device info
# Connected to: "XXXXX XXXXXX’s iPhone" (XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX) USB
#
# name	XXXXX XXXXXX’s iPhone 
# UDID	d7d5b623ac4e29331c029537aec9b6e75c81c88c
# Product Type	iPhone10,3
# 
# State	Activated
# ...
# 
# DskSpce	78%
# Serial	XXXXXXXXXXXX
# ...

            ## Requires DDI ##
$ mobdevim -p                   # list running processes on the device
$ mobdevim -k <...>             # kill a process

$ mobdevim -l | grep example    # list all apps & grep/show with name 'example'
# com.example.com, ExampleApp
##          ... or ... 
$ mobdevim -l com.example.com                 # get detailed info about specified app
$ mobdevim -l com.example.com Entitlements    # list 'Entitlemenets' key from specified app

            ## Requires DDI ##
$ mobdevim -o com.example.com   # open app
#           ... or ...
$ mobdevim -o com.example.com -A "--some-args-here" -V EnvKey=EnvValue \
                              -V AnotherEnv=SomeValue # open app with args and env flags                       

$ mobdevim -g com.example.com   # get device logs for specific app
$ mobdevim -g 3                 # get the 3rd most recent log
$ mobdevim -g __all             # get all the logs
$ mobdevim -c                   # dump out the console info

$ mobdevim -i <path_to_bundle>    # Install app. given the path to bundle
$ mobdevim -u <bundleIdentifier>  # Uninstall an app, given the bundleIdentifier

            ## Requires DDI ##
$ mobdevim -L 0 0               # remote location simulation
$ mobdevim -L <lat> <lon>       # simulate phone in location at lan/lon

$ mobdevim -R                   # use color in tty output
                                # or use: DSCOLOR=1 mobdevim <...>
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
* [Testing if an arbitrary pointer is a valid ObjC Object](https://blog.timac.org/2016/1124-testing-if-an-arbitrary-pointer-is-a-valid-objective-c-object/)
* [Unredacting iOS's `<private>` os_log privacy mechanism](https://github.com/EthanArbuckle/unredact-private-os_logs), practically [explained here](https://naehrdine.blogspot.com/2022/05/iphone-setup-for-reversing-and-debugging.html)
* [Embedding Frida in iOS TestFlight Apps](https://naehrdine.blogspot.com/2023/02/embedding-frida-in-ios-testflight-apps.html)