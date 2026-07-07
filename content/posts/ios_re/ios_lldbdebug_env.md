---
title: "lldb for iOS"
---

**Setup LLDB for iOS remote debugging**

Install `lldb` on Host OS (MacOS), and all necessary USB debugging toolset.

```
$ brew install lldb libplist libusb ldid 
# ...

$ brew install iproxy // tunnel ssh traffic to usb
$ iproxy 2222 22  // will tunnel port/2222(usb) to port/22(ssh)
$ iproxy 23999 22 // will tunnel port/23999(usb) to port/22(ssh)

/** we are tunneling 2x ports because one will be used for    */
/** iOS Device shell, and the second one, specifically for the */
/** lldb (debugserver)  */
```

Sign the `debugserver` so that it can attach to iOS apps. To do so, create a new signature file named `entitlements.plist`.

```
$ vi entitlements.plist
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>com.apple.springboard.debugapplications</key>
    <true/>
    <key>get-task-allow</key>
    <true/>
    <key>task_for_pid-allow</key>
    <true/>
    <key>run-unsigned-code</key>
    <true/>
</dict>
</plist>
```

After creating the `entitlements.plist` file with above content, use `codesign` tool to Code Sign your `debugserver`, and then move `debugserver` to your iPhone device.

```
$ codesign -s - --entitlements entitlements.plist -f debugserver
$ scp debugserver root@127.0.0.1:/bin/debugserver		// this will copy signed debugserver to iPhone device
```

The above process is automatically completed in case you use XCode daily, and you already debugged your own app. In this case, the `debugserver` is located on your iPhone device in **`/Developer/usr/bin`**.

(**optional**) Copy `ARMDisassembler` to improve code readability from within `lldb` and `debugserver`:

```
// be sure to change DeviceSupport/?.?/ to your Device version
$ cp /Applications/Xcode.app/Contents/Developer/Platforms/iPhoneOS.platform/DeviceSupport/?.?/DeveloperDiskImage.dmg/Library/PrivateFrameworks/ARMDisassembler.framework ARMDisassembler.framework

// copy *framework to your device
$ scp –r –p ARMDisassembler.framework root@127.0.0.1:/System/Library/PrivateFrameworks
```

Start an `lldb-server` from your iPhone device:

```
root# /bin/debugserver
# debugserver host:port [program-name program-arg1 program-arg2 ...]
# debugserver host:port --attach=<pid>
# debugserver host:port --attach=<process_name>

# (ie. starting debugserver)
root# /bin/debugserver 127.0.0.1:22 /AppName.app/Binary
root# /bin/debugserver 127.0.0.1:22 --attach=7778
```

From the Host OS (MacOS), start the `lldb` and use `process connect` to initialise a connection between your Host and your iPhone device.

```
$ lldb
$ (lldb) process connect connect://127.0.0.1:23999
```

For WindowsOS users, you can use [gikdbg](https://www.andnixsh.com/2018/05/archived-gikdbg-mobile-debugging-tool.html) which is now outdated. It's an Android and iOS debugger developed on top of `ollydbg`. Supports, static analysis of ELF/Mach-O (arm64). The software runs on Windows.

**Inject `LOAD_DYLIB` from LLDB**

```
(lldb) po dlopen("/usr/lib/test.dylib", 1)
```