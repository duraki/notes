---
title: "lldb"
---

[Click Here](/lldb-for-ios) if you are looking for iOS-specific `lldb` notes. Scroll below to [see attaching errors and workaround](#errors-and-workarounds). 

## Commands/Assistance

* [chisel](https://github.com/facebook/chisel) is a collection of LLDB commands to assist debugging iOS apps.
* [swift_po](https://github.com/kastiglione/swift_po) substitutes `po` command for Swift, with edge cases avoidance.
* [lldb-helpers](https://github.com/kastiglione/lldb-helpers) is a collection of helpers for more precise breakpoints.

## Cheatsheet

### Objective-C

**Inject `LOAD_DYLIB` from LLDB** -- load `Cycript`, or dylib of your choice

```
(lldb) po dlopen("/usr/lib/test.dylib", 1)
```

**Important** -- set a lldb language context to Objective-C:

```
(lldb) settings set target.language objc 
```

Cast an address to object:

```
(lldb) po ((MKPinAnnotationView *)0x7df67c50).alpha
```

### Swift

**Important** -- set a lldb language context to Swift:

```
(lldb) settings set target.language swift
```

Import a Library in the lldb context:

```
# => Library
(lldb) expr -l Swift -- import UIKit

# => Custom Classes
(lldb) expr -l Swift -- import MyTestProject
(lldb) expr -l Swift --  let $vc = unsafeBitCast(0x7fad22c066d0, ViewController.self)
(lldb) expr -l Swift -- print($vc.view)
```

Create a new class from lldb:

```
(lldb) expression let $myHello = HelloClass()
(lldb) po $myHello
```

Call a method from a class:

```
(lldb) po $myHello.hello()
```

Get an object address of current instance:

```
(lldb) p tabView.controlTint
(NSControlTint) $R10 = defaultControlTint

(lldb) p self
(LearningStoryboard.NSTabViewController) $R11 = 0x00006080000e2280 {

# => then cast this address to x object. @see below.
```

Cast an address to object:

```
(lldb) e let $pin = unsafeBitCast(0x7df67c50, MKPinAnnotationView.self)
(lldb) po $pin

# => then you can work with $pin as usual – access properties, call methods, etc.
```

### Multiplatform (ObjC + Swift)

If you want to run an lldb expression depending on the scope, use:

```
(lldb) expression -l objc -o -- HelloClass* class = [[HelloClass alloc] init]      # => obj-c
(lldb) expression -l swift -o -- let $myHello = HelloClass()                       # => swift
```

## Errors and Workarounds

### Attach Failed

**Not allowed to attach to process**

```
(lldb) process attach --pid 76371 # => or 'lldb /Applications/SomeApp.app'
error: attach failed: attach failed (Not allowed to attach to process.  Look in the console messages (Console.app), near the debugserver entries, when the attach failed.  The subsystem that denied the attach permission will likely have logged an informative message about why it was denied.)
```

**Solution:**

```
$ cat /tmp/debug_entitlements.plist
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
        <key>com.apple.security-get-task-allow</key>
        <true/>
        <key>com.apple.security.cs.disable-library-validation</key>
        <true/>
        <key>com.apple.security.device.audio-input</key>
        <true/>
</dict>
</plist>

$ codesign --force --options runtime --sign - --entitlements /tmp/debug_entitlements.plist /Applications/SomeApp.app
```

---

**Not allowed to attach to process**

Note: This is only for stand-alone binaries such is `ls`, `cat` and so on.

```
$ lldb /usr/bin/login
error: attach failed: attach failed
```

**Solution:**

```
$ cat /tmp/debug_entitlements.xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
 <dict>
  <key>com.apple.security.get-task-allow</key>
  <true/>
 </dict>
</plist>

$ cp /usr/bin/login /tmp/login 		# requires entitling a copy of the binary, not the original
$ sudo codesign --sign "signature" -f --timestamp --entitlements ./debug_entitlements.xml /tmp/login
```

You are required to create `signature` certificate from the `Keychain.app` in MacOS.

---

**Terminated due to code signing error**

Happens when targeted application is not properly code signed. Usually happens when you added a new entitlement, but did not codesign a Mach-O binary:

```
(lldb) process attach --pid 76371 # => or 'lldb /Applications/SomeApp.app'
Process 8873 exited with status = 9 (0x00000009) Terminated due to code signing error
```

**Solution:**

Create a Code Signing certificate from within Keychain.app in MacOS (ie. `signature`), and use it to code sign target application. The following will recursevly force code sign of all application resources.

```
# switch signature with your code signing certificate 
$ codesign --deep --force -s "signature" /Applications/SomeApp.app
```

