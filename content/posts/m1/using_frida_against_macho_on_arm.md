---
title: "Using Frida against MachO on ARM"
---

This short notes will introduce you to basic attacking and reverse engineering techniques against MachO binaries running on MacOS M1/M2 ARM processor. This also includes a self-invented technique to attack iOS apps. running on M1/M2 machines  ⃗ **without disabling SIP**.

**Preliminary Setup**

We will target an iOS application running on M1/M2, based on MacOS Ventura. The target for today is `UniFon` which is a VOIP/SIP mobile app. provided by my Telecom provider as a part of the package. By using UniFon, I can call free-of-charge via my home-office phone number, whenever I'm on the go.

The application was extracted via off-the-shelf dumping tools, like these described in [iOS App. Decryption](/decrypt-ipa-from-appstore) notes. Upon successful extraction, I've installed the app. via iOS App Installer that comes by default on all M1/M2 Apple hardware.

Make sure to have common **#RevEng** tools installed. I prefer to work in my Virtual MacOS environment which helps me keep my Host OS tidy and clean. Not to tell its a lot easier to work with, when doing multiple, large engagements.

You can download decrypted iOS applications online. I like to use [decrypt.day](https://decrypt.day). Otherwise, I charge my jailbroken testbed iPhones, and dump target IPA manually.

For a start, lets enable Developer Mode on our MacOS:

```
$ sudo DevToolsSecurity -enable
```

**Bypassing SIP Protection without Kernel/NV Tricks**

I've researched this exploit myself in ~2k21 while playing on M1 virtual box that I had provisioned. This was proposed to Olle' from Frida/@NowSecure and he was grateful for sharing this trick.

The trick works by abusing Apple's own Notarization internals; This was invented by Apple in a hope to prevent apps. from being easily cracked and exploited. Little did they know it's a double-edged sword.

**Injecting Frida on M1/M2 iOS apps**

Using this trick, it's possible to inject Frida Binary Instrumentation toolkit on M1 process, without disabling SIP. This native exploit consists of few steps:

* Starting a targeted iOS app. on M1/M2
* Attaching MacOS's original `lldb` (Notarized)
* Wait for `lldb` to hit early thread breakpoint
* Attach a Frida to App. during the breakpoint
* Once Frida is attached, it will wait for REPL command
* In Frida REPL, type `%resume` to continue iOS app. lifecycle
* In `lldb` again, continue (c) with the process lifecycle
* Frida will automatically attach to the iOS app.

*How it works:* there is no easy way to explain it, but take a look at `frida-core` and `frida-gum` to gain insight on how Frida works in normal occurences. Usually, it gets `dylibmap` and tries to inject to relative memory address on mm/procmap (with a bit of paging). Due to `lldb` being notarized by Apple, as with other bundled MacOS software, it has all privileges to access a process; meaning it uses Signing/Notarization with communication on XPC layer, having "all ACL privileges" in their sandbox. Once `lldb` maps a process within those access rights, the apps that are attached to the debugger are also children, therefore, Frida in this case, also being one of the children of the top-down proc/privs hierarchy. This way, **SIP is bypassed**, and Frida can continue injecting its own dylib map into the targeted app.

## Practical Excersise

Start of by choosing a good target to test. Inhere, I will use "DVIA-v2" which is a common OSS vulnerable iOS app. for testing. After small code change and compilation of the XCode project, I ended up with:

{{< imgcap title="Compiled DVIA running on MacOS M1" src="/posts/images/ios-dvia-2.png" >}}

The build of target app. is compiled for `iPad8,6` (effectively an IPA), useable in MacOS via "App Bundle Wrapper", that acts as a bridge between IPA and MacOS apps.

Lets start cracking. Make sure to always copy the app. to `~/temp` or similar directory. In fact, applications directly stored in `/Applications` or `~/Applications` usually won't play well with `lldb`.

```
$ cp ~/Library/Developer/Xcode/DerivedData/DVIA-v2-xxxxxxxxxxxxxxxxxxxxxxxxxxxxx/Build/Products/Debug-iphoneos/DVIA-v2.app ~/Projects/DVIA_frida-m1-_NOSIP/DVIA.app

$ cd ~/Projects/DVIA_frida-m1-_NOSIP && tree
# .
# └── DVIA.app
#    ├── AntiAntiHookingDebugging.storyboardc
# ...
```

We can do some basic recon. process to get feel of the target:

```
$ file ./DVIA.app/DVIA-v2
./DVIA.app/DVIA-v2: Mach-O 64-bit executable arm64

$ otool -L DVIA.app/DVIA-v2
DVIA.app/DVIA-v2:
	/usr/lib/libc++.1.dylib (compatibility version 1.0.0, current version 1300.36.0)
	/usr/lib/libsqlite3.dylib (compatibility version 9.0.0, current version 346.0.0)
	/usr/lib/libz.1.dylib (compatibility version 1.0.0, current version 1.2.11)
	# ...
```

It's good to note that you may also try [mirage/conan](https://github.com/mirage/conan) which is file type detection, a successor of Unix `file` command.

Looking at the `otool` output, we can see that the app is correctly code-signed:

```
$ codesign -d DVIA.app -vv
Executable=/Users/$USER/Projects/DVIA_frida-m1-_NOSIP/DVIA.app/DVIA-v2
Identifier=com.durakiconsulting.DVIA
Format=app bundle with Mach-O thin (arm64)
CodeDirectory v=20400 size=70877 flags=0x0(none) hashes=2204+7 location=embedded
Signature size=4781
Authority=Apple Development: XXXXX XXXXXX (xxxxxxxxxx)
TeamIdentifier=xxxxxxxxxx
# ...
```

Remember, you will need to strip code-signature that is bundled with the targeted application. You can do so by looking at `xattr`, described in the [MacOS Reverse Engineering notes](/MacOS-Reverse-Engineering).

It's time to start debugging into the iOS application.

```
$ lldb DVIA.app
Voltron loaded.
Registered stop-hook
(lldb) target create "DVIA.app"
Current executable set to '/Users/$USER/Projects/DVIA_frida-m1-_NOSIP/DVIA.app' (arm64).
```

But, if we try to start the app. from within debugger:

```
(lldb) r
Process 50552 launched: '/Users/$USER/Projects/DVIA_frida-m1-_NOSIP/DVIA.app/DVIA-v2' (arm64)
# Process 50552 exited with status = 9 (0x00000009) Terminated due to code signing error
```

Once again, reference to [MacOS Reverse Engineering notes](/MacOS-Reverse-Engineering) to learn how to circumate such errors; it's simply as:

```
$ codesign --deep --force -s "codesign" DVIA.app
DVIA.app: replacing existing signature

    # the "codesign" is my own code-signing certificate,
    # created over Keychain Access and setting it as trusted.
    # this is so-called "Ad-Hoc" code signing of Apple Apps. and it
    # works only on your own PC.
```

While we are on preparation, lets also include special entitlement that allows us to attach to the process.

```
$ codesign --force --options runtime --sign - --entitlements ~/entitlements.plist DVIA.app
DVIA.app: replacing existing signature
```

Run the iOS application either by passing the filename to `lldb` or using the PID as I do below:

```
    # Running app. Process ID
$ pgrep -x DVIA-v2
64421

    # Attach to Process ID via lldb
$ lldb -p 64086
Voltron loaded.
Registered stop-hook
(lldb) process attach --pid 64086
Process 64086 stopped
* thread #1, queue = 'com.apple.main-thread', stop reason = signal SIGSTOP
    frame #0: 0x000000018049a050 libsystem_kernel.dylib`mach_msg2_trap + 8
libsystem_kernel.dylib`mach_msg2_trap:
->  0x18049a050 <+8>: ret

libsystem_kernel.dylib`macx_swapon:
    0x18049a054 <+0>: mov    x16, #-0x30
    0x18049a058 <+4>: svc    #0x80
    0x18049a05c <+8>: ret

Architecture set to: arm64e-apple-ios-.
(lldb)
```

That breakpoint trap is exactly the place where we should sit at, during the spawn of Frida toolset.

Attach Frida to the PID of the running process using the command below:

```
$ frida -p 64086
     ____
    / _  |   Frida 16.0.11 - A world-class dynamic instrumentation toolkit
   | (_| |
    > _  |   Commands:
   /_/ |_|       help      -> Displays the help system
   . . . .       object?   -> Display information about 'object'
   . . . .       exit/quit -> Exit
   . . . .
   . . . .   More info at https://frida.re/docs/home/
   . . . .
   . . . .   Connected to Local System (id=local)
Attaching...
```

Go back in your `lldb` Termianl window and continue process execution; and Frida will as well connect to targeted iOS app.

```
(lldb) c
# Process 64086 resuming
# ...
```

As soon as the process pops with lifecycle continuation, Frida will either connect automatically, or you will have to `%resume` the dylib injection process.

```
#                   ... cont
# Attaching...
[Local::PID::64086 ]-> %resume
[Local::PID::64086 ]->
```

From there on, you can continue enganging and hunting exploits as typical 🥳

```
[Local::PID::64086 ]-> Frida.version
"16.0.11"
[Local::PID::64086 ]-> ObjC.api
{
    "_dispatch_main_q": "0x10525cd40",
    "class_addMethod": "0x180176c4c",
    # ...
[Local::PID::64086 ]-> Object.keys(ObjC.classes).slice(0, 10)
[
    "JSExport",
    "Object",
    # ...,
    "NSProxy",
    "RawCameraCIImageProxy",
    "FlurryWatchConnectivityProxy"
]
```

**Important** - Depending on the targeted architecture, you may need to setup a `frida-server` for specific architecutre, that will act as a gateway between the targeted Arch and the Host OS.

```
# example, for macos/arm64
$ wget https://github.com/frida/frida/releases/download/16.0.11/frida-server-16.0.11-macos-arm64.xz
# ...

$ xz -d frida-server-16.0.11-macos-arm64.xz     # to extract it
$ sudo ./frida-server-16.0.11-macos-arm64

# Remember:
# frida-server needs to be running during the Frida instrumentation
```

For a list of `frida-server` and their downloads, refer to official GitHub releases on Frida repository. Make sure to match the version of the server on par with your `frida-tools`.
