---
title: "MacOS Reverse Engineering"
---

It helps knowing more deep technical stuff for the overview of those notes. Besides, also take a look at: [Ghidra](/ghidra-and-related), [LLDB for MacOS](/lldb-for-macos), and [Hopper for MacOS](/pure-reverse-engineering). Notes on [`dyld` Injection](/dyld-macos-injection) are also handful for Mach-O RE tasks.

Additionally, the notes at [Objective-C RevEng](/objective-c-re) provides introduction to all Objective-C related Reverse Engineering techniques and tactics you might use during macOS Reverse Engineering or otherwise, during [iOS RevEng](/ios-reverse-engineering).

Some additional instructions on #RevEng, specifically making sense of MacOS disassembled instructions in Hopper, is visible on [Apple XNU commpage](/pure-reverse-engineering#macos-and-ios-commpage) notes. This section briefly explains what are pseudo-random memory addresses visible here and there in the Hopper Disassembler outputs.

## Accessing Metadata Attributes {{< sup_a "ref/metadata" "/macos-metadata-extraction" >}}

Describing how to use `mdls`, `mdfind` and `mdutil`, and `mdimport` is [referenced in related](/macos-metadata-extraction) notes.

## Converting MachO binaries {{< sup_a "ref/tool/LIPO" "/lipo" >}}

Using [lipo](/lipo) to convert a MachO universal binary, or a single-architecture binary.

## Accessing AppStore Downloaded PKGs

The location of AppStore's downloaded application, ie. `*.PKG` and `*.DMG`, is generated in a different spot. You have to crawl the filesystem to locate the folder(s) that contain these files.

```
ls -ld $TMPDIR../C/com.apple.appstore*

drwx------  5 $USER  staff  160 Feb 27 16:23 /var/folders/g1/3xgktw055bj8v173njj_333m0000gn/T/../C/com.apple.appstoreagent
drwx------  2 $USER  staff   64 Feb 28 06:59 /var/folders/g1/3xgktw055bj8v173njj_333m0000gn/T/../C/com.apple.appstorecomponentsd
```

## Accessing Logs on System Level

To access the Host OS (MacOS) logs from the command line, the `log` command can be used.

```
# => will log via default settings
$ (sudo) log show --style syslog --predicate 'process == "com.durakiconsulting.appname"'

# => will log with debug & info
$ (sudo) log show --style syslog --predicate 'process == "com.durakiconsulting.appname"' --debug --info
```

You may also filter results depending on use-case:

```
# => will log via default, and match only "Error" message
$ (sudo) log show --style syslog --predicate 'process == "com.durakiconsulting.appname" && eventMessage CONTAINS "Error"'
```

Additonally, run the binary from the Terminal, which will yield `stdout` and `stderr` logs just from that specific app.

```
$ /Applications/AppName.app/Contents/MacOS/AppName
```

## Dump System LaunchServices
Basically, OS X LaunchServices is how an application is found to run when you double-click on a document. If the program is in `/Applications`, or you launch it at least once, then LaunchServices should detect it. LaunchServices contains a big, long list of all the Applications, and which ones accept documents of which type. So if you have an Application that is not "registering" correctly with LaunchServices, try this in the Terminal:

Via `lsregister` utility:
```
$ /System/Library/Frameworks/CoreServices.framework/Frameworks/LaunchServices.framework/Versions/Current/Support/lsregister -dump
```

Via `defaults` cli utility:
```
$ defaults read com.apple.LaunchServices # | grep -v LSBundleLocator 
```

## Interesting Paths

* `/Users/<USER>/Library/HTTPStorages/` (Contains all App. bundles HTTP Storage, incl. cookies et al)

## Code Signing

Due to Apple being "security-oriented", they included additional hardened layer that sits between native GateKeeper (`ring3`) and the XPC (`ring0`) surface. There are some steps that you can take to minimise the troublesome of reversing Apple apps. Fortunately, Apple provides their [full PKI list](https://www.apple.com/certificateauthority/) which can be used to revocate CA-X.509 Certificates.

First, decode the original provision file of a targeted Application (it's a [CMS Encrypted XML](http://en.wikipedia.org/wiki/Cryptographic_Message_Syntax)):

```
$ security cms -D -i /Applications/AppName.app/Contents/MacOS/embedded.provisionprofile > embedded.plist	 # => or .mobileprovision for iOS
```

This will create an XML file containing the original Provision File. Next, we can use `plist` to extract the Entitlements attributes:

```
$ plutil -p embedded.plist
```

> You will have to create a new project in XCode, add Capability by clicking **Project Root** -> **Targets** and pressing *"+ Capability"* in the top-left corner. This will allow you to build placeholder for a Provisioning Profile during the project build (ie. CodeSign phase).

## Code Signing Toolset

**Tools I often use**

```
jtool (code signing),
spctl (manage system's policy, controls gatekeeper),
codesign (macos codesign utility),
security (decode CMS format),
openssl (generate certificates),
xcrun (validate/notarize utility),
csreq (code signing utility),
rcodesign (3rd party code signing utiltiy)
```

**Display valid Code Signing identities of the MacOS**

```
# You need to create "Code Signing" certificates from the Keychain Access
$ xcrun security find-identity -v -p codesigning

  1) 1C8177C2xxxxxxxxxxxxxxxxxxx6C565999Dxxxx "signature"
  2) E8B3B406xxxxxxxxxxxxxxxxxxx6C8EA4A38xxxx "mycert"
  3) 3F4806E9xxxxxxxxxxxxxxxxxxx173A6C3C8xxxx "Apple Development: Developer Name (SXXXXXXXX7)"
     3 valid identities found

 # ... or ...

$ security find-identity -p basic -v 		  # display all installed certificates
  1) 1C8177C2xxxxxxxxxxxxxxxxxxx6C565999Dxxxx "signature"
  2) E8B3B406xxxxxxxxxxxxxxxxxxx6C8EA4A38xxxx "mycert"
  3) 3F4806E9xxxxxxxxxxxxxxxxxxx173A6C3C8xxxx "Apple Development: Developer Name (SXXXXXXXX7)"
     3 valid identities found
```

**Display CodeSign information of the App.**

```
$ codesign -dvvv /Application/SomeApp.app   # Verbose

Executable=/private/tmp/SomeApp.app/Contents/MacOS/SomeApp
Identifier=com.durakiconsulting.someapp
Format=app bundle with Mach-O universal (x86_64 arm64)
...
TeamIdentifier=2XXXXXXXX5

 # ... or ...

$ codesign -dv -r- /Applications/SomeApp.app  # Base Attributes

Executable=/Applications/SomeApp.app/Contents/MacOS/SomeApp
...
```

**Display (in)validity of the CodeSign Identity**

```
$ codesign --verify -vv --no-strict /Applications/SomeApp.app

/Applications/SomeApp.app: invalid signature (code or signature have been modified)
In architecture: x86_64
```

**Clear Extended Attributes**

```
$ xattr -lr /Applications/SomeApp.app 		# to see which files are causing errors/codesign issues
$ xattr -cr /Applications/SomeApp.app 		# remove all extended attributes from the app bundle
$ xattr -c  /Applications/SomeApp.app/<file path> # clear extended attributes of several files
```

**X.509 Certificate Format**

```
$ rcodesign x509-oids 	# => to print OIDs for x.509 certs

1.3.6.1.5.5.7.3.3	        CodeSigning
1.2.840.113635.100.6.1.1	AppleSigning
1.2.840.113635.100.6.1.2	IPhoneDeveloper
...
```

### Resources

* [MacOS Frida Setup](https://naehrdine.blogspot.com/2022/11/macos-frida-setup.html)
* [Jailbreak any IPA and run it on Apple M1/M2 macOS w/o decrypting](https://github.com/RootHide/FairFree)
* [MacOS Open Source](https://developer.apple.com/opensource/)
* [MacOS Documentation Archives](https://developer.apple.com/library/archive/navigation/)
* [Apple Legacy Manuals](https://web.archive.org/web/20180414202241/http://home.earthlink.net/~strahm_s/manuals.html)
* [OS X Frameworks](https://developer.apple.com/library/archive/documentation/MacOSX/Conceptual/OSX_Technology_Overview/SystemFrameworks/SystemFrameworks.html), [Apple Frameworks](https://iphonedev.wiki/index.php/Frameworks), [System Frameworks](https://www.theiphonewiki.com/wiki//System/Library/Frameworks)
* [TN3125: Inside Code Signing: Provisioning Profiles](https://developer.apple.com/documentation/technotes/tn3125-inside-code-signing-provisioning-profiles)
* [TN3126: Inside Code Signing: Hashes](https://developer.apple.com/documentation/technotes/tn3126-inside-code-signing-hashes)
* [TN3127: Inside Code Signing: Requirements](https://developer.apple.com/documentation/technotes/tn3127-inside-code-signing-requirements)
* [Using the Latest Code Signature Format](https://developer.apple.com/documentation/Xcode/using-the-latest-code-signature-format)
* [Certificate, Key, and Trust Services](https://developer.apple.com/documentation/security/certificate_key_and_trust_services)
* [App Groups Entitlement](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_application-groups)
* **Tools:** [iOSValidation](https://github.com/quadion/iOSValidation), [codesign](https://codesigning.guide/)
