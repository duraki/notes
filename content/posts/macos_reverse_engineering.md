---
title: "MacOS Reverse Engineering"
---

Click Here to read notes and visit ToC of [Encryption & Cryptography](/encryption-and-cryptography). It helps knowing more deep technical stuff for the overview of those notes. Besides, also take a look at: [Ghidra](/ghidra), [LLDB for MacOS](/macho_lldb), and [Hopper for MacOS](/pure_reverse_engineering).

## How to `log`
To access the same logs from the command line, the `log` command can be used.

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

* `/Users/hduraki/Library/HTTPStorages/` (Contains all App. bundles HTTP Storage, incl. cookies et al)
* *todo*: add more

## Code Signing

Due to Apple being what it is, they included additional hardened layer, that sits between native GateKeeper and the XPC surface. This makes our life much harder. Luckly, there are some steps that you can take to minimise the troublesome. Fortunately, Apple provides their [full PKI list](https://www.apple.com/certificateauthority/) which can be used to revocate CA-X.509 Certificates.

First, decode the original app. provision file (it's a [CMS Encrypted XML](http://en.wikipedia.org/wiki/Cryptographic_Message_Syntax)):

```
$ security cms -D -i /Applications/IE.app/Contents/MacOS/embedded.provisionprofile > embedded.plist	 # => or .mobileprovision for iOS
``` 

This will create an XML file containing the original Provision File. Next, we can use `plist` to extract the Entitlements attributes:

```
$ plutil -p embedded.plist
```

> You will have to create a new project in XCode, add Capability by clicking **Project Root** -> **Targets** and pressing *"+ Capability"* in the top-left corner. This will allow you to build placeholder for a Provisioning Profile during the project build (ie. CodeSign phase).

## CodeSign CLI's

**Tools I often use**

```
jtool, 
spctl -  manages the system's security assesment policy; meaning you can control Gatekeeper
codesign - 
security - decodes CMS format
openssl - ofcourse :)
xcrun [altool] - validate apps for the App Store, or Notarize apps
csreq – Expert tool for manipulating Code Signing Requirement data
rcodesign - 3rd party code sign
```

**Display valid Code Signing identities of the MacOS**

```
# you need to create "Code Signing" certificates from the Keychain Access

$ xcrun security find-identity -v -p codesigning

  1) 1C8177C2xxxxxxxxxxxxxxxxxxx6C565999Dxxxx "signature"
  2) E8B3B406xxxxxxxxxxxxxxxxxxx6C8EA4A38xxxx "mycert"
  3) 3F4806E9xxxxxxxxxxxxxxxxxxx173A6C3C8xxxx "Apple Development: Halis Duraki (SXXXXXXXX7)"
     3 valid identities found

 # ... or ...

$ security find-identity -p basic -v 		  # display all installed certificates
  1) 1C8177C25FF5BA8F2215C6F76F36C565999D7A9B "signature"
  2) E8B3B406A2DDA93ED554D9CC53B6C8EA4A38A909 "durakicert"
  3) B51C0B6A529E1FD733FE25D5EEF05865282E44B7 "JamfProtect Client 98CFE55D-360D-5BD2-871F-AB2E1B92E14F"
  4) 2DAEC6934DF5F94EA40D06709CEEC64EB82E4AED "A41D5801-A179-4211-94C7-250007CA5B5C"
  5) 9F9267442F6C4C3B0700EE8B72184FF81D7442D2 "ema.protect Jamf Protect CSR Identity"
  6) 622D3B81D69547167160DA8D615C2B264B4E558D "CE-C02G20EZMD6R.atrema.deloitte.com"
     6 valid identities found
```

**Display CodeSign information of the App.**
```
$ codesign -dvvv iA\ Writer.app
Executable=/private/tmp/iA Writer.app/Contents/MacOS/iA Writer
Identifier=pro.writer.mac
Format=app bundle with Mach-O universal (x86_64 arm64)
CodeDirectory v=20500 size=34554 flags=0x10000(runtime) hashes=1069+7 location=embedded
Hash type=sha256 size=32
CandidateCDHash sha1=1af6ef1b45248d495868ff0d59f02c36b34caa1e
CandidateCDHashFull sha1=1af6ef1b45248d495868ff0d59f02c36b34caa1e
CandidateCDHash sha256=6af0b89206a68b7bea946980bda5d9f67a183b6d
CandidateCDHashFull sha256=6af0b89206a68b7bea946980bda5d9f67a183b6de460f992bc908f14197e8fbf
Hash choices=sha1,sha256
CMSDigest=1b78d64b1fa909284c8bb4c2a0fc076fc8cbfc91c10b5b2dc4b6d4ca42641274
CMSDigestType=2
CDHash=6af0b89206a68b7bea946980bda5d9f67a183b6d
Signature size=9036
Authority=Developer ID Application: Information Architects GmbH (27N4MQEA55)
Authority=Developer ID Certification Authority
Authority=Apple Root CA
Timestamp=4 Mar 2021 at 10:15:29
Info.plist entries=38
TeamIdentifier=27N4MQEA55
Runtime Version=11.1.0
Sealed Resources version=2 rules=13 files=697
Internal requirements count=1 size=208
```

**Display (in)validity of the CodeSign ident. of the App.**

```
$ codesign --verify -vv --no-strict /Applications/IE.app
/Applications/IE.app: invalid signature (code or signature have been modified)
In architecture: x86_64
```

**Clear extended attributes (CodeSign Ident.)**

```
$ xattr -lr /Applications/IE.app 		# to see which files are causing errors/codesign issues
$ xattr -cr /Applications/IE.app 		# remove all extended attributes from the app bundle
$ xattr -c  /Applications/IE.app/<file path> 		# clear extended attributes of several files
``` 

**Display App Bundle Base Attributes**

```
$ codesign -dv -r- /Applications/IE.app
Executable=/Applications/IE.app/Contents/MacOS/IE
Identifier=pro.ie.mac
Format=app bundle with Mach-O universal (x86_64 arm64)
CodeDirectory v=20500 size=34554 flags=0x10000(runtime) hashes=1069+7 location=embedded
Signature size=9036
Timestamp=4 Mar 2021 at 10:15:29
Info.plist entries=38
...
```

**[TABLE] X.509 Certificate Format**

```
$ /Applications/RevEng/rcodesign x509-oids 	# => use this cmd to print it
# Extended Key Usage (EKU) Extension OIDs

1.3.6.1.5.5.7.3.3	CodeSigning
1.2.840.113635.100.4.8	SafariDeveloper
1.2.840.113635.100.4.9	ThirdPartyMacDeveloperInstaller
1.2.840.113635.100.4.13	DeveloperIdInstaller

# Code Signing Certificate Extension OIDs

1.2.840.113635.100.6.1.1	AppleSigning
1.2.840.113635.100.6.1.2	IPhoneDeveloper
1.2.840.113635.100.6.1.3	IPhoneOsApplicationSigning
1.2.840.113635.100.6.1.4	AppleDeveloperCertificateSubmission
1.2.840.113635.100.6.1.5	SafariDeveloper
1.2.840.113635.100.6.1.6	IPhoneOsVpnSigning
1.2.840.113635.100.6.1.7	AppleMacAppSigningDevelopment
1.2.840.113635.100.6.1.8	AppleMacAppSigningSubmission
1.2.840.113635.100.6.1.9	AppleMacAppStoreCodeSigning
1.2.840.113635.100.6.1.10	AppleMacAppStoreInstallerSigning
1.2.840.113635.100.6.1.12	MacDeveloper
1.2.840.113635.100.6.1.13	DeveloperIdApplication
1.2.840.113635.100.6.1.33	DeveloperIdDate
1.2.840.113635.100.6.1.14	DeveloperIdInstaller
1.2.840.113635.100.6.1.16	ApplePayPassbookSigning
1.2.840.113635.100.6.1.17	WebsitePushNotificationSigning
1.2.840.113635.100.6.1.18	DeveloperIdKernel
1.2.840.113635.100.6.1.25.1	TestFlight

# Certificate Authority Certificate Extension OIDs

1.2.840.113635.100.6.2.1	AppleWorldwideDeveloperRelations
1.2.840.113635.100.6.2.3	AppleApplicationIntegration
1.2.840.113635.100.6.2.6	DeveloperId
1.2.840.113635.100.6.2.9	AppleTimestamp
1.2.840.113635.100.6.2.11	DeveloperAuthentication
1.2.840.113635.100.6.2.14	AppleApplicationIntegrationG3
1.2.840.113635.100.6.2.15	AppleWorldwideDeveloperRelationsG2
1.2.840.113635.100.6.2.19	AppleSoftwareUpdateCertification
```

### Resources

* [TN3125: Inside Code Signing: Provisioning Profiles](https://developer.apple.com/documentation/technotes/tn3125-inside-code-signing-provisioning-profiles)
* [TN3126: Inside Code Signing: Hashes](https://developer.apple.com/documentation/technotes/tn3126-inside-code-signing-hashes)
* [TN3127: Inside Code Signing: Requirements](https://developer.apple.com/documentation/technotes/tn3127-inside-code-signing-requirements)
* [Using the Latest Code Signature Format](https://developer.apple.com/documentation/Xcode/using-the-latest-code-signature-format)
* [Certificate, Key, and Trust Services](https://developer.apple.com/documentation/security/certificate_key_and_trust_services)
* [App Groups Entitlement](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_application-groups)
* **Tools:** [iOSValidation](https://github.com/quadion/iOSValidation), [codesign](https://codesigning.guide/)