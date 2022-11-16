---
title: 'Frida Gadget Injection on iOS'
---

Here, I will explain quickly how to patch IPA with Frida Gadget, usable for iOS, and iPadOS operating systems.

**Provision of Apple Certificate**

* Create a new Apple Developer Account (Free), or use Apple Paid Developer Account ($99)
  * *this works even if your Apple Device (iPhone, iPad) is not iCloud synced to newly created account*
* Login to Apple Developer account in XCode via `Preferences -> Account`
* Create a blank iOS app., let it be Objective-C based, name it 'MobileProvision'
* Go to `Target -> MobileProvision`, then select 'Signing & Capabilities'
  * Check 'Automatically manage signing'
  * Set 'Bundle Identifier' to `com.dummydcprovision.MobileProvision'
  * Set 'Team' to reflect newly created Apple Developer Account
* Connect your iPhone device via Lightning Cable
* Select Application Target to the physical device
* Build and run the application
* This will create a new `.mobileprovision`

**Lookup local CodeSign Cert.**

Via Terminal, on your MacOS host, enter the following:

```
$ security find-identity -v -p codesigning
  ...
  6) C250ExxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxD3F "Apple Development: xxxxxxxxxx@gmail.com (4B3xxxxxx4)"
```

As seen, the provision file will be displayed, which we will use later during the IPA patch procedure.

**Use Objection to patch an IPA file**

Using [objection](#) you can patch the IPA file. First, install Objection, as well as `patchipa` command pre-requisits:

```
# install applesign node package
$ npm install -g applesign

# install insert_dylib for injecting
$ cd /tmp/ && git clone https://github.com/Tyilo/insert_dylib && cd insert_dylib &&xcodebuild && cp build/Release/insert_dylib /usr/local/bin/insert_dylib
```

**Patching IPA**

To patch an IPA file, use the command:

```
$ objection patchipa --source /path/to/app.ipa -c CODESIGN_IDENTITY -b com.dummydcprovision.MobileProvision
  # where:
  #     --source      Original IPA File Path
  #     -c            Code Signing Certificate to use (ie. '4B3xxxxxx4')
  #     -b            The bundleid to set when codesigning the IPA, must equal to Bundle Identifier as created 
                      during MobileProvision (see above)
```

Such example can be seen below, disclosing actual usage:

```
$ objection patchipa --source PROJECT/Workpapers/target.ipa -c 4B3xxxxxx4 -b com.dummydcprovision.MobileProvision

# 
# Using latest Github gadget version: 16.0.2
# Patcher will be using Gadget version: 16.0.2
# No provision file specified, searching for one...
# Found provision file $USER/Library/Developer/Xcode/DerivedData/MobileProvision-xxxxxxxxxxxxxxxxxxxxxxxxxxxx/Build/Products/Debug-iphoneos/# MobileProvision.app/embedded.mobileprovision
# Found a valid provisioning profile
# Setting bundleid to specified value: com.dummydcprovision.MobileProvision
# Working with app: xxxxxxxxxxxxxxxxxxx-mobile.app
# Bundle identifier is: com.xxxxxxxxxxx.app
# Codesigning 1 .dylib's with signature 4B3xxxxxx4
# Code signing: FridaGadget.dylib
# Creating new archive with patched contents...
# Codesigning patched IPA...
# 
# Copying final ipa from /var/folders/1t/******************************/T/xxxxxxx-frida-codesigned.ipa to current directory...
# Cleaning up temp files...
```

**Download Frida Gadget to your MacOS Host machine**

This will allow Frida & Objection to connect to a jailed iOS, depending on the installation method, you will need to:

```
# Create Frida cached directory
$ mkdir -p $HOME/.cache/frida/ && cd $HOME/.cache/frida/

# Download universal build of Frida Gadget for iOS, using the Objection gadget version 
$ wget https://github.com/frida/frida/releases/download/16.0.2/frida-gadget-16.0.2-ios-universal.dylib.gz

# Unpack gzip archive
$ gunzip frida-gadget-16.0.2-ios-universal.dylib.gz

$ Rename the unzipped gz file
$ mv frida-gadget-16.0.2-ios-universal.dylib gadget-ios.dylib
``` 

**Install the patched IPA and Inject to Process**

Install the final IPA from MacOS Host to your device, using `ideviceinstaller` command-line utility installed earlier:

```
$ ideviceinstaller -i target.ipa
...
Install: InstallComplete (100%)
Install: Complete
```

To Attach via Frida or Objection, start the Application from the iPhone, and use:

*It is expected for an injected App to hang on Splashscreen, or during application startup. This is due to injected dylib `Frida Gadget`, which will freeze until you attach to the running app.* 

```
$ frida -U -N com.dummydcprovision.MobileProvision
$ objection -g com.dummydcprovision.MobileProvision explore
```