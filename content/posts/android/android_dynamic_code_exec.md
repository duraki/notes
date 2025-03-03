---
title: "Android Dynamic Code Execution"
url: "android-dynamic-code-execution"
---

### Using JADXecute plugin

The [JADXecute](https://github.com/LaurieWired/JADXecute) is a plugin for [JADX](https://github.com/skylot/jadx) that enhances its functionality by adding **Dynamic Code Execution** abilities to it. With JADXecute, it's possible to dynamically run Java code to modify or print components of the jadx-gui output. JADXecute is inspired by IDAPython to help and aims to assist Android Reverse Engineers in analyzing APKs more efficiently.

**Installation**

This code is based on the latest release of JADX version 1.4.7. It contains an additional plugin to enable dynamic Java coding using all of the standard Java libraries as well as the JADX libs and APIs. To install it JADXecute, simply [download latest release](https://github.com/LaurieWired/JADXecute/releases) with the embedded plugin (ie. asset with filename `jadx-gui-jadxecute-[version].zip`), and run as you normally would. Here is a quick guide:

1. Go to [JADXecute Releases](https://github.com/LaurieWired/JADXecute/releases) page
2. Download latest version zipfile named `jadx-gui-jadxecute-[version].zip`
3. Unzip the downloaded zipfile
4. Open Terminal and `cd` into unzipped directory (`cd ~/Downloads/jadx-gui-jadxecute-[version]`)
5. Start the `jadx-gui` using its' POSIX wrapper (`./bin/jadx-gui`)

**Usage**

Once JADX is open, select APK you wish to analyze. Then click on the *coffee cup* icon in the top left corner and click it. Upon clicking, the JADXecute dialog will appear providing template list you can pick from, or using the "Java Input" textarea to write a script.

Check out [Wiki](https://github.com/LaurieWired/JADXecute/wiki/Usage) for usage instructions and script examples. The official tutorial video is on [Youtube](https://youtu.be/g0r3C1iEeBg).

### Using ARTful Library

The [ARTful](https://github.com/LaurieWired/ARTful) is a native Android library for dynamically modifying the Android Runtime (ART) on Android 13/14. With this tool, it's possible to dynamically change the implementation of any static method within the Android application, or the Android Framework, to affect methods called from within the application.

For detailed installation, usage instructions, and script examples, visit the official [Wiki](https://github.com/LaurieWired/ARTful/wiki/Usage) page.
