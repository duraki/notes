---
title: "Exploring React Native Apps on Android"
url: "reactnative-on-android"
---

**Extracting APK from the Android Device**

Idnetify the desired package name from the `adb` instance by grepping the relevant app. name info:

```
$ adb shell pm list packages | grep [AppName]
# package:com.example.appname
```

Once you have package name, get the `path` corresponding to the application package:

```
$ adb shell pm path Extract com.example.appname
# package:/data/app/~~2GcSEtWOfJulAzZ9AlLk8Q==/com.example.appname-aknu0Dn8RjBhBvICee4Tlg==/base.apk
```

Use the full path name from above to pull the APK file from the Android device to the HostOS:

```
$ adb pull /data/app/~~2GcSEtWOfJulAzZ9AlLk8Q==/com.example.appname-aknu0Dn8RjBhBvICee4Tlg==/base.apk \
            $HOME/RevBox/Targets/Android/adb_pull/"
```

The APK file from the Android device will be stored in `$HOME/RevBox/Targets/Android/adb_pull` directory.

You can use `adb logcat` and fixate the matching patterns to show only ReactNative logs:

```
$ adb logcat "*:S ReactNative:V ReactNativeJS:V"
```

**Extracting loaded `*.so` modules from the APK**

Start by running JADXecute as explained in [Dynamic Code Execution for Android](/android-dynamic-code-execution) note. Once you have `jadx-gui` open, click on `File->Open Files...` and choose the extracted `*.apk` file we pulled earlier. Leave the JADX to fully analyze the APK file and once analyzed, click on the `Summary` in the file list paneview on the left.

The Summary tab should contain all native libraries loaded into APK per corresponding architecture, for example for `arm64-v8a` it shows:

```
Native libs
    Arch List: arm64-v8a, [...]             # shows all supported architectures
    Per arch count: arm64-v8a:20, [...]     # shows number of native libs (*.so) loaded per arch

    lib/arm64-v8a/libVisionCamera.so
    lib/arm64-v8a/libbarhopper_v3.so
    lib/arm64-v8a/libc++_shared.so
    lib/arm64-v8a/libconceal.so
    lib/arm64-v8a/libdatastore_shared_counter.so
    lib/arm64-v8a/libfbjni.so
    lib/arm64-v8a/libgvr.so
    lib/arm64-v8a/libhermes.so
    lib/arm64-v8a/libhermestooling.so
    lib/arm64-v8a/libimage_processing_util_jni.so
    lib/arm64-v8a/libimagepipeline.so
    lib/arm64-v8a/libjsi.so
    lib/arm64-v8a/libnative-filters.so
    lib/arm64-v8a/libnative-imagetranscoder.so
    lib/arm64-v8a/libpanorenderer.so
    lib/arm64-v8a/libreactnative.so
    lib/arm64-v8a/libreactnativemmkv.so
    lib/arm64-v8a/libreanimated.so
    lib/arm64-v8a/librnscreens.so
    lib/arm64-v8a/libworklets.so
```

Besides the list of loaded `*.so` (ie. *native libraries*) loaded with the application, this tab should also provide relevant information about decompiled source code. For an example, the APK I've pulled and analyzed in JADX shows the following:

```
Code sources

    Count: 5
    base.apk:DebugProbesKit.bin
    classes.dex
    classes2.dex
    classes3.dex
    classes4.dex
```

**React Native Reverse Engineering Tricks**

**1. Trick when analyzing '`index.[ios|android].bundle`' react-native asset**

The bundle file `index.ios.bundle` or `index.android.bundle` are React's Native way to store JavaScript code into a single file, which is visible upon decompilation of APK (or unzipping, in some cases) in the `assets/` directory.

The index bundle file is a compressed Javascript code file which is usually compiled with Hermes, and therefore is not in readable plaintext format. You first need to decompile it, which is doable using the following command:

```
$ python3 hermes-dec/hbc_decompiler.py /path/to/index.android.bundle > /tmp/index.android.bundle.decompiled.js
```

Once you have decompiled Javascript file, we can use this simple trick I found on [Callstack's Blog](https://www.callstack.com/blog/learn-once-hack-everywhere) to easily inspect, beautify and analyze this bundle. The trick is to create a new HTML file in the folder where our decompiled Javascript code is (ie. `/tmp/web.html`) and include the decompiled JS file in it:

```
$ echo "<script src='./index.android.bundle.decompiled.js'></script>" > /tmp/web.html
## $ open /tmp/web.html ~> View -> Developer -> Developer Tools (Chrome)
```

The above Terminal command writes a simple HTML file which uses `<script>` tag to load the decompiled JS code in its' HTML source page. Open this `web.html` file in Chrome/Firefox and then use "Developer Tools". The result is beautifed and readable decompiled code which you can further analyze against.

{{< imgcap title="Chrome DevTools - Analyzing Decompiled Javascript Code" src="/posts/android/reactnative_devtools_decompiled-bundle.png" >}}

{{< notice >}}
Tips & Tricks
{{</ notice >}}
{{< callout emoji="💡" text="Once you extract targeted React Native app and have Bundle Asset (`.bundle`) file in both original hermes-bytecode compiled format, and a decompiled Javascript version of it, create a new HTML file with single `<script>` tag. Set its' `src` value to point to location of the decompiled Javascript file and use Chrome DevTools to analyze it further." >}}

Detecting Hermes Version used in the React Native App is possible either by inspecting APK contents and looking for Hermes-specific files (ie. `index.android.hermes`, `index.android.bundle`), or if we already extracted asset Javascript code bundle, simply using `file` command:

```
$ file index.android.bundle
# index.android.bundle: Hermes JavaScript bytecode, version 94
```

The output indicates Hemes JavaScript v94 used. The version number (e.g., *Version 94*) is crucial because it signifies the specific version of the Hermes engine used to compile the bytecode. Each version of Hermes might have different features, optimisations, or bug fixes. Knowing the version can help in:

* **Choosing the Right Tools:** Some decompilation tools, like `hermes-dec` by *@P1sec*, must support specific Hermes versions to decompile the bytecode correctly. This tool might not support older versions, but for example, `hbctool` by *@bongtrop* supports versions 59, 62, 74, and 76.
* **Understanding Bytecode Changes:** Different versions of Hermes can introduce changes in the bytecode format, which can affect how you analyse and interpret the decompiled code.

**2. Sensitive Information Recon in react-native apps**

Always make sure to analyze all static files with-in decompiled APK files, such is:
    Checking `AndroidManifest.xml` - Reveals what SaaS app uses, app activities, services, deeplinks, API keys
    Checking `values/string.xml` - The app might hardcode IDs and Keys in this file
    Using `binwalk` against the React's Asset Bundle (ie. `binwalk -e index.android.bundle`)
    Using `grep` to search for interesting strings (ie. `grep -rnis 'apiKey' .`)
    Query all SQL Databases, Log Files, Text Files, XML Data Stores, Binary Data, Cookie, SD Card
    Temporary Created Files, File Monitoring

**3. Approaching The Hybrid Mobile Assessments**

Summary of the approach I take is something like this:
    MiTM on comm channels, remote loads/calls inspection, injection oopertunities in webapi's
    Inject a custom debugging library into the WebView
    Inspecting the DOM, looking for custom bridge objects or comm channels
    Inspecting JavaScript for bridge prototypes or comm channels
    Reviewing framework documentation for exposed default functionalities
    Reviewing native code for exposed functionality or vulnerable implementations
    Reviewing native code for weak protections (tokens, regex, inspection, implementation)

**4. Using logcat CLI to determine issues**

Always relay on [logcat](https://developer.android.com/studio/command-line/logcat) CLI when ever debugging Android apps. Connect the device via USB, or use the emulator of your choice and in Terminal:

```
$ adb logcat '*:E'      # log all errors from any/all *TAG(s) on device
```

**5. Hermes Utils to the Rescue**

Save yourself a lot of trouble with React Native blackbox penetration testing by relayin on [hbctool](https://github.com/bongtrop/hbctool), and other helpful OSS #offsec tools.

* [`hbctool`](https://github.com/bongtrop/hbctool) - Console utility for working with Hermes bytecode (disas)
* [`unwebpack-sourcemap`](https://github.com/rarecoil/unwebpack-sourcemap) - If you have bundle asset `*.map` for the compiled file
* [`hermes-dec`](https://github.com/P1sec/hermes-dec) - If bundle asset is exported as binary data, use this utility to convert Hermes bytecode
* [`fb/hermes`](https://github.com/facebook/hermes) - Hermes JS Engine alognside with its' utilities
* [`react-native-decompiler`](https://github.com/numandev1/react-native-decompiler) - A CLI for React Native JS decompilation
* [`hasmer`](https://github.com/lucasbaizer2/hasmer) - RevEng CLI Utility for Hermes Bytecode **[new]**

Using `hermes-dec` to decompile Hermes bytecode back to Javascript and other cheatsheet is below:

```
    # Disassemble Hermes bytecode from binary asset bundle
$ python3 hbc_disassembler.py /path/to/index.android.bundle disas-react
# [+] Disassembly output wrote to "disas-react"

    # Decompile Hermes bytecode from binary asset bundle to JavaScript
    # If decompiled JS code is obfuscated, @see https://github.com/ben-sb/obfuscator-io-deobfuscator
$ python3 hbc_decompiler.py /path/to/index.android.bundle decompiled-react.js
# [+] Decompiled output wrote to "disas-react"
```

**6. Understanding/Modifying Hermes Bytecode**

The Hermes JavaScript engine is customly built for React Native apps. The JavaScript source code is often compiled into the Hermes bytecode. Latest versions of React Native by default enable Hermes on all APK/IPA builds, as it results in improved start-up time, decreases memory usage, and produces smaller apps.

Thus, when decompiling and reversing React Native apps. that used Hermes during compilation, the code in `index.[platform].bundle` file will be converted into Hermes bytecode. Again, reference to tools mentioned above on how to disassemble and decompile `.bundle` files.

Currently, there is no way to convert disassembled Hermes bytecode to readable JavaScript code. We must [understand bytecode](https://lucasbaizer2.github.io/hasmer/hasm/instruction-docs/) in bits and pieces to modify the behaviour of a specific function and/or app component. Bytecode consists of bunch of constants and functions that make up the logic of the application.

Lets take example of some key elements in Hermes to make some sense.

- `Oper[1]: String(strNumber)`: This constant contains all strings, either added by the dev during development or it may contain strings of various third-party JavaScript libraries used in the app. Most of the time, this constant contains strings that we should look for during assessments.

{{< notice >}}
Helpful Tip
{{</ notice >}}
{{< callout emoji="💡" text="Always search from the bottom of the 'instructions.hasm' file to find strings that are added by developers during development." >}}

- `createElement:`: This string value refers to the JSX elements which is coded in React Native. Refer to the below image for side-by-side comparison of the JSX code snippet and it's final Hermes bytecode.

![](https://i0.wp.com/payatu.com/wp-content/uploads/2024/11/Screenshot-2024-11-05-140941.png?ssl=1)

- `LoadConstInt:`: This element stores all integer values created within the application. For example `LoadConstInt RegX:X, Imm32:1337` would indicate a constant integer value of `1337` defined in the app.

- `Hermes Relational Operators`: These instructions has different keywords for relational operators. Some of the imporant keywords and their meaning is described below.

| Keyword            | Operator | Meaning                      |
|--------------------|----------|------------------------------|
| `JEqual`          | `==`      | Equal to                     |
| `JNotEqual`       | `!=`      | Not equal to                 |
| `JLess`           | `<`       | Less than                    |
| `JGreater`        | `>`       | Greater than                 |
| `JLessEqual`      | `<=`      | Less than or equal to        |
| `JGreaterEqual`   | `>=`      | Greater than or equal to     |
| `JNotLessEqual`   | `!<=`     | Not less than or equal to    |
| `JNotGreaterEqual`| `!>=`     | Not greater than or equal to |
| `JEqualLong`      | `==`      | Equal to long data type      |
| `JNotEqualLong`   | `!=`      | Not equal to long data type  |
| `JStrictEqual`    | `===`     | Strict equal to              |
| `JStrictNotEqual` | `!==`     | Strict not equal to          |

- More on Hermes Bytecode: Sekai Team has [a nice CTF write-up](https://sekai.team/blog/insomni-hack-teaser-2022/herald) describing Hermes disassembly line by line, and [another one for same target](https://github.com/Pusty/writeups/tree/master/InsomnihackTeaser2022#herald). 

---

The below section explains how to find functions in Hermes disassembly and how to cross-reference valuable or known information.

{{< notice >}}
Helpful Tip
{{</ notice >}}
{{< callout emoji="💡" text="Find interesting functions in HASM using any string indicator, and then searching this cross-referencing string in the '.hasm' files. The `Oper[1]: String(XXX) 'SomeKeyword'` declaration should be visible in all functions that uses it, therefore copy the ID from `Function<>(ID)(...)` declaration and search for that ID in the '.hasm' file." >}}

{{< details "Find interesting functions in HASM (Expanded)" >}}
For example, lets take a look at the application's screenshot below:

![](https://i0.wp.com/payatu.com/wp-content/uploads/2024/11/Screenshot-2024-11-05-141825.png?w=322&ssl=1)

We can search with any keyword in the string shown in the screenshot, for example, lets search for 'Increase button' in the ".hasm" file:

![](https://i0.wp.com/payatu.com/wp-content/uploads/2024/11/Screenshot-2024-11-05-141918.png?w=801&ssl=1)

Once identified or found in the Hermes disassembled code, copy the ID of the function and search for this ID in the ".hasm" file again.

![](https://i0.wp.com/payatu.com/wp-content/uploads/2024/11/Screenshot-2024-11-05-142021.png?w=796&ssl=1)

This will result in the name of the function shown. For reference, here is a comparison of React Native JSX Code and its' compiled Hermes bytecode on the `onIncrement()` function.

![](https://i0.wp.com/payatu.com/wp-content/uploads/2024/11/Screenshot-2024-11-05-142454.png?w=795&ssl=1)

Using this method, we can therefore cross-reference any function with its properties. More details about Hermes bytecode can be found on [official website](https://hermesengine.dev), which also provides a great playground for it.
{{< /details >}}

---

The **Hermes**-bytecode **Modification** is explored in next section. This example is extracted from a CTF challenge which provides valid flag if the counter reaches `1337`. The thing is, if user taps on the "{{kbd}}+{{/kbd}}" icon, the counter is increased once, and then it throws the error that the button has already been tapped, meaning the app allows incrementing only *x1* step.

{{< details "Vulnerable CTF App (Expand Image)" >}}
![](https://i0.wp.com/payatu.com/wp-content/uploads/2024/11/Screenshot-2024-11-05-142732.png?w=300&ssl=1)
{{< /details >}}

{{< details "Vulnerable CTF App - Multiple Taps Error (Expand Image)" >}}
![](https://i0.wp.com/payatu.com/wp-content/uploads/2024/11/Screenshot-2024-11-05-142830.png?w=309&ssl=1)
{{< /details >}}

Therefore, inhere I will explain how to set the counter value to always contain `1337` directly. As always, decompile and unpack APK until we extract relevant `index.android.bundle` file, and then use `hbctool` to convert gibberish binary data to Hermes bytecode:

```
$ hbctool disasm index.android.bundle output
# [*] Disassemble 'index.android.bundle' to 'output' path
# [*] Hermes Bytecode [ Source Hash: sha256hash, HBC Version: 74 ]
# [*] Done
```

Open the "`instructions.hasm`" file from the `output/` directory. This file should contain all React Native application's JavaScript code in Hermes bytecode format.

Using the steps described above, we need to find the function that deals with the counter value incremental. We might search for keywords of the shown error alert, ie. searching keyword term "*Increase button has already been broken.*":

{{< details "Vulnerable CTF App - Search For Error Message (Expand Image)" >}}
![](https://i0.wp.com/payatu.com/wp-content/uploads/2024/11/Screenshot-2024-11-05-143849.png?w=654&ssl=1)
![](https://i0.wp.com/payatu.com/wp-content/uploads/2024/11/Screenshot-2024-11-05-144003.png?w=652&ssl=1)
{{< /details >}}

When the searched string has been found, take note of the `Function<>(ID)`. From the previous observation, the counter stops when user try to increase the counter value above `10`. Thus, the applicaton perform's a "*Hermes Relational Operators*" to verify whether the counter value exceeded that of intval `10`.

{{< details "Vulnerable CTF App - Relational Ops (Expand Image)" >}}
![](https://i0.wp.com/payatu.com/wp-content/uploads/2024/11/Screenshot-2024-11-05-144116.png?w=654&ssl=1)
{{< /details >}}

From the above screenshot, the `LoadConstUInt8` defines an integer value `10`. Using the `JNotEqual` relational operator checks if the register `Reg8:1` (which holds defined intval of `10`), equals that of `Reg8:2` which contains `counter` value.

Instead of increasing the counter's value, we can change the target value from `1337` to lets say `4`. For this, we need to find the relational operator in the same function which checks whether the counter value is greater than `1336` or equals to `1337`.

{{< details "Vulnerable CTF App - RelOps expecting the Counter value (Expand Image)" >}}
![](https://i0.wp.com/payatu.com/wp-content/uploads/2024/11/Screenshot-2024-11-05-144116.png?w=654&ssl=1)
{{< /details >}}

As shown above, a relational operation is identified that yields "*decrypt*" and alerts the valid flag if the counter value reaches `1336` or greater. Thus, it's possible to change the expected value from defined `1336`, to lets say `4`. This change will be made in `LoadConstInt` bytecode.

```
    # the opcode we need to modify
LoadConstInt            Reg8:1, Imm32:1336          # original expected value
    # modify/patch this as below 
LoadConstInt            Reg8:1, Imm32:4             # modified expected value
```

{{< details "Vulnerable CTF App - Patching expected Counter value (Expand Image)" >}}
![](https://i0.wp.com/payatu.com/wp-content/uploads/2024/11/Screenshot-2024-11-05-144334.png?w=651&ssl=1)
{{< /details >}}

Finally, save this file after making any changes to the file. The following step is required to reassemble the asset bundle file back to Hermes bytecode format:

```
$ hbctool asm output/ index.android.bundle
# [*] Assemble 'output' to 'index.android.bundle' path
# [*] Hermes Bytecode [ Source Hash: sha256hash, HBC Version: 74 ]
# [*] Done
```

Copy (ie. *overwrite*) original `assets/index.android.bundle` file from decompiled APK directory, with our newly created (assembled) Bytecode `index.android.bundle` file:

```
$ cp -R index.android.bundle  /path/to/decompiled_apk/assets/index.android.bundle
```

Use APKLab Workbench in VS Code (*explained in separate section below*) to re-compile final patched APK with automatic keystore signature. Push the modified APK to the device either via APKLab Workbench, or using `adb install` command:

```
# If not using APKLab Workbench
##      $ keystore -genkey -v -keystore ....
##      $ jarsigner -verbose -sigalg ....

$ adb install --force /path/to/modified.apk 
```

Open the app and increase the counter value by tapping the "{{kbd}}+{{/kbd}}" button 5 times, and Alert message will popup, showing the correct flag.

{{< details "Vulnerable CTF App - Flag Captured (Expand Image)" >}}
![](hhttps://i0.wp.com/payatu.com/wp-content/uploads/2024/11/Screenshot-2024-11-05-145259.png?w=282&ssl=1)
{{< /details >}}

Understanding and analyzing Hermes bytecode can be a headache. However, certain patterns in the bytecode help us understand the flow of the functions, methods, and constants. Most of the codes and references were taken from [online blogs](https://pilfer.github.io/mobile-reverse-engineering/react-native/reverse-engineering-and-instrumenting-react-native-apps/).

### Resources

* https://stackoverflow.com/questions/58747496/how-to-turn-on-development-bundling-in-react-native-for-android
* https://www.callstack.com/blog/secure-your-react-native-app
* https://www.callstack.com/blog/react-native-how-to-check-what-passes-through-your-bridge
* https://www.callstack.com/blog/code-splitting-in-react-native-applications
* https://www.callstack.com/blog/ssl-pinning-in-react-native-apps
* https://hackmd.io/@Wciv3q-xTFidMecq00GnhQ/BJZSRmNw2
* https://securityqueens.co.uk/android-attack-javascript-interfaces-and-webviews/
* https://labs.withsecure.com/publications/webview-addjavascriptinterface-remote-code-execution
* https://labs.withsecure.com/publications/samsung-s20-rce-via-samsung-galaxy-store-app
* https://labs.withsecure.com/publications/how-secure-is-your-android-keystore-authentication
* https://labs.withsecure.com/publications/putting-javascript-bridges-into-android-context
* https://labs.withsecure.com/publications/adventures-with-android-webviews
* https://securityqueens.co.uk/android-attack-reversing-react-native-applications/
* https://labs.cognisys.group/posts/How-to-Decompile-Hermes-React-Native-Binary/
* https://payatu.com/blog/understanding-modifying-hermes-bytecode/
* https://www.p1sec.com/blog/releasing-hermes-dec-an-open-source-disassembler-and-decompiler-for-the-react-native-hermes-bytecode
* https://pilfer.github.io/mobile-reverse-engineering/react-native/reverse-engineering-and-instrumenting-react-native-apps/
* https://lucasbaizer2.github.io/hasmer/hasm/instruction-docs/
* https://jscrambler.com/blog/securing-react-native-applications