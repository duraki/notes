---
title: "Android Reverse Engineering"
---

### Android Shell Commands

**Activities**

Launch an activity with parameter:

```
adb shell am start -a android.intent.action.DIAL -d "tel:*%00000%00"
```

Launch an activity from specific application / package:

```
adb shell am start-activity com.example.appname/com.example.appname.MainActivity
```

Launch an activity and wait for debugger to attach:

```
adb shell am start -D -S -n com.example.appname/MainActivity
```

Launch Home:

```
adb shell am start -a android.intent.action.MAIN -c android.intent.category.HOME
```

Launch specific intent:

```
adb shell am start -a android.intent.action.VIEW -d "dsec://open"
```

**Applications & Packages**

List only third-party packages (ie. installed applications):

```
adb shell pm list packages -3
```

**Process and FileSystem**

List all processes:

```
adb shell ps-A
```

Kill a process or application:

```
adb shell pm disable AppName    # rooted devices only, this kills the app
adb shell pm enable AppName     # rooted devices only, this re-enables the app
```

Retrieve several files:

```
adb shell 'ls sdcard/gps*.trace' | tr -d '\r' | xargs -n1 adb pull
```

**Logcat**

Filter the logs by tag:

```
adb logcat -s [TAGNNAME]
```

Filter the logs by priority (ie. *warning* and above):

```
adb logcat "*:W"
```

**SMS Commands**

Send an SMS from device:

```
adb emu sms send "1234" "hello and hi"  # adb emu sms send [PHONE] [MSG]
```

**General Commands**

Get the **AndroidID** of the device:

```
adb shell settings get secure android_id
```

Dump various system information:

```
adb shell dumpsys iphonesubinfo
adb shell dumpsys cpuinfo
adb shell dumpsys notifications
```

Get current window:

```
adb shell dumpsys window windows | grep 'mCurrentFocus'
```

Get various classes:

```
adb shell dumpsys package | grep -i [PACKAGE_NAME]
```

Get various Android Properties:

```
adb shell getprop ro.build.version.release  # Version of AndroidOS
adb shell getprop ro.build.version.sdk      # AndroidOS API Level
```

**Device Admin**

Launch Device Admin screen:

```
adb shell am start -s "com.android.settings/.Settings\$DeviceAdminSettingsActivity"
```

Remove device admin rights:

```
adb shell dpm remove-active-admin [PACKAGE_NAME]/deviceadminreceivername
    #       OR
adb shell pm disable-user [PACKAGE_NAME]
adb uninstall [PACKAGE_NAME]
```

Bypass `INSTALL_FAILED_VERIFICATION_FAILURE` error when installing APK:

```
adb shell settings put global verifier_verify_adb_installs 0
# ...
# adb install ExampleApp.apk
```

Enable Accessibility Services:

```
adb  shell settings put secure enabled_accessibility_services com.example.AppName/com.example.AppName.MyAccessibilityService:com.example.AnotherApp/com.example.AnotherApp.MyAccessibilityService
```

**Redirections**

```
adb forward --remove-all
adb reverse --list
```

**Boot/Writeable System**

Disable secure boot:

```
adb shell avbctl disable-verification
adb reboot
``` 

Mount `/system` as writeable:

```
adb root
adb remount
```

### Installing Frida on Android Device/Emu

To install the correct version of the Frida (ie. `frida-server` component) on the phone device or emulator, we need to know the processor version. Either plug the phone into PC, or start the Android emulator as described in [Running Android Apps on MacOS](/running-android-apps-on-macos).

Install Frida on your Host, for example using `pip` on GNU/Linux:

```
$ sudo apt install python3-pip
$ sudo pip install frida-tools
```

Check the version of Frida we have installed on our HostOS:

```
$ frida --version
# 16.4.2
```

Then use the following command to get the platform (architecture) version of the device/emulator:

```
$ adb shell getprop ro.product.cpu.abi
# arm64-v8a
```

Now we can download `frida-server` corresponding to our Frida version and the arhitecture we are targeting, like so:

```
$ open https://github.com/frida/frida/releases/tag/$(frida --version)
```

This will open the default Web Browser to location of the Frida GitHub Release page of the HostOS version. Since our Frida version is `16.4.2` on the HostOS, and the processor version of the device is `arm64-v8a`, we need to find it in the "Assets" of that version release. Therefore, we would download the following asset from Frida release:

* `frida-server-16.4.2-android-arm64.xz`

To download this file via Terminal, you can use the following:

```
$ wget https://github.com/frida/frida/releases/download/16.4.2/frida-server-16.4.2-android-arm64.xz
$ xz -d frida-server-16.4.2-android-arm64.xz
```

Lastly, push the extracted binary to the device using the `adb` to the directory: `/data/local/tmp` or similar:

```
$ adb push frida-server-16.4.2-android-arm64 /data/local/tmp
# frida-server-16.4.2-android-arm64: 1 file pushed, 0 skipped. 205.0 MB/s (56466808 bytes in 0.263s)
```

Finally, we need to start `frida-server` on the device using the following:

```
$ adb shell
$ su
$ chmod +x /data/local/tmp/frida-server-16.4.2-android-arm64
$ /data/local/tmp/frida-server-16.4.2-android-arm64 &
```

Thats it, the `frida-server` should now be running on your rooted and emulated device. To test it, try the following from your HostOS:

```
$ adb devices
# List of devices attached
# 127.0.0.1:26624	device

$ frida-ps -D 127.0.0.1:26624 -a
PID   Name               Identifier
----  -----------------  -----------------------
4103  Browser            com.android.browser
4745  Files              com.android.documentsui
4339  Settings           com.android.settings
xxxx  ...                ...
```

### Decompilation & Debugging

Use the [JADX](https://github.com/skylot/jadx) and Laurie's [JADXecute](https://github.com/LaurieWired/JADXecute) plugin that enhances JADX by adding **Dynamic Code Execution** abilities. The JADXecute allows you to dynamically run Java code or modify/investigate components of the `jadx-gui` output.

### Burp Proxy Setup

If using **Android 7** or above, you need to export Burp CA Certificate from `Proxy → Options`, and selecting `Import/Export CA certificate`. Android wants the certificate to be in **PEM format**. The filename has to be equal to the `subject_hash_old` value appended with `.0`.

**Note** - if you are using OpenSSL < 1.0, you need to use `subject_hash` instead of `subject_hash_old`. 

Using `openssl` is recommended way to convert DER to PEM format. Dump the `subject_hash_old` and rename the file as explained above.

```
$ openssl x509 -inform DER -in cacert.der -out cacert.pem
$ openssl x509 -inform PEM -subject_hash_old -in cacert.pem |head -1
$ mv cacert.pem <hash>.0
```

Push the certificate onto Android device by using `adb` or `ssh`:

```
# => move cert to the device
$ adb push <hash>.0 /data/local/tmp

# => on android device:
$ adb shell
% su
% mount -o rw,remount /system 
% mv /data/local/tmp/<hash>.0 /system/etc/security/cacerts/
% chown root:root /system/etc/security/cacerts/<hash>.0
% chmod 644 /system/etc/security/cacerts/<hash>.0
% reboot
```

### Using Logcat on Android

To use built-in `logcat`, append the following:

```
$ adb shell 'logcat --pid=$(pidof -s x.xxx.xxx.xxxxx.xx)'
```

We can use a simple oneliner to specify `logcat` application PID:

```
$ adb shell list packages | grep "<app_name>"               # => com.example.appname
$ adb logcat --pid=$(adb shell pidof -s <app_bundle_id>)    # => where <app_bundle_id> is com.example.appname
```

To output logged lines in color via `logcat`, use the following command:

```
$ adb logcat --pid=$(adb shell pidof -s com.example.appname) dalvikvm DEBUG -v color
```

Read more on `logcat` on [official documentation](https://developer.android.com/tools/logcat) and relevant pages.

Alternatively, use [lnav](https://lnav.org), which is a logfile navigator/viewer, installable on MacOS using:

```
$ brew install lnav
```

Once installed, prepare `logcat` file description for it using the following command:

```
$ mkdir -p ~/.lnav/formats/installed/
$ wget "https://github.com/phoenixuprising/lnav-android-scheme/raw/refs/heads/main/android-logcat.json" -O $HOME/.lnav/formats/installed/android-logcat.json
```

Then use `lnav` combined with `adb logcat` command to provide application logs:

```
$ lnav -e "adb logcat --pid=$(adb shell pidof -s com.example.appname)"
```

Read more on `lnav` on [official documentation](https://docs.lnav.org/en/latest/intro.html) and relevant pages, as well as [official website](https://lnav.org).

Other solutions: [pidcat](https://github.com/JakeWharton/pidcat)

### Analyze and Find Stored App. Information

To find a specific string or key in the application's data, use:

```
$ adb shell
$ find /data/app -type f -exec grep --color -Hsiran "<FIND_THIS_STRING>" {} \;
```

To show all files stored on the device by the application use:

```
$ adb shell
$ find /storage/ -maxdepth 7 -exec ls -dl \{\} \;                   # search in /storage/ path
$ find /storage/sdcard0/Android/ -maxdepth 7 -exec ls -dl \{\} \;   # search in /storage/sdcard0/Android/ path
```

### Using the ADB tools

Reference to [Android Developer's CLI](https://developer.android.com/studio/command-line/adb?hl=es-419) documentation for more in-depth details.

```
$ adb connect [IP]:[PORT]/ID                    # connect to server
$ adb devices                                   # list devices
$ adb shell                                     # enter into device tty shell
$ adb push                                      # transfer file from local system to android device
$ adb install                                   # install apk on device
$ adb shell pm list packages                    # list all installed packages
$ adb shell pm path com.example.package.name    # show installation path of the given package
$ adb shell settings get secure android_id      # get the devices Android ID
$ adb shell sqlite3 /data/data/com.android.providers.settings/databases/settings.db "select value from secure where name = 'android_id'" # get the devices Android ID via database
```

### Toolset

* [jnitrace](https://github.com/ChiChou/vscode-frida) - trace JNI API in Android apps
* [ldpreloadhook](https://github.com/poliva/ldpreloadhook) - `open/close/ioctl/read/write/free` symbol hooker
* [dexinfo](https://github.com/poliva/dexinfo) - android dex file parser
* [dexterity](https://github.com/rchiossi/dexterity) - analyse and manipulate android dex files
* [apk-medit](https://github.com/aktsk/apk-medit) - memory search and patch tool for non-rooted android devices 
* [ApkUrlGrep](https://github.com/ndelphit/apkurlgrep) - extract endpoints from APK files 
* [dexcalibur](https://github.com/FrenchYeti/dexcalibur) - frida powered android RE tool
* [fridroid-unpacker](https://github.com/enovella/fridroid-unpacker) - defeat Java packers via Frida instrumentation

**Android Modules**

If you look for rooted Android modules, there are few of them that can save your time:

* [MagiskTrustUserCert](https://github.com/NVISOsecurity/MagiskTrustUserCerts) - This Magisk module allows adding System CA on modern version of Androids (*where it's not allowed*)
* [WebViewDebugHook](https://github.com/feix760/WebViewDebugHook) - This LSposed hook mod allows to look WebView of any app *from the inside*
* [XIntent](https://github.com/2Y2s1mple/xintent) - This mod allows us to see how the system works with intents exchanged between apps and components

**References**

* [Android Nougat and Burp Proxy Configuration](https://blog.ropnop.com/configuring-burp-suite-with-android-nougat/)
* [Install custom CA on Android](https://awakened1712.github.io/hacking/hacking-install-ca-android/)
* [Generic Android Deobfuscator](https://github.com/CalebFenton/simplify#generic-android-deobfuscator)
* [Injecting Frida via Lief](https://lief-project.github.io/doc/stable/tutorials/09_frida_lief.html)
* [Frida on non-rooted device](https://jlajara.gitlab.io/mobile/2019/05/18/Frida-non-rooted.html)
* [InjectFridaGadget tool](https://github.com/darvincisec/InjectFridaGadget)
* [Proxying Android App traffic](https://blog.nviso.eu/2020/11/19/proxying-android-app-traffic-common-issues-checklist/)
* [Awesome Android Security](https://github.com/ashishb/android-security-awesome)
* [Android Application Reversing 101](https://www.evilsocket.net/2017/04/27/Android-Applications-Reversing-101/)
* https://b4y.dev/posts/android-extract-backup/