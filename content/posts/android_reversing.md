---
title: "Android Reverse Engineering"
---

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

### Toolset

* [jnitrace](https://github.com/ChiChou/vscode-frida) - trace JNI API in Android apps
* [ldpreloadhook](https://github.com/poliva/ldpreloadhook) - `open/close/ioctl/read/write/free` symbol hooker
* [dexinfo](https://github.com/poliva/dexinfo) - android dex file parser
* [dexterity](https://github.com/rchiossi/dexterity) - analyse and manipulate android dex files
* [apk-medit](https://github.com/aktsk/apk-medit) - memory search and patch tool for non-rooted android devices 
* [ApkUrlGrep](https://github.com/ndelphit/apkurlgrep) - extract endpoints from APK files 
* [dexcalibur](https://github.com/FrenchYeti/dexcalibur) - frida powered android RE tool
* [fridroid-unpacker](https://github.com/enovella/fridroid-unpacker) - defeat Java packers via Frida instrumentation

**References**

* [Android Nougat and Burp Proxy Configuration](https://blog.ropnop.com/configuring-burp-suite-with-android-nougat/)
* [Install custom CA on Android](https://awakened1712.github.io/hacking/hacking-install-ca-android/)
* [Generic Android Deobfuscator](https://github.com/CalebFenton/simplify#generic-android-deobfuscator)
* [Injecting Frida via Lief](https://lief-project.github.io/doc/stable/tutorials/09_frida_lief.html)
* [Frida on non-rooted device](https://jlajara.gitlab.io/mobile/2019/05/18/Frida-non-rooted.html)
* [InjectFridaGadget tool](https://github.com/darvincisec/InjectFridaGadget)
* [Proxying Android App traffic](https://blog.nviso.eu/2020/11/19/proxying-android-app-traffic-common-issues-checklist/)
