---
title: "iOS Reverse Engineering"
---

**Using `class-dump`**

```
$ class-dump -S -s -H App -o /path/to/headers/App/
```

**Install offloaded `*IPA` files**

```
# requires: 
#   brew install libimobiledevice
#   brew install ideviceinstaller

$ ideviceinstaller -i <path_to_ipa_file>
```

**`frida-server` crashing on iPhone device**

If your `frida-server` is crashing on the iPhone test device, you can try to:

* Reset `frida-server` on test device (*requires gawk*):

```
# from your "iPhone:" device, such is via SSH tunnel

$ apt install gawk
$ FRIDA_PID=$(ps aux | grep frida-server | grep -v grep | awk '{print $2}'); kill -9 $FRIDA_PID; frida-server -l 0.0.0.0
```

* Inject Frida Gadget in the iOS app. and engage from non-jailbroken iDevice
* Upgrade to latest [Frida](https://frida.re) version

### Related iOS Notes~

* [Frida & Objection Tutorial](/frida-objection-tutorial#ios-tutorial)
* [LLDB](/lldb)
* [Pure Reverse Engineering](/pure-reverse-engineering)
* [Cycript](/cycript)
* [Decrypt IPA from AppStore](/decrypt-ipa-from-appstore)
* [iOS Jailbreak Bypass](/jailbreak-bypass)
* [iOS Static Analysis](/ios-static-analysis)

**References**

* [iOS CheatSheet](https://owasp.org/www-pdf-archive/OWASPIreland-Limerick-Day_20131031_iOSCheatSheet-OanaCornea.pdf)
* [Decrypting apps from AppStore](https://kov4l3nko.github.io/blog/2016-03-01-decrypting-apps-from-appstore/)
* [Reverse Engineering Tools](https://iphonedevwiki.net/index.php/Reverse_Engineering_Tools)
* [iOS Static Analysis](https://trelis24.github.io/2018/03/27/Pentesting-iOS-Static/)
