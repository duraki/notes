---
title: "iOS Reverse Engineering"
---

**Restart SpringBoard if iPhone crashed**

```
$ killall SpringBoard
$ killall -SIGSEGV SpringBoard ^ 	// Safe Mode
```

**Print iOS Logs from Terminal**

```
$ tail -f /var/log/syslog
```

**Using `class-dump`, or `dsdump`**

```
$ class-dump -S -s -H App -o /path/to/headers/App/ 		// old way
$ dsdump App 	// new way
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


**Common iOS RE tools**

... commonly for *debugging*

```
$ brew install lldb
```

... commonly for *hooking*

* Cydia Substrate
* Theos

... via *Cydia and `apt-get*` (non-jailed)

```
Cydia:
	- OpenSSH, OpenSSL
	- tcpdump # https://mcapollo.github.io/Public/
	- python, pip # https://mcapollo.github.io/Public/
	- AppSync # https://cydia.akemi.ai/?page/net.angelxwind.appsyncunified
	- Cycript # https://cydia.saurik.com/package/cycript/
	- Apple File Conduit # https://cydia.saurik.com/package/com.saurik.afc2d/
	- syslog # https://cydia.saurik.com/package/syslogd/
apt-get
	- adv-cmds (finger, fingerd, lsvfs, last, md, ps)
	- file-cmds (chflags, compress, ipcrm, ipcs, pax)
	- basic-cmds (msg, uudecode, uuencode, write)
	- shell-cmds (killall, mktemp, renice, time, which)
	- system-cmds (iostat, login, passwd, sync, sysctl)
	- diskdev-cmds (mount, quota, fsck, fstyp, fdisk, tunefs)
	- network (arp, ifconfig, netstat, route, traceroute)
	- syslog (syslogon, syslogoff); /var/log/syslog
	- wget, ncdu, lsof, file, less
	- gdb (ar, nm, objdump, ranlib, strip, addr2line, gdb, objdump)
``` 

### Related iOS Notes~

* [Frida & Objection Tutorial](/frida-objection-tutorial#ios-tutorial)
* [LLDB](/lldb)
* [Pure Reverse Engineering](/pure-reverse-engineering)
* [Cycript](/cycript)
* [Decrypt IPA from AppStore](/decrypt-ipa-from-appstore)
* [iOS Jailbreak Bypass](/jailbreak-bypass)
* [iOS Static Analysis](/ios-static-analysis)

**References**

* [iOS Pentesting Checklist](https://book.hacktricks.xyz/mobile-pentesting/ios-pentesting-checklist)
* [iOS WebViews Debugging](https://book.hacktricks.xyz/mobile-pentesting/ios-pentesting/ios-webviews)
* [iOS CheatSheet](https://owasp.org/www-pdf-archive/OWASPIreland-Limerick-Day_20131031_iOSCheatSheet-OanaCornea.pdf)
* [Decrypting apps from AppStore](https://kov4l3nko.github.io/blog/2016-03-01-decrypting-apps-from-appstore/)
* [Reverse Engineering Tools](https://iphonedevwiki.net/index.php/Reverse_Engineering_Tools)
* [iOS Static Analysis](https://trelis24.github.io/2018/03/27/Pentesting-iOS-Static/)
