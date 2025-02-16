---
title: "Windows Notes"
---


### Hacking

When setting up Reverse Engineering workstation, use `retoolkit` for a start kit. You may [try Windows inside a Docker container](https://github.com/dockur/windows) if running virtualized environment. 

---

**Extract WiFi cleartextr password**

```
cls & echo. & for /f "tokens=4 delims=: " %a in ('netsh wlan show profiles ^| find "Profile "') do @echo off > nul & (netsh wlan show profiles name=%a key=clear | findstr "SSID Cipher Content" | find /v "Number" & echo.) & @echo on
```

**Active Directory**

Access Active Directory Domain Admin via Linux:

```
$ sudo apt-get realmd
$ realm join example.ba --user username
```

See also [Linux Notes](/linux-notes)

Resource:

* [AD Attack-Defense](https://github.com/infosecn1nja/AD-Attack-Defense)
* [Windows Data Hunting](https://thevivi.net/2018/05/23/a-data-hunting-overview/)

### Tweaking

* [macOS Cursors for WindowsNT](https://github.com/antiden/macOS-cursors-for-Windows)
* [Sort of 'QuickLook' for WindowsNT](https://github.com/QL-Win/QuickLook)
* [NanoZip - Modern 7-Zip alternative](https://github.com/M2Team/NanaZip)
* [Flow.Launcher](https://github.com/Flow-Launcher/Flow.Launcher) Windows "Spotlight-*inspired*" Laucnher
* [Achieve macOS look on Win11](https://github.com/Runixe786/Macified-Windows)