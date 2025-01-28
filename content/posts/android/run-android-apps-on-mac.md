---
title: Running Android Apps on MacOS
---

There are multiple ways to run Android applications on MacOS. Some of tested methods are outlined below, while others are presented by Laurie's [Android Emulators for RE](https://github.com/LaurieWired/android_emulators_for_reverse_engineers) notes on her GitHub, albeit seems a bit old.

## Running Android apps via MuMuPlayer Pro

* Download MuMuPlayer Pro from [Official Website](https://www.mumuplayer.com/mac/)
* Install MuMuPlayer Pro using downloaded `*dmg` file
* Open MuMuPlayer Pro and start the Android Device
  - You may need to login to MuMuPlayer Pro account (you can create a free 7-days account)

{{< imgcap title="MuMuPlayer Pro - Welcome Screen" src="/posts/android/mumu_1.png" >}}

* Inside the AndroidOS Screen you can either:
  - Install `*apk` file via MuMuPlayer menuber via "Tools => Install APK", or by drag-dropping apk
  - Download the app. via Google Playstore within MuMuPlayer Android Device Screen

{{< imgcap title="MuMuPlayer Pro - Android Device Screen" src="/posts/android/mumu_2.png" >}}

* To get Android Device details or to Export Logs
  - Click on the "Help" in menubar, then "Show Android Device Information"
  - In "Android Device Information" window, click "Export Log" button

{{< imgcap title="MuMuPlayer Pro - Device Information - Export Log" src="/posts/android/mumu_3.png" >}}

*Games and applications not compatible with MuMuPlayer Pro:* Call of Duty®: Mobile, Call of Duty®: Warzone™ Mobile, GODDESS OF VICTORY: NIKKE, KartRider: Drift, Warcraft Rumble, NIGHT CROWS, DOFUS Touch: A WAKFU Prequel, Fortnite, Shopee Live.

**Debugging Android Apps via MuMuPlayer**

Developers can now use Android Studio and MuMuPlayer Pro to debug applications, using the steps below:

1. Find the IPv4 address of the device running MuMuPlayer Pro
  - Open "Settings => Network" on the MacOS Host
  - Click "Advanced..." on the current Network selection, and click "TCP/IP" tab
  - Check the IP address under IPv4 Address, for example: `192.168.0.117`
2. Start the Android Device from MuMuPlayer Pro
  - Click "Tools" on the top menubar
  - Click "Open ADB (xxxxx)" in the "Tools" top menubar
  - The "xxxxx" is an ADB Terminal IP number (ie. `26624`)
3. Using iTerm execute the following commands
  - `adb kill-server`
  - `adb connect 192.168.0.117:26624`, replacing the IPv4/Port
4. Then you can select this `Android Device` in Android Studio Debug Interface, [see this image](https://r.res.easebar.com/pic/20240814/5f6dd2d3-6976-456f-950d-279edc87b78e.png)
  - Click on the "Build and Run" to install the debugging APK to the Android Device
  - Click on the "Attach" button to start debugging the app

**Install Certificates for MITM via MuMuPlayer**

You can install Custom Certificates and execute MITM (Packet Capture) on MuMuPlayer Pro, using the steps below;:

1. Download the certificate from the packet capturing software
  - For *Charles*: Open Charles, click on the menubar "Help => SSL Proxying => Save Charles Root Certificate ..."
  - For *Burp*: Open Burp, visit "http://burp" from integrated Burp Chromium Browser, and click "CA Certificate"
2. Start the Android Device from MuMuPlayer Pro
  - Open "Settings Center" from the top menubar, click on "Data" tab
  - Set "System Disk Mode" to *Writeable* and restart the Android Device in MuMuPlayer Pro
3. Click on the top menubar again, select "Tools => Open ADB"
4. Execute the following commands in adb shell term:
  - `exit` - popup from adb shell to MacOS host tty
  - `cd /Applications/MuMuPlayer.app/Contents/MacOS/MuMuPlayerPro.app/Contents/MacOS/tools/`
  - `openssl x509 -subject_hash_old -in /tmp/<your-ssl-proxying-certificate.pem>` - changing the path to `cert.pem`
    - the above command output result's first line is similar to: `af06d509`, [see this image](https://r.res.easebar.com/pic/20240404/21ef8ad8-94d4-41b5-bd60-9b74d76be62b.png)
  - Rename the certificate file from `/tmp/<your-ssl-proxying-certificate.pem>` to `/tmp/af06d509.0` - replacing w/ actual names
5. Use ADB to put the certificates into the system directory
  - Using iTerm cd in this dir: `cd /Applications/MuMuPlayer.app/Contents/MacOS/MuMuEmulator.app/Contents/MacOS/tools/`
  - Use commands:
    - `./adb` - note that root will prompt for superuser access in the emulator, check the allow options
    - `./adb push /tmp/af06d509.0 /system/etc/security/cacerts/` - copy the local cert to cacerts dir in device
    - `./adb shell "chmod 664 /system/etc/security/cacerts/af06d509.0"` - change cert perms in device
6. Configure your Packet Capture software to allow SSL Proxying from devices in the same network, as usual

### References

* [Transfer files via MuMuPlayer Pro](https://www.mumuplayer.com/mac/tutorials/transfer-files.html)
* [Enable Graphics Enhancement in MuMuPlayer Pro](https://www.mumuplayer.com/mac/tutorials/graphics-enhancement.html)
