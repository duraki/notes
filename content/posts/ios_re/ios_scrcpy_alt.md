---
title: "Scrcpy for iOS"
---

- [Screen Mirroring (Free)](#screen-mirroring-free)
- [Screen Mirroring (Paid)](#screen-mirroring-paid)
- [Screen Mirroring \& Control (Paid)](#screen-mirroring--control-paid)

Although there is no real alternative to Android's [scrcpy](/scrcpy-for-android) utiltiy, alternatives for it do exist. Having the iPhone device shown on your macOS without having the ability to remotely control it is doable natively via QuickTime Player app., but having option to remotely control the device is rather difficult to implement, and as you've guessed, not free - ie. only one software supports it from my initial research (*at the time of writing*).

## Screen Mirroring (Free)

The macOS QuickTime app. has the ability to mirror any iPhone, connected via cable the Mac. To use this option, first, connect your iPhone device to your Host running macOS and open QuickTime Player. Once you have QuickTime app. running, use keyboard shortcut {{<kbd>}}⎇{{</kbd>}}+{{<kbd>}}⌘{{</kbd>}}+{{<kbd>}}N{{</kbd>}} or select {{<kbd>}}File -> New Movie Recording{{</kbd>}} via menu, and then:

1. Click on the "Recording Button" in QuickTime Player
2. Select your iPhone device in the *Screen* section
3. The QuickTime app. should display (ie. *mirror*) your iPhone screen

{{< imgcap title="QuickTime Player - Selecting Device in Screen Section" src="/posts/ios_re/images/quicktime_iphone_screenmirror.png" >}}

## Screen Mirroring (Paid)

Alternatively to the free version, there is also a paid solution via software called [Bezel](https://nonstrict.eu/bezel/) which allows you to mirror iPhone/iPad/AppleTV devices to your Mac. Using is simple as plugging-in your device (ie. *iPhone*) and the Bezel will instantly start, mirroring your device. The app. also provides a quick way to record screen in high-quality.

Other Bazel features:

* Supports all kind of devices: iPhone/iPad/iPod/VisionOS/AppleTV
* Matches the model & color of iPhone via [Bezel Helper](https://nonstrict.eu/bezel/helper/) utility
* Auto-rotate based on device orientation in real-time
* Detects device sleep and lock modes
* To see all Bezel features, [check official website](https://nonstrict.eu/bezel/#features)

The price of the Bezel MacOS License (*(x1) ~ single license*) is $29 *USD* with one-time purchase and 1 yr of updates. Not cheap for something that MacOS can already do natively.

## Screen Mirroring & Control (Paid)

![](/posts/ios_re/images/spacetime_left.png)

To have both the screen mirroring and the control of the real iOS device (iPhone), there is a software solution called [Wormhole](https://er.run) and its' cousine [Blackhole](https://er.run/blackhole). I practically haven't found any difference between these two software solutions, and they are from the same vendor.

One thing that seems to make difference between Wormhole and Blackhole is that former supports controlling and mirroring non-jailbroken devices via some bluetooth magic. The Blackhole version supports only Jailbroken devices but it must be jailbroken via Cydia Subtrate.

* **Wormhole**: Browse, mirror, and control iOS/Android Phone from WinNT/MacOS. Jailbreak **not required**
* **Blackhole**: Browse, mirror, and control iOS/Android Phone from WinNT/MacOS. Jailbreak **required**

The price of the Wormhole/Blackhole MacOS License (*(x1) ~ single license*) is $7.99 *USD* with one-time purchase and lifetime updates. Actually, quite cheap for what it does and provides to user. The latest versions of Wormhole/Blackhole provides a *3-days* free trial which is a good way to test the software and see if it works for your environment or workflow.

**Cydia Subtrate Jailbreak Support**

Once you install [Blackhole](https://er.run/blackhole) on your WinNT/MacOS, you will need to install a **Blackhole Plugin** which provides a supporting interface from the iPhone device to your Blackhole Desktop app. allowing you to mirror and control it.

To install *Blackhole Plugin*, open Cydia and add the following source repository: `https://cydia.er.run`. Once added, install the Blackhole Plugin. Connect your iPhone device to your MacOS via cable, and restart the Blackhole Desktop app.

**Non-Cydia Subtrate Jailbreak Support**

The Blackhole requires a jailbroken iPhone device, and a Blackhole Plugin which is supported by Cydia. Since Cydia is not readily available with the latest jailbreaks (ie. Palera1n), and the fact that these jailbreaks are [rootless](https://theapplewiki.com/wiki/Rootless), rather then them being based rootful; the Blackhole Cydia repostiory would not work if added to [Sileo](https://getsileo.app), [Zebra](https://getzbra.com) or other rootless package managers.

Searching around on the internet and Blackhole official Telegram channel, [I've found a way](https://drive.google.com/drive/folders/1YVcJqptm6cH0EdQVPrTAfcHvn9KQowKX) to have Blackhole Plugin installed on the [rootless](https://theapplewiki.com/wiki/Rootless) jailbreaks. Someone on Reddit manually updated all paths in the Blackhole Plugin to make it work on rootless jailbreaks.

To install Blackhole Plugin on rootless jailbreak for majority of implementation like Dopamine and Palera1n, download the file: 
* [`run.er.wormctrl_1.1.0_rootless_Ellekit`](/posts/ios_re/files/run.er.wormctrl_1.1.0_rootless_Ellekit.deb)

To install Blackhole Plguin on rootless Jailbreaks that doesn't support `ElleKit`, use the file:
* [`run.er.wormctrl_1.1.0_rootless_CydiaSubstrate_Substitute`](/posts/ios_re/files/run.er.wormctrl_1.1.0_rootless_CydiaSubstrate_Substitute.deb)

Depending on which `*.deb` file you downloaded, move it to the iPhone device using SFTP or similar tool (ie. iMazing). Here are the steps of moving the deb-file from MacOS host to an iPhone jailbroken via Palera1n:

```
$ iproxy 2222 22
$ ssh root@[iPhone-Device-IPv4] -p2222      # make sure you are able to connect via SSH to your device
~ root# apt install rsync                   # make sure to install rsync on your iPhone device
```

Now transfer the appropriate deb-file to your device:

```
# brew install rsync                        # make sure to install rsync on your HostOS/MacOS
$ rsync ~/Downloads/run.er.wormctrl_1.1.0_rootless_Ellekit.deb root@[iPhone-Device-IPv4]:/var/jb/var/root/
#
# ...
# sent 195,364 bytes  received 35 bytes  78,159.60 bytes/sec
# total size is 195,196  speedup is 1.00
```

Once the file has been `rsync`-ed to your device, open Filza and locate the above directory: `/var/jb/var/root` and find the `*.deb` file you just moved there. Then click on the deb-file and click the *Install* button in the top-right corner.

{{< imgcap title="Filza App - Installing Blackhole Plugin" src="/posts/ios_re/images/install_blackhole_plugin.jpg" >}}

Wait for the installation to complete and for the SpringBoard to reset. If you open Sileo now and go to "Packages" tab, you should see *Blackhole Plugin* installed.

{{< imgcap title="Filza App - Blackhole Plugin visible in Sileo" src="/posts/ios_re/images/blackhole_plugin_installed.jpg" >}}

---

{{< notice >}}
Jailbreaks without ElleKit
{{</ notice >}}
{{< callout emoji="💡" text="For rootless Jailbreaks that doesn't support ElleKit, the process of moving and installing the deb-file is same as described above, but instead of using the Rootless ElleKit *.deb, you shouold opt-out for the `*_CydiaSubstrate_Subtitute` deb." >}}

{{< notice >}}
Important Errata
{{</ notice >}}
{{< callout emoji="✅" text="If any of these tweaks (both Cydia Substitute, or the ElleKit version) are not working properly, or are causing crashing and SpringBoard issues, consider installing legacy `arm64e` support via your package manager. Only install this if you need it due to aftermentioned issues. To install it, open Sileo or your jailbreak provided package manager, and search for 'Legacy arm64e Support' to install it. Check <a target='_blank' href='/posts/ios_re/images/install_legacy_arm64e_support.jpg'>this image</a> on how-to." >}}

Once you have the Blackhole Plugin installed, connect your iPhone device to your MacOS via cable, and restart the Blackhole Desktop app. You should now be able to control the iPhone device from your MacOS via Blackhole.
