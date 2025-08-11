+++
title = "duraki notes"
lastmod = 2022-04-29
type = "index"
+++

# <img style="height: 32px; vertical-align: middle; float: left; padding-right: 10px;" src="https://deviltux.thedev.id/notes/favicons/favicon_boxed.png"> About these notes

Hi! 👋 I'm [Halis Duraki](https://duraki.github.io) and these are my personal notes. I'm a passionate hacker, mostly interested in reverse engineering, 0day exploitation and web applications. Notes presented here will relate to topics I'm most expertus about.

I started using [Obsidian](https://obsidian.md/) a bit early in 2020. and continued graphing my knowledge since then. I wanted something more functional, as to offer me a practical snippet library for my TTP's, both online and as a backup of my dementia.

The notes are inspired by [others](#outro)[^1], and I'm very thankful for all the ideas. To simply put, I use this to note-take, graph, and quickly extract valuable data.

I sincerely hope these notes will help you build yourself, extend your views, and expand your possibilities. In any case, these notes were written for myself and by myself, so they might not reflect the wide public opinion, nor was that the case when I started collecting them.

You can start exploring from the [List of Topics](#list-of-topics-hahahugoshortcodes0hbhb), or see the [full list of notes](/posts). Besides, my {{< aref  href="works-for-me/" title="✨ works for me" >}} page is open for public.

<p style="display: contents;">The following link indicators are used for all <div class="indicator"><a class="internal-note-indicator"> Internal Notes<p>This is just an example of link indicators, clicking the link won't do anything.</p></a></div>, while links leading to <div class="indicator"><a class="external-resource-indicator">External Website/Resource<p>This is just an example of link indicators, clicking the link won't do anything.</p></a></div> are rendered as such.</p>

---

## List of Topics {{< sup_clean " ~" "#" >}}

### Automotive Cyber Security

* [Automotive Hacking](/automotive-hacking)
* [Ethernet in Vehicles](/ethernet-specifications)
* [CANFD Specifications](/canfd-specifications)
* [ECU Foundation](/ecu-foundations)
  * [ECU Programming](/ecu-programming)
    * [Developing a Training ECU](/ecu/diy-training-ecu)
  * [ECU Lookup Tables](/lookup-tables)
  * [ECU File Formats](/ecu-file-formats)
  * [ECU Calibration](/ecu-calibration)
  * [ECU Compromise](/how-to-compromise-ecu)
* [Vehicle Graybox Security Testing](/vehicle-graybox-security-testing)
* [Vehicle Hacking Environment](/vehicle-hacking-environment)
{{< hrsep >}}
* [BMW E34 Learning Material](/bmw-ag-e34-learning-materials) {{< sup_a "~ BMW" "#" >}}
    * [Diagnostic ADS Interface](/ads-interface)
        * [Keyword Protocols](/keyword-protocols) {{< sup_a " KW-71" "/kw71-protocol-description" >}}
    * [Electronic Signals](/electronic-signals)
    * [AC & DC Signals](/ac-and-dc-signals) {{< sup_a " (expand) ⏦" "/bmw-ag-e34-learning-materials" >}}
        * [AC Voltage Signals](/ac-voltage-signals)
        * [DC Voltage Signals](/dc-voltage-signals)
    * [Signals Table](/signals-table)
* [Honda Accord TypeS Learning Material](/honda-accord-types-learning-materials) {{< sup_a "~ Honda" "#" >}}
{{< hrsep >}}
* [Hardware Hacking](/hardware-hacking)
    * [Logic Analyzer](/hw/logic-analyzer)
      * [DSLogic Plus](/hw/dslogic-logic-analyzer)
    * [Hardware Engagement Fieldkit](/offsec-hardware-fieldkit)
    * [UART Interface](/uart-interface)
    * [JTAG Interface](/jtag-interface)
    * [EEPROM](/eeprom)

### Classical Penetration Testing

* [OSINT](/osint)
* [Source Code Auditing](/source-code-audit)
* [Web Pentest Oneliners](/web-penetration-testing-oneliners)
    * [Web Tricks and Tips](/web-tricks-and-tips)
* [Web Fuzzing](/web-fuzzing-techniques)
    * [Javascript Deobfuscation](/javascript-deobfuscation)
* [SQL Injection Payloads](/sqli-payloads)
* [Cloud Metadata](/cloud-metadata)
* [XSS Payloads](/xss-payloads)
* [Captcha Bypass](/captcha-bypass-tricks)
* [403 Bypass](/bypass-403-on-nginx)
* [Virtual Host Enumeration](/vhost-enumeration)
* [API Abuse](/classical-api-abuse)
* Checklists
    * [REST API Issue Library](/api-penetration-test-checklist)
    * [Web Issue Library](/web-application-penetration-test-checklist)
    * [PHP Source Code Analysis](/php-source-code-analysis)
        * [PHP Filesystem Functions](/php-filesystem-functions)
* Networking {{< sub "~ net" "#" >}}
    * [Basic Network Recon](/network-recon)
    * [Firewall Penetration Test](/firewall-engagements)
    * [Wifi Cracking via Aircrack](/wifi-cracking-via-aircrack)
    * [GSN3 Lab Environment](/network-lab)
    * [Metasploit Framework](/metasploit-framework)
    * [Server Anywhere](/server-anywhere)
    * [Netcat Tricks](/netcat-tricks)

### Reverse Engineering {{< sup_a "Toolset" "/posts/tools" >}}

* [Tricks and Tips](/reverse-engineering-tricks-and-tips)
* [Network Reverse Engineering](/network-reverse-engineering)
* [Byteman Cheatsheets](/byteman)
* [Byteman Scripts](/byteman-scripts)
* [Encryption and Cryptography](/encryption-and-cryptography)
* [Demangling C++ files using Frida](/c-plus-plus-demangler)
* [Objective-C Reverse Eng.](/objective-c-re) {{< sup_a "~ iOS/macOS" "#" >}}
    * [ObjC Class Decompilation](/objc-decompile)
* [Frida](/frida)
    * [Frida Class Generator](/generate-frida-class)
    * [Frida and r2 Interop](/r2frida)
    * [Medusa Framework](/medusa) [{{< sup_clean "iOS" >}}](/using-medusa-ios) [{{< sup_clean "/" >}}](/medusa) [{{< sup_clean "Android" >}}](/using-medusa-android)
* [radare2](/radare2)
* [MacOS Reverse Engineering](/macos-reverse-engineering)
    * [Filesystem Monitor](/macos-filesystem-monitoring)
      * [MacOS App. Preferences](/macos-application-preferences)
      * [MITM MacOS Preferences](/hook-macos-preferences)
      * [Apple URI Schemes](/apple-application-schemes-and-handlers)
    * [Ghidra](/ghidra-and-related)
      * [Ghidra Native ARM Binaries](/rebuilding-native-arm64-binaries)
      * [Ghidra Scripts & Plugins](/ghidra-scripts)
    * [MacOS Library Injection](/dyld-ios-injection)
    * [LLDB for MacOS](/lldb-for-macos)
    * [Hopper for MacOS](/pure-reverse-engineering#hopper-disassembler)
      * [ObjC Class Decompilation @macOS](/objc-decompile)
    * [MacOS MITM for TCP/UDP protocols](/macos-mitm-on-tcp/udp/)
    * macOS ARM/M1/M2 [{{< sup_clean "ARM/M1/M2 §" >}}](/macos-arm/m1/m2/)
      * [M1 LLDB Configuration](/configure-lldb-on-m1/m2/)
      * [Using Frida against MachO on ARM](/using-frida-against-macho-on-arm)
    * [Safari Dev Console](/safari-devconsole-internals)
    * [Metadata Extraction](/macos-metadata-extraction)
* [iOS Reverse Engineering](/ios-reverse-engineering)
    * [iOS Vulnerability Checklist](/ios-vulnerability-checklist)
    * [Frida & Objection Tutorial](/frida-objection-tutorial)
      * [Using Medusa for iOS](/using-medusa-ios)
    * [Pure Reverse Engineering](/pure-reverse-engineering)
    * [LLDB for iOS](/lldb-for-ios)
    * [iOS Library Injection](/dyld-ios-injection)
    * [Cycript](/cycript)
    * [Decrypt IPA from AppStore](/decrypt-ipa-from-appstore)
      * [Download IPA on MacOS](/download-ipa-on-macos)
    * [iOS Jailbreak Bypass](/jailbreak-bypass)
      * [Scrcpy for iOS](/scrcpy-for-ios)
      * [Tweaks](/tweaks-for-ios)
    * [iOS Static Analysis](/ios-static-analysis)
      * [ObjC Class Decompilatio @iOS](/objc-decompile)
    * [Frida Gadget injection on iOS](/frida-gadget-injection-on-ios)
    * [Advanced Frida Scripting for iOS](/ios-frida-scripting)
    * [Frida Tracing](/frida-trace-for-ios)
* [Android Reverse Engineering](/android-reverse-engineering)
    * [Find Secrets in APK Files](/apk-secrets)
    * [Android Vulnerability Checklist](/android-vulnerability-checklist)
    * [Running Android Apps on MacOS](/running-android-apps-on-macos)
      * [Android MITM for HTTP/S Protocols](/android-mitm-for-https-protocols)
      * [Scrcpy for Android](/scrcpy-for-android)
    * [Frida & Objection Tutorial](/frida-objection-tutorial-android)
      * [Using Medusa for Android](/using-medusa-android)
    * [Frida Gadget Injection on Android](/frida-gadget-injection)
    * Hybrid Android Apps {{< sup_clean " ~ React+Native/Xamarin/Flutter" "#" >}}
      * [Developing simple app in React Native](/reactnative-simple-app)
      * [Exploring React Native Apps on Android](/reactnative-on-android)
      * [Enabling DevMode in React Native Apps](/reactnative-patch-devmode)
      * [Using APKLab for Recompilation](/reactnative-patch-devmode-old)
    * [Android Dynamic Code Execution](/android-dynamic-code-execution)
    * [Android Recompilation](/android-recompilation)
* [Windows/WinNT Reverse Engineering](/windowsnt-reverse-engineering)
    * [Running WinNT Apps on MacOS](/running-winnt-apps-on-macos)
    * [WinDbg Cheatsheets](/windbg-cheatsheets)

### SCADA/ICS/OT Cybersecurity {{< sup_a "~ scada/ics" "/scada" >}}

* [SCADA](/scada)
  * [SCADA/ICS/OT Common Protocols](/scada/protocols)
  * [Identifying SCADA Networks](/scada/osint)

### Development & Design

**.files**

My `.dotfiles` are available [on my GitHub](https://github.com/duraki/dotfiles). At the time of writing, this repository is private due to confidential information. Please refer to {{< aref  href="works-for-me/" title="✨ works for me" >}} page to get details about my running environment.

In particular, I use:

* ssh, git, iterm, zsh, tmux
* macos, neovim+nvchad, karabiner, 60%mkb,
* lldb+voltron, amass, binwalk, nmap, burp

**blog**

Mockup for my minimal blog and notes publishing app called `art` (visible in [blog setup](/blog-setup)).

* todo: `vim.init`, `tmux`, `iterm`, `osx`
* todo: `gmmk + key remap`
* todo: `photos/ physical`
* [Bash](/bash-in-simple-words)

**btw**, I use GMMK 60% keyboard, [here are the default shortcuts](/gmmk-60-keyboard).

**design**

The details of UI/UX design environment is described in corresponding [Design](/design) notes, which includes details about my prefered design toolkits and plugins.


### Misc

* [Windows Notes](/windows-notes)
* [Linux Notes](/linux-notes) & [AndroidOS Notes](/android-notes)
* [MacOS Notes](/macos-notes) & [iPad Notes](/ipad-notes)
* [Computer Sync](/computer-sync)
* [Sys/DevOps Deployments & Notes](/sys/devops-notes) 🦄
* [Single-Board Computers (SBC)](/sbc-and-alternatives)
    * [Raspberry Pi Installation](/raspberry-pi-quick-guide)
    * [Enable SSH access via SD Card](/enable-ssh-on-raspbian-os)
    * [Building Kali Linux for Banana Pro](/building-kali-linux-for-banana-pro)
    * [Mounting SD Cards](/mounting-sd-cards)
    * [Mounting (ext4) partition in MacOS](/macos-notes)
* [Uplink (game) Modding](/modding-uplink-by-introversion)
* [How to write Notes](/how-to-write-notes)
* [Troubleshoot](/troubleshoot)
* [~ ideas](/~-ideas)

---

### How it works

It uses parameters (such is `[params.styles]`) via `config.toml`. It's possible to deploy dark version as well. Read for more in `*.css`. The theme used in `~notes` is rewritten from [my blog](https://duraki.github.io/).

### Outro

{{< details "Show #Outro" >}}
This website is provided free, for educational purposes. Knowledge shared here can be used for personal gain and experience. I do not condemn using TTPs explained here in your blackhat activities. The site is largely inspired by [Andy's](https://andymatuschak.org/) notes. Thanks to Justin and Jethro for their theme support and contribution. I would like to thank to the One, All-seeing, All-hearing. Many greetings to all my friends and family who supported me till the very end.

Peace out ✌️
{{< /details >}}

[^1]: Outro
