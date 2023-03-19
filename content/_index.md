+++
title = "duraki notes"
lastmod = 2022-04-29
type = "index"
+++

# About these notes

Hi! 👋 I'm [Halis Duraki](https://duraki.github.io) and these are my personal notes. I'm a passionate hacker, mostly interested in reverse engineering, 0day exploitation and web applications. Notes presented here will relate to topics I'm most expertus about.

I started using [Obsidian](https://obsidian.md/) a bit early in 2020. and continued graphing my knowledge since then. I wanted something more functional, as to offer me a practical snippet library for my TTP's, both online and as a backup of my dementia.

The notes are inspired by [others](#outro), and I'm very thankful for all the ideas. To simply put, I use this to note-take, graph, and quickly extract valuable data.

I sincerly hope these notes will help you build yourself, extend your views, and expand your possibilities. In any case, these notes were written for myself and by myself, so they might not reflect the wide public opinion, nor was that the case when I started collecting them.

You can start exploring from the [List of Topics](#list-of-topics), or see the [full list of notes](/posts).

---

## List of Topics

### Automotive Cyber Security

* [Automotive Hacking](/automotive-hacking)
* [Ethernet in Vehicles](/ethernet-specifications)
* [CANFD Specifications](/canfd-specifications)
* [ECU Foundation](/ecu-foundations)
* [ECU Calibration](/ecu-calibration)
* [ECU Compromise](/how-to-compromise-ecu)
* [Vehicle Graybox Security Testing](/vehicle-graybox-security-testing)
* [Vehicle Hacking Environment](/vehicle-hacking-environment)
* [BMW E34 Learning Material](/bmw-ag-e34-learning-materials)
    * [Electronic Signals](/electronic-signals)
    * [AC & DC Signals](/ac-and-dc-signals) (*[⏦︎ click here](/bmw-ag-e34-learning-materials) to expand*)
        * [AC Voltage Signals](/ac-voltage-signals)
        * [DC Voltage Signals](/dc-voltage-signals)
    * [Signals Table](/signals-table)

### Classical Penetration Testing

* [OSINT](/osint)
* [Web Pentest Oneliners](/web-penetration-testing-oneliners)
* [Web Fuzzing](/web-fuzzing-technqiues)
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
* Networking [§Network](/network)
    * [Basic Network Recon](/network-recon)
    * [Firewall Penetration Test](/firewall-engagements)
    * [Wifi Cracking via Aircrack](/wifi-cracking-via-aircrack)
    * [GSN3 Lab Environment](/network-lab)
    * [Metasploit Framework](/metasploit-framework)
    * [Server Anywhere](/server-anywhere)
    * [Netcat Tricks](/netcat-tricks)

### Reverse Engineering

* [Tricks and Tips](/reverse-engineering-tricks-and-tips)
* [Network Reverse Engineering](/network-reverse-engineering)
* [WinDbg Cheatsheets](/windbg-cheatsheets)
* [Byteman Cheatsheets](/byteman)
* [Byteman Scripts](/byteman-scripts)
* [Encryption and Cryptography](/encryption-and-cryptography)
* [Demangling C++ files using Frida](/c-plus-plus-demangler)
* [Frida](/frida)
    * [Frida Class Generator](/generate-frida-class)
    * [Frida and r2 Interop](/r2frida)
* [radare2](/radare2)
* [MacOS Reverse Engineering](/macos-reverse-engineering)
    * [Ghidra](/ghidra-and-related)
    * [MacOS Library Injection](/dyld-ios-injection)
    * [LLDB for MacOS](/lldb-for-macos)
    * [Hopper for MacOS](/pure-reverse-engineering#hopper-disassembler)
    * [MacOS MITM for TCP/UDP protocols](/macos-mitm-on-tcp/udp/)
* [MacOS M1 Reverse Engineering]()
    * [M1 LLDB Configuration](/configure-lldb-m1-m2)
    * [Using Frida against MachO on ARM](/using-frida-against-macho-on-arm)
* [iOS Reverse Engineering](/ios-reverse-engineering)
    * [Frida & Objection Tutorial](/frida-objection-tutorial#ios-tutorial)
    * [Pure Reverse Engineering](/pure-reverse-engineering)
    * [LLDB for iOS](/lldb-for-ios)
    * [iOS Library Injection](/dyld-ios-injection)
    * [Cycript](/cycript)
    * [Decrypt IPA from AppStore](/decrypt-ipa-from-appstore)
    * [iOS Jailbreak Bypass](/jailbreak-bypass)
    * [iOS Static Analysis](/ios-static-analysis)
    * [Frida Gadget injection on iOS](/frida-gadget-injection-on-ios)
    * [Advanced Frida Scripting for iOS](/ios-frida-scripting)
    * [Frida Tracing](/frida-trace-for-ios)
* [Android Reverse Engineering](/android-reverse-engineering)
    * [Frida & Objection Tutorial](/frida-objection-tutorial#android-tutorial)
    * [Frida Gadget Injection on Android](/frida-gadget-injection)
    * [Android Recompilation](/android-recompilation)
* [OPCRouter Research](/opcrouter-research)

### Development

**.files**

My `.dotfiles` are available [on my GitHub](https://github.com/duraki/dotfiles). At the time of writing, this repository is private due to confidential information.

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

### Misc

* [Windows Notes](/windows-notes)
* [Linux Notes](/linux-notes)
* [MacOS Notes](/macos-notes)
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
