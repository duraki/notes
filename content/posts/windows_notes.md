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
* [Adding reaction GIFs to Windows Terminal](https://www.hanselman.com/blog/adding-reaction-gifs-for-your-build-system-and-the-windows-terminal)
* [Make Windows Terminal pretty with Powerline, Nerd Fonts, WSL, and oh-my-posh](https://www.hanselman.com/blog/how-to-make-a-pretty-prompt-in-windows-terminal-with-powerline-nerd-fonts-cascadia-code-wsl-and-ohmyposh)
* [Tweak Windows to open Command Prompt/Powershell directly from startmenu](https://www.hanselman.com/blog/how-to-make-command-prompt-powershell-or-any-shell-launch-from-the-start-menu-directly-into-windows-terminal)

### Tools

* [Yori](https://www.hanselman.com/blog/yori-the-quiet-little-cmd-replacement-that-you-need-to-install-now) - Handy little `cmd` replacement
* [QuickLook](https://www.microsoft.com/en-us/p/quicklook/9nv4bs3l1h4s?activetab=pivot:overviewtab&WT.mc_id=-blog-scottha) - A MacOS alternative for Windows Explorer, press `Space` to get a preview
* [Eartrumper](https://eartrumpet.app) - Volume control for Windows
* [Teracopy](https://www.codesector.com/teracopy) - Copy your files faster and more securely, also available for [MacOS](https://www.codesector.com/teracopy-for-mac) (~ $30 💰)
* [ShellExView](https://www.nirsoft.net/utils/shexview.html) - The ShellExView utility displays the details of shell extensions installed on your computer
* [Everything](https://www.voidtools.com) - Locate files and folders by name instantly
* [AltTabTer](https://www.ntwind.com/software/alttabter.html) - An alternative and better Alt-Tab dialog replacement (~ $20 💰)
* [PureText](https://stevemiller.net/puretext/) - Similar to PurePaste for MacOS
* [Carnac](http://code52.org/carnac/) - Show pressed key from keyboard on a screen

### Tutorials

* [How to SSH into WSL2/Bash on Windows 10 from an external machine](https://www.hanselman.com/blog/the-easy-way-how-to-ssh-into-bash-and-wsl2-on-windows-10-from-an-external-machine)
* [How to connect to a device over `serial` (COM) port on Windows 10 via WSL1 and Minicom](https://www.hanselman.com/blog/connect-to-a-device-over-serial-com-port-on-windows-10-with-wsl1-tty-devices-with-windows-terminal-and-minicom)
* [Windows 10 Dev Virtual Machines for Parallels, Virtualbox and VMWare](https://www.hanselman.com/blog/free-windows-10-development-virtual-machines-for-hyperv-parallels-virtualbox-and-vmware)
* [Create a Windows Terminal profile to automatically SSH into a Linux box](https://www.hanselman.com/blog/how-to-set-up-a-tab-profile-in-windows-terminal-to-automatically-ssh-into-a-linux-box)
* [How to SSH into a Windows 10 Machine from Linux/Windows/MacOS from anywhere](https://www.hanselman.com/blog/how-to-ssh-into-a-windows-10-machine-from-linux-or-windows-or-anywhere)
* [How to run Linux *GUI* apps on Windows 10 WSL/WSLg](https://www.hanselman.com/blog/how-to-run-linux-gui-apps-on-windows-10-with-wsl-and-wslg)

### Visual Studio Code *Extensions*

* [hexdump for VSCode](https://marketplace.visualstudio.com/items?itemName=slevesque.vscode-hexdump) - Hexdump Utility for `DATA` files
* [GitHistory for VSCode](https://marketplace.visualstudio.com/items?itemName=donjayamanne.githistory) - Show Git history timeline
* [CodeSnap](https://marketplace.visualstudio.com/items?itemName=adpyke.codesnap) - Take beautiful screenshots of your code in VS Code
* 