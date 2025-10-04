---
title: "MacOS Notes"
---

Reference to a [macOS Tweak](/macos-tweaks) note if you want to check how I tweak my system environment based on details and workflow as described in my [Works for Me](https://deviltux.thedev.id/notes/works-for-me/) (ie. `/uses`) page. For other macOS configuration settings and relevant details, unrelated to my typical hacking notes, please take a look below.

Additonally, take a look at [this macOS command-line index](https://git.herrbischoff.com/awesome-macos-command-line/about/) which contains a lot of useful resources (there is also [cli-app-index](https://git.herrbischoff.com/awesome-command-line-apps/about/) mostly __*nix__ related).

**Use Windows SMB Share as a Time Machine Backup**

I have a highly modded "Thinkpad T430" with a lot of storage available on disposal. It has "*Microsoft Windows 10*" installed as main bootable OS, for various tasks and needs that I need on Windows environments (ie. automotive software, security engagements on Desktop app. clients, etc.). Since I'm daily driving my Apple Mac M1 (*that only has 512GB* of storage), I wanted to use this Thinkpad T430 laptop as my time machine backup location. Steps to do this are described below, originally found on [this article](https://www.makeuseof.com/tag/turn-nas-windows-share-time-machine-backup/), also check [Apple Website - How to back up your Mac](https://support.apple.com/en-us/102307):

1. In Windows 10, right-click on the HDD in File Explorer, and select "Properties"
2. Go to the "Sharing" tab, click "Advanced Sharing", and check "Share this folder"
   - Set the "Share Name" in the popup window, click "Add", then click "Apply" -> "OK"
   - In the "Sharing" tab, you should now see `\\[hostname]\[share_name]` as a *Network Path* of the Share
3. In MacOS, open Finder, then use `CMD+K` shortcut to connect to server
4. Enter the `SMB` path of your Windows 10, alongside its' IPv4, ie: `smb://192.168.1.x` and click "Connect"
   - Hint: Set the fixed IPv4 for your Windows 10 from Control Panel, so you can avoid DHCP IPv4 renewals
   - Once connected, the SMB location should be visible in the Finder's sidebar
   - Right-click on the SMB in the Finder's sidebar and go into corresponding "Share Name"
   - Create a new directory in this Windows Share, for example "`MACOS_BACKUP`" (can be done either from Windows 10, or from your MacOS)
   - Open this created directory from MacOS, then right click on path location of the Finder, and select `Copy 'MACOS_BACKUP' as Pathname`
   - The copied pathname should look something like: `/Volumes/SHARENAME/MACOS_BACKUP`
5. Open Terminal in MacOS and: 
   - Type `cd` to enter directory: `cd /Volumes/SHARENAME/MACOS_BACKUP` (paste the copied path of the mounted share folder)
   - Create a Time Machine disk in that folder using: `hdiutil create -size 512g -type SPARSEBUNDLE -fs "HFS+J" TimeMachine.sparsebundle`
     - Replace `512G` with your default Mac storage, since I have M1 w/ 512GB thats what I've set it to
     - The "`HFS+J`" flag indicates that this TimeMachine disk will be created using "MacOS Journaled (Non-encrypted)" disk type
     - Optionally, you may replace the name of the disk image filename with something else instead of `TimeMachine.sparsebundle`
     - Once the `hdiutil` command output that the creation is completed (`created: /Volumes/.../TimeMachine.sparsebundle`), mount this `*.sparsebundle` from Finder by double-clicking it
     - Optionally, rename the mounted disk by right-clicking on it from Finder sidebar, then "Rename", and set it to for example "`TimeMachineCapsule`"
6. Tell Time Machine to use this virtual drive for backups using Terminal:
    - Use `tmuitl` command: `sudo tmutil setdestination /Volumes/TimeMachineCapsule.sparsebundle`
    - Use the actual path of your mounted `*.sparsebundle`
7. Open MacOS "System Preferences", click on "General", and then open the "Time Machine" settings
8. The newly added virtual drive destination should be visible
   - Right-click on the virtual drive, click the "Backup device to Time Machine right now"
   - Optionally, click on "Options..." in the Time Machine settings, and set prefered mode for "Backup Frequency" (ie. Manually, Automatically etc.)
   - Optionally, in the "Options" you can set which folders and apps to exclude from the Time Machine backup

{{< notice >}}
Tips & Tricks
{{</ notice >}}
{{< callout emoji="💻" text="The initial backup will take a while. It's recommended to plug the Mac directly to the router via an ethernet cable, instead of using WiFi, and the same can be said for the Windows machine that acts as a Time Machine capsule. A MacOS software such is Caffeine or Amphetamine can be used to keep the Mac awake until the backup is completed." >}}

As long as the image is mounted, Time Machine will keep backing up to it. If you restart the Mac, hovever, we will need to open this disk image again before the backups can start. To minimise the efforts needed for this, a quick AppleScript automation can be created, which will mount the drive automatically. Open the *Script Editor* app. in MacOS, click "Create New File", and use the following AppleScript:

```
try
	mount volume "smb://192.168.1.x/"
on error
	return
end try

do shell script "hdiutil attach -mountpoint /Volumes/TimeMachineCapsule/ /Volumes/SHARENAME/MACOS_BACKUP/TimeMachine.sparsebundle"
```

Test the result and save this script if it works anywhere on your MacOS, for example in `~/.config/MountVirtWin10TimeMachine.scpt` folder. Now from "System Preferences" on MacOS, search for "Login Items & Extensions", and add the the application you just made to your "Startup Items" section; this allows it to run the script automatically when you log-in to your MacOS.

More details on MacOS Time Machines `.sparsebundle` files can be found on the following URL: [`TimeMachine Sparsebundle via ~null.53bits.co.uk`](https://null.53bits.co.uk/page/timemachine-sparsebundle).

**Avoiding and disabling `.DS_Store` files in macOS**

Start by removing all `.DS_Store` files from the current directory or from the `/` (__root__) directory. This can also be any kind of shared (SMB) file server directory:

```
# Remove all .DS_Store from the current directory
$ find ./ -name ".DS_Store" -exec rm {} \;

# Remove all .DS_Store from the root directory
$ find / -name ".DS_Store" -exec rm {} \;

# Remove all .DS_Store from an SMB share/directory
$ find smb://x.x.x.x/<share>/example_directory -name ".DS_Store" -exec rm {} \;
```

Once the `.DS_Store` file removal is completed, use the following command to make sure new `.DS_Store` files are not written automatically by the system:

```
$ defaults write com.apple.desktopservices DSDontWriteNetworkStores true
```

**Fine-adjusting MacOS sound output volume**

* When pressing special volume keys (ie. *Mute* 🔇, *Volume +* or *Volume -*) it steps by `1 bar`
* Using any of the above special volume keys in combination with `Shift+Option` key pressed;
  * You can adjust volume output more granually and precisely
  * When using this combination, the volume steps by `1/4` of a bar, allowing for finer adjustments

Also, this Terminal command disables the play icon on a media file thumbnail in Finder to prevent the audio or video file from playing when selecting:

```
$ defaults write com.apple.finder QLInlinePreviewMinimumSupportedSize -int 514
```

**Pasting text and removing all formattings**

Its possible to paste text only and remove formatting for any text in the clipboard by using `CMD+Shift+v` key button combination, while the `CMD+v` will paste text formatted as copied.

**Show macOS Network Interfaces**

Network Interface details can be queried either via typical `ifconfig`, or what I prefer to usually use (showing a prettier, *one-line-per-interface* output):

```
$ netstat -bi
# Name       Mtu   Network       Address            Ipkts Ierrs     Ibytes    Opkts Oerrs     Obytes  Coll
# lo0        16384 <Link#1>                        247863     0  245148028   247863     0  245148028     0
# lo0        16384 127           localhost         247863     -  245148028   247863     -  245148028     -
# ...
```

**Show macOS IP/Network routes definition**

To show all network addressing `routes` with FQDN included, use below command line:

```
$ netstat -nr

# Routing tables
#
# Internet:
# Destination        Gateway            Flags               Netif Expire
# default            192.168.0.1        UGScg               en7
# default            192.168.1.1        UGScIg              en0
# ...                ...                ...                 ...
#             (shows IPv4 network addressing routes)

# Internet6:
# Destination                             Gateway                                 Flags               Netif Expire
# default                                 fe80::%utun0                            UGcIg               utun0
# default                                 fe80::%utun1                            UGcIg               utun1
# ...                                     xxxx::%<tunif                           ...                 ...
#             (shows IPv6 network addressing routes)
```

To show all network addressing `routes` **without** FQDN included, use the same command without `-n` argument, as shown below:

```
$ netstat -r

# Routing tables
#
# Internet:
# Destination        Gateway            Flags               Netif Expire
# default            modem.corp.durakic UGScg               en7
# default            192.168.1.1        UGScIg              en0
# ...                ...                ...                 ...
#             (shows IPv4 network addressing routes)

# Internet6:
# Destination        Gateway            Flags               Netif Expire
# default            fe80::%utun0       UGcIg               utun0
# default            fe80::%utun1       UGcIg               utun1
# ...                xxxx::%<tunif      ...                 ...
#             (shows IPv6 network addressing routes)
```

**Show macOS active network connections** (based on given protocol)

Below command allows you to show active network connections on macOS for a given protocol:

```
$ netstat -p <protocol>   # where protocol is <any> of
                          # cat /etc/protocols

$ netstat -p tcp          # exmaple for 'tcp' protocol
#
# Active Internet connections
# Proto Recv-Q Send-Q  Local Address          Foreign Address        (state)
# tcp4       0      0  xxx.168.0.xx.xxxxx     xx.xxx.xxx.xx.https    ESTABLISHED
# tcp4       0      0  xxx.168.0.xx.xxxxx     xxxxxxxx-in-xxy..https ESTABLISHED
# ...      ...    ...  ...                    ...                    ...

$ netstat -p udp          # example for 'udp' protocol
#
# Active Internet connections
# Proto Recv-Q Send-Q  Local Address          Foreign Address        (state)
# udp4       0      0  *.*                    *.*
# udp4       0      0  *.*                    *.*
# ...      ...    ...  ...                    ...
```

**List Open Files on macOS alongside their Connected Destination**

The command [`lsof`](http://en.wikipedia.org/wiki/Lsof) is used to '*List Open Files*'. Using a simple `grep`, it's possible to filter their destination, which will show you which files are connected to which destinations:

```
$ [sudo] /usr/sbin/lsof -i -P | grep ESTABLISHED
# lghub_upd   567           root   11u  IPv4 0xc3ac610176fc3a2d      0t0    TCP localhost:9100->localhost:49431 (ESTABLISHED)
# rapportd    690        xxxxxxx   14u  IPv6 0x374c318c196dd3d2      0t0    TCP hostname.local:49156->other-hostname.local:49704 (ESTABLISHED)
# identitys   710        xxxxxxx   56u  IPv6 0x9c95f2b22703317c      0t0    TCP hostname.local:1024->[xxxx:xx::xxxx:xxxx:xxxx:xxxx]:1024 (ESTABLISHED)
# ...
```

**Monitor Real-time Network Traffic on macOS**

To monitor a real-time network traffic for a given network interface on macOS, one can use the `iftop` command-line utility. The [`iftop`](http://www.ex-parrot.com/pdw/iftop/) utility can be used to show bandwidth usage on all or specific network interface, alongisde hostnames, ports, host pair, and so on.

```
# install 'iftop' CLI utlity via brew
$ brew instlal iftop

# run 'iftop' utility with 'sudo' rights
$ sudo iftop

# specific interface to use with 'iftop' using
$ sudo iftop -i en7
```

**Move macOS Desktop/Spaces with Keyboard Shortcut**

Using `Control+Left` or `Control+Right` keyboard shortcut, we can move over macOS spaces either while in maximised full screen view or in default desktop/app view.

To do so, open `Keyboard->Keyboard Shortcuts...` menu button in *System Settings* app. on macOS and set the following in the `Mission Control` *[tree]*-sidebar and it's relevant section:

- Add "Move left a space" (`Control+[Left Arrow]`)
- Add "Move right a space" (`Control+[Right Arrow]`)
- Click "Done" button

![](https://i.imgur.com/37gACWs.png)

**Essential Commands**

Add below code to `~/.zshrc` or equivalent to quickly enable new settings and configuration.

```
profile() {
  open .bash_profile
}

reload() {
  . .bash_profile
}
```

**Printers and Related**

Clear printing queue:

```
$ cancel -a -
```

Quit Printer App after print jobs has completed:

```
$ defaults write com.apple.print.PrintingPrefs "Quit When Finished" -bool true
```

**System and Related**

Use `sudo` with TouchID instead of typing the password:

```
$ sudo vim /etc/pam.d/sudo
# add the following line to the top:
# auth sufficient pam_tid.so
```

Or use the following one-liner to do the same:

```sh
sudo sh -c -- 'filename="sudo" && file="/etc/pam.d/$filename" && echo "auth sufficient pam_tid.so" | cat - $file > /tmp/$filename.tmp && mv /tmp/$filename.tmp $file'
```

Disable or enable letter accents popups when long-pressing keyboard letter:

```
# Ever wanted to send "lollllllllll", but noticed that upon long-pressing a letter you get the letter accents popup?
defaults write -g ApplePressAndHoldEnabled -bool false      # Turn it off

# To re-enable just revert the bool type to true
defaults write -g ApplePressAndHoldEnabled -bool true       # Turn it on
```

Programatically set macOS login window text:

```
sudo defaults write /Library/Preferences/com.apple.loginwindow LoginwindowText "This system is authorized to ... [redacted]"
```

Speeding up "Quick Look" animation:

```
$ defaults write -g QLPanelAnimationDuration -float 0.1
```

Get battery percentage:

```
$ pmset -g batt | egrep "([0-9]+\%).*" -o --colour=auto | cut -f1 -d';'
```

Terminal color Test:

```
$ fg=""
bg=""
for i in {0..255}; do
    a=$(printf "\\x1b[38;5;%sm%3d\\e[0m " "$i" "$i")
    b=$(printf "\\x1b[48;5;%sm%3d\\e[0m " "$i" "$i")
    fg+="$a"
    bg+="$b"
    if (( "$i" % 5 ==0 )); then
        echo -e "$fg\\t\\t$bg"
        fg=""
        bg=""
    else
        fg+="  "
        bg+="  "
    fi
done
```

Bash alias function to extract any compressed file:

```
# append the following in ~/.config/functions file

#!/usr/bin/env bash
# Extract archives - use: extract <file>
# Credits to http://dotfiles.org/~pseup/.bashrc

if [ -f "$1" ] ; then
    case "$1" in
        *.tar.bz2) tar xjf "$1" ;;
        *.tar.gz) tar xzf "$1" ;;
        *.bz2) bunzip2 "$1" ;;
        *.rar) rar x "$1" ;;
        *.gz) gunzip "$1" ;;
        *.tar) tar xf "$1" ;;
        *.tbz2) tar xjf "$1" ;;
        *.tgz) tar xzf "$1" ;;
        *.zip) unzip "$1" ;;
        *.Z) uncompress "$1" ;;
        *.7z) 7z x "$1" ;;
        *) echo "'$1' cannot be extracted via extract()" ;;
    esac
else
    echo "'$1' is not a valid file"
fi
```

Allow last installed app. from unidentified developer to be allowed:

```
$ sudo spctl --add /Applications/$(ls -lt /Applications/ | head -2 | grep .app | cut -d':' -f2 | sed 's/[0-9]*//g' | sed -e 's/^[ \t]*//')
# it's possible to create a shortcut that will execute this command 
```

**Quickly open selected item in Finder's New Window**

This works both for opening either new Finder.app window or opening a new tab in the Finder.app for selected folder or document item, as selected in the Finder app.

To do so, first open Automator.app and use the `Cmd+N` to create new Quick Action using the workflow name `Open New Tab for selected Item ...`.

{{< notice >}}
Tips and Tricks
{{</ notice >}}
{{< callout emoji="💡" text="The Automator.app workflows will be stored in the following macOS directory: /Users/$USER/Library/Services/[filename].workflow" >}}

Using Terminal, you can open the workflow script directory with the command:

```sh
$ open ~/Library/Services
```

The Automator.app workflow will start up with blank view, use a `File->New ...` menu button or shortcut `CMD+N` to choose the `Quick Action` as the workflow type and click **Choose** in the popup window.

![](https://i.imgur.com/dVthoCx.jpeg)

Then use the newly created Automator.app Workflow settings as shown below:

1. **Rename the Workflow to `"Open New Tab for selected Item ...[.workflow]"` (by renaming the document in Finder)**
2. **Workflow Receiver:**
   - "Workflow receives current: `[files or folders]`" in `Finder.app`
   - "Input is: `[entire selection]`" (*disabled, default*)
   - "Image: `All My Files`" (*or select any other icons*)
   - "Colour: `Black`" (*or select icon color*)
3. **Click on the "Library" toolbar icon, or app. menu `View->Show Library`**
4. **In `Library->Actions` tab, search for "Run AppleScript" and drag-&-drop it to the workflow steps**
5. **Paste the AppleScript code for the workflow and Save the Workflow Document (`Cmd+S`)**

![](https://i.imgur.com/SZySwSp.jpeg)

The AppleScript code to use is shown below:

```scpt
# AppleScript for macOS Sonoma that opens a new Finder window/tab showing the directory of  
# a selected item (file or folder). If no item is selected, the script does nothing. Can be 
# used in a Shortcut.app, as a Service in the menubar item, or as a Quick Action extension. 
# 
# Author: H. Duraki <hduraki@icloud.com>
#		    <https://github.com/duraki>
#                   Jan 11, 2025

tell application "Finder"
	-- Check if there is a selection of Item/Folder
	set selectedItems to selection
	if selectedItems is not {} then
		-- Get the folder of the first selected item
		set selectedItem to item 1 of selectedItems
		set parentFolder to container of selectedItem as alias
		
		-- Open a new Finder window/tab with the item's directory
		make new Finder window
		set target of front window to parentFolder
		
		-- Optionally highlight the item in the new window
		select selectedItem
	else
		-- If no item is selected, ~do~ nothing ~or~
		-- use 'display dialog ... buttons {...}' to show the dialog selection
	end if
end tell
```

The workflow will be added to the "Quick Action" list when using right-click button on the Finder's selected item or directory, or it can be enabled in "Services" by opening Finder.app, then clicking `Finder->Services->Services Settings...` in the macOS menubar and selecting "Files and Folders" from the listview in the `Services` sidebar and checking the "*Open New Tab for selected item ...*". Click "Done" button when finished to complete the adding the item in the Application Services menu. By clicking on the "*none*" column (marked as *no# 4* in screenshot below), you may set a shortcut for the selected service button/action.

![](https://i.imgur.com/hoPzEd7.jpeg)

Using the above, the workflow will be added both in the right's-click "Quick Action" menu from the Finder.app, or using the `Services->Open New Tab for selected item ...` from the menubar in the Finder.app - for example, [using the right-click menu](https://i.imgur.com/Q8MLDes.jpeg), or via `Services->[...]` in the menubar [as shown here](https://i.imgur.com/yFdxkjZ.jpeg).

{{< details "Right-click 'Quick Action' Menu" >}}
![](https://i.imgur.com/Q8MLDes.jpeg)
{{< /details >}}

{{< details "Using 'Services' Menu in Finder" >}}
![](https://i.imgur.com/yFdxkjZ.jpeg)
{{< /details >}}

Alternatively, download the full `.workflow` script for Automator.app to quickly add this action: [Download `.workflow` Bundle]("/posts/files/macos/Open New Tab for selected Item .....workflow"), and copy it to `~/Library/Services` directory on your macOS.

See also: [Github Gist - "*Open New Tab for Selected Item.scpt*"](https://gist.github.com/duraki/9a14120e74ab7e678a99eb9621ef108f)

**Handy Command Line (CLI) Apps.**

Several CLI utility apps are described and linked in [Sys/DevOps Notes](/sys/devops-notes). Other newly discovered CLI utils, that may not be *Sys/DevOps* specific, are linked in list below:

* [xsv](https://github.com/BurntSushi/xsv) - fast CSV command-line toolkit written in Rust
* [tealdeer](https://github.com/dbrgn/tealdeer) - faster *(Rust-based)* alternative for `tldr`
* [denisidoro/navi](https://github.com/denisidoro/navi) - `navi` is an interactive cheatsheet tool
* [phiresky/ripgrep-all](https://github.com/phiresky/ripgrep-all) - `rga` is like `ripgrep` but works for PDFs, eBooks, Office Docs, Archives, ..
* [sharkdp/fd](https://github.com/sharkdp/fd) - `fd` is a quick, user-friendly alternative to `POSIX`'s `find`
* [ivarch/pv/pipeviewer](https://ivarch.com/programs/pv.shtml) - `pv` is a Pipe Viewer, allowing you to monitor the progress of data thru pipelines
* [fkill-cli](https://github.com/sindresorhus/fkill-cli) - `fkill` is a cross-platform process terminator, can kill by: `PID`, `Name`, `Port`
* [TomWright/dasel](https://github.com/TomWright/dasel) - The app. `dasel` is like `jq/yq/fq` but supports: `JSON`, `YAML`, `TOML`, `XML`, & `CSV`
* [jqnatividad/qsv](https://github.com/jqnatividad/qsv) - Ultra-fast CSV data-wrangling toolkit `qsv`, with [huge list of commands](https://github.com/jqnatividad/qsv#available-commands)
* [samwho/spacer](https://github.com/samwho/spacer) - `spacer` is a simple CLI tool to insert spacers when command output stops or finishes
* [o2sh/onefetch](https://github.com/o2sh/onefetch) - use `onefetch` to query `git` repositories information, providing project info., code statistics and other info

**System Builtin Command Line (CLI) Apps.**

```
    # User identity
$ id -F             # => [FirstName  LastName]
$ id -u             # => [UserID]
$ hostname          # => [user.hostname]

    # Host identity
$ sw_vers
$ sw_vers -productName
$ sw_vers -productVersion
$ sw_vers -buildVersion

    # Date/Time
$ date
$ cal

    # List Open Files/Networks
    # @see: https://ftp.mirrorservice.org/sites/lsof.itap.purdue.edu/pub/tools/unix/lsof/FAQ
$ lsof
$ lsof [FILEPATH1] [FILEPATH2] [...]        # => Show who is using a FILE(S)
$ lsof -c [PROCNAME]                        # => Show used files from PROCNAME
$ lsof -i                                   # => List all network connections
$ lsof -i [4|6] -a -p [PID]                 # => List all open files by PID that also pings IPv4 or IPv6
$ lsof -i @HOSTNAME.com:80-443              # => List all files using PORTS range of HOSTNAME
$ lsof -i :PORT                             # => List all files using PORT

    # Network
$ sudo tcpdump -i [INTERFACE]

    # Launch Services DB
$ lsregister

    # Evaluates expression
$ expr [EXPR]
$ let  [EXPR]

    # Environment
$ export
$ printenv

    # macOS user defaults
$ defaults [read|write] [PATH]
$ defaults read -app Preview

    # Kernel Extensions (kexts)
$ kextfind
$ kextstat
$ kextfind
```

* Other *(built-in)* [Hidden Tools in macOS](https://github.com/azenla/MacHack)

**Adding an application to Finder.app toolbar**

Locate the app. in your `/Application` folder. Lets say you want to use OpenTerminal-Lite app. as a toolbar menu in Finder.

1. Locate the /Applications/OpenTerminal-Lite.app
2. Use `⌘`+`⌥` on keyboard, and drag-and-drop the app to Finder.app toolbar
3. Yup, thats it

**Hide a folder on MacOS (using an attribute)**

```
$ chflags hidden /someones/desktop/folder
```

**Hide a symlink folder on MacOS**

```
$ chflags -h hidden /someones/desktop/folder
```

**Check Application entitlement**

```
# ~> brew install jtool

# => no visible entitlemens
$ jtool --ent /Applications/MachOView.app
/Applications/MachOView.app/Contents/MacOS//MachOView apparently does not contain any entitlements

# => with visible entitlements
$ jtool --ent /Applications/ProtonVPN.app
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>com.apple.application-identifier</key>
	<string>J6S6Q257EK.ch.protonvpn.mac</string>
	<key>com.apple.developer.maps</key>
	<true/>
...
```
**libSystem.B.dylib**

All API rely on above library. For example, when the MachO Process starts, the above library will be loaded early in time so it can use other APIs.

**Color-print file output with line numbers**

```
$ brew install ccat
# in ~/.config/.aliases:
#
#       alias ccat="ccat --bg=dark
#                   -G Plaintext='white' -G String='*darkgray*'
#                   -G Comment='white' -G HTMLAttrValue='red'
#                   -G HTMLAttrName='red' -G Type='**purple**'
#                   -G HTMLTag='**yellow**'"

$ cat -n ~/INPUT.txt | ccat
```

**Completely remove Microsoft forced Auto-update Utility**

There is annoying feature when you have Microsoft Word (Office) installed from official channel which requires subscription, that pops-up an error "Microsoft Autoupdater is disabled" if you removed it previously from the MacOS System Settings autorun/login items. This results in a non-working Microsoft Office software until you finish updating the Office bundle, which may take a while and render your time unusable (eh, *shitty microsoft*).

The shell script shown below tries to bypass this forced auto-updater that is bundled by the Microsoft. Use with caution, after all, it removed the agent/xpc mods and configs from your MacOS host, which can create some new problems. My advise is to ditch Microsoft all together in your work/business environment because it's prone as a potential attack vector against non-literate IT employees. Since I'm a consultant, I write a lot of penetration testing reports, and therefore I'm required to have it most of the time.

*Note:* Running this script also stops auto-updating of all Microsoft Office pkgs from your MacOS, so you will have to update the Office apps manually when new version is released. P.S. There is an alternative 'GUI' version which provides more features called [Office Reset](https://office-reset.com) for MacOS, but I have not tested it myself (also see: [ms-auto-update via `brew`](https://formulae.brew.sh/cask/microsoft-auto-update))

Start by creating a new file in `~/.config/bin` directory, and paste the shell content. Make sure to set the script as an executable. To run it, you must invoke `sudo` or alternative *su* privileged account.

```sh
$ touch ~/.config/bin/remove-microsoft-autoupdate
$ chmod +x ~/.config/bin/remove-microsoft-autoupdate
$ vim ~/.config/bin/remove-microsoft-autoupdate       # script is shown below
```

Running the script will output its result in the *termtty*:

```sh
$ sudo ~/.config/bin/remove-microsoft-autoupdate      # run the script to do the magic
# 
# Microsoft AutoUpdate Remover
# ==================================
# Check Microsoft Update components? y
# 
# Microsoft Update Components Check List:
# No  | File                                                                   | Status     | Size
# ----+----------------------------------------------------------------------+------------+--------
# 1   | /Library/Application Support/Microsoft/MAU2.0/Microsoft AutoUpdate.app | [Exists]   |  11M
# 2   | ...
# 
# Remove all existing Microsoft Update components? y
# Removing components...
# 
# No  | File                                                                   | Status     | Size
# ----+----------------------------------------------------------------------+------------+--------
# 1   | /Library/Application Support/Microsoft/MAU2.0/Microsoft AutoUpdate.app | REMOVED
# 2   | ...
# 
# Successfully removed: 4
# Operation completed!
```

The shell script tries to remove all of its Microsoft autoupdate agents which eventually makes Word/Excel/Office running successfully (that is, without annoying updater pop-ups).

```bash
#!/bin/zsh

# Original Repo: https://github.com/mrsarac/microsoft-update-remover

# Check for root privileges
check_root() {
    if [ "$(id -u)" != "0" ]; then
        echo "This script requires root privileges."
        echo "Please run with 'sudo':"
        echo "sudo $0"
        exit 1
    fi
}

# Display file size in a human-readable format
get_size() {
    if [ -f "$1" ]; then
        size=$(du -h "$1" 2>/dev/null | cut -f1)
        echo "$size"
    elif [ -d "$1" ]; then
        size=$(du -sh "$1" 2>/dev/null | cut -f1)
        echo "$size"
    else
        echo "-"
    fi
}

# Show table header
show_table_header() {
    printf "%-3s | %-70s | %-10s | %s\n" "No" "File" "Status" "Size"
    printf "%s\n" "----+----------------------------------------------------------------------+------------+--------"
}

# Display all removable items in a table format
show_items() {
    echo "\nMicrosoft Update Components Check List:"
    
    show_table_header
    
    found_count=0
    i=1
    
    for file in "${files_to_remove[@]}"; do
        file_status=""
        file_size=""
        if [[ -e "$file" ]]; then
            file_status="[Exists]"
        else
            file_status="[Not Found]"
        fi
        file_size=$(get_size "$file")
        
        printf "%-3d | %-70s | %-10s | %s\n" "$i" "$file" "$file_status" "$file_size"
        
        if [[ "$file_status" == *"Exists"* ]]; then
            ((found_count++))
        fi
        ((i++))
    done
    
    echo "\nSummary:"
    echo "Total components: ${#files_to_remove[@]}"
    echo "Existing components: ${found_count}"
}

# Remove selected items
remove_items() {
    local success=0
    local failed=0
    
    echo "\nRemoving components...\n"
    
    show_table_header
    
    local i=1
    for file in "${files_to_remove[@]}"; do
        printf "%-3d | %-70s | " "$i" "$file"
        if sudo rm -rf "$file" 2>/dev/null; then
            printf "REMOVED\n"
            ((success++))
        else
            printf "ERROR\n"
            ((failed++))
        fi
        ((i++))
    done
    
    echo "\nResult:"
    echo "Successfully removed: $success"
    [ $failed -gt 0 ] && echo "Failed: $failed"
}

# Main function
main() {
    # Check for root privileges
    check_root
    
    # List of removable files
    files_to_remove=(
        "/Library/Application Support/Microsoft/MAU2.0/Microsoft AutoUpdate.app"
        "/Library/LaunchAgents/com.microsoft.update.agent.plist"
        "/Library/LaunchDaemons/com.microsoft.autoupdate.helper.plist"
        "/Library/PrivilegedHelperTools/com.microsoft.autoupdate.helper"
    )
    
    # Header
    echo "\nMicrosoft AutoUpdate Remover"
    echo "=================================="
    
    # File check prompt
    echo "\nCheck Microsoft Update components? (y/n)"
    read -r response
    if [[ ! "$response" =~ ^[YyEe]$ ]]; then
        echo "\nOperation cancelled."
        exit 0
    fi
    
    # Show items
    show_items
    
    # Deletion confirmation
    echo "\nRemove all existing Microsoft Update components? (y/n)"
    read -r response
    if [[ ! "$response" =~ ^[YyEe]$ ]]; then
        echo "\nOperation cancelled."
        exit 0
    fi
    
    # Remove selected items
    remove_items
    
    echo "\nOperation completed!"
    echo "\nNote: If you want to update Microsoft Office in the future,"
    echo "you can manually download updates from Microsoft's website:"
    echo "https://learn.microsoft.com/en-us/officeupdates/update-history-office-for-mac"
}

# Run the script
main
```

**Remove an Application from Launchpad**

Sometimes MacOS Launchpad gets overflown with number of applications that are visible in the view. There is a way to remove/hide an application by working directly with MacOS's Internal databases.

```
$ sqlite3 $(sudo find /private/var/folders -name com.apple.dock.launchpad)/db/db
# ...

sqlite> .tables
app_sources       categories        downloading_apps  image_cache
apps              dbinfo            groups            items
sqlite> DELETE FROM apps WHERE title='qwingraph';
   <Ctrl+D>

$ killall Dock
```
This should remove the application from the Launchpad, but will not remove it from the `/Applications` directory.

**Mount RaspberryPi / BananaPi SD Card**

Note: these instructions are outdated, please take a look at newer documentation in [fuse-ext2 notes](/fuse-ext2). The difference between the `fuse-ext2` and `ext4fuse` is that the former allows for `r/w` on the mounted partition; and not only `r/o`, as is the case with `ext4fuse`.

Insert SD Card in your card reader or Macbook. Then when the error pops-up, just hit "Ignore" (not *Eject*!).

The SD Card should be visible by the MacOS, but not mounted, as such:

```
$ diskutil list
...
/dev/disk2 (external, physical):
   #:                       TYPE NAME                    SIZE       IDENTIFIER
   0:     FDisk_partition_scheme                        *15.9 GB    disk2
   1:                      Linux                         1.3 GB     disk2s1
                    (free space)                         14.6 GB    -
```

Make sure to install macfuse, and ext4fuse:

```
$ brew install macfuse

$ brew install ext4fuse # => might throw an error, @see below for instructions
# 1) the first possibility is to install osxfuse first, and then try ext4fuse again
# ie.
# 		brew install --cask osxfuse
# 		brew install ext4fuse
# Make sure to reboot your system, because of the new Kext/Kernel extension.

# 2) the other option is to manually force ext2fuse via the script. the script are
#	 in this notes, right below.
```

Add current `$USER` to the operator group, so it could have readonly permissions to the disk:

```
$ sudo dscl . append /Groups/operator GroupMembership `whoami`
```

We shall not forget important step right here, unmounting the disk from the MacOS host (not the partition):

```
$ sudo diskutil unmountDisk /dev/disk2
```

Make a mountable directory on your Mac and mount the SD card ext4 partition:

```
$ mkdir ~/raspberry # => or /Volumes/raspberry for natural choice
$ sudo ext4fuse /dev/disk2s1 ~/raspberry -o allow_other
```

If you get **fuse: no mount point** error, it means you haven't set correct mount directory (ie. `~/raspberry`). Go back and repeat the steps as instructed.

*note*: adding `allow_other` for this SD card should make it readable by everyone.

To unmount the SD Card, just simply use:

``` 
$ sudo diskutil unmount /dev/disk2s1
$ sudo diskutil unmountDisk /dev/disk2
$ sudo diskutil unmountDisk ~/raspberry
```

**Installing ext4fuse in MacOS**

Download the script below, and save it somewhere in your machine, then run:

```
$ brew install --formula --build-from-source /tmp/ext4fuse.rb
```

**References:**

* [Mount Raspberry Pi SD Card on MacOS (R/O)](https://www.jeffgeerling.com/blog/2017/mount-raspberry-pi-sd-card-on-mac-read-only-osxfuse-and-ext4fuse)
* [Mount Raspberry Pi SSD on Big Sur](https://bespired.medium.com/mount-a-pi-ssd-on-your-big-sur-mac-d0ada9939fa4)
* [Mount an ext4 partition on MacOS](https://www.zleptnig.com/blog/mount-an-ext4-partition-on-macos)
* [Mount ext4 Filesystem on MacOS](https://docs.j7k6.org/mount-ext4-macos/)
* [Use more than one version of macOS on a Mac](https://support.apple.com/en-us/HT208891)

(*note*: paste the following in `/tmp/ext4fuse.rb`:

```
# => cat /tmp/ext4fuse.rb

class MacFuseRequirement < Requirement
  fatal true

  satisfy(build_env: false) { self.class.binary_mac_fuse_installed? }

  def self.binary_mac_fuse_installed?
    File.exist?("/usr/local/include/fuse/fuse.h") &&
      !File.symlink?("/usr/local/include/fuse")
  end

  env do
    ENV.append_path "PKG_CONFIG_PATH", HOMEBREW_LIBRARY/"Homebrew/os/mac/pkgconfig/fuse"
    ENV.append_path "PKG_CONFIG_PATH", "/usr/local/lib/pkgconfig"

    unless HOMEBREW_PREFIX.to_s == "/usr/local"
      ENV.append_path "HOMEBREW_LIBRARY_PATHS", "/usr/local/lib"
      ENV.append_path "HOMEBREW_INCLUDE_PATHS", "/usr/local/include/fuse"
    end
  end

  def message
    "macFUSE is required. Please run `brew install --cask macfuse` first."
  end
end

class Ext4fuse < Formula
  desc "Read-only implementation of ext4 for FUSE"
  homepage "https://github.com/gerard/ext4fuse"
  url "https://github.com/gerard/ext4fuse/archive/v0.1.3.tar.gz"
  sha256 "550f1e152c4de7d4ea517ee1c708f57bfebb0856281c508511419db45aa3ca9f"
  license "GPL-2.0"
  head "https://github.com/gerard/ext4fuse.git"

  bottle do
    sha256 cellar: :any, catalina:    "446dde5e84b058966ead0cde5e38e9411f465732527f6decfa1c0dcdbd4abbef"
    sha256 cellar: :any, mojave:      "88c4918bf5218f99295e539fe4499152edb3b60b6659e44ddd68b22359f512ae"
    sha256 cellar: :any, high_sierra: "fc69c8993afd0ffc16a73c9c036ca8f83c77ac2a19b3237f76f9ccee8b30bbc9"
    sha256 cellar: :any, sierra:      "fe8bbe7cd5362f00ff06ef750926bf349d60563c20b0ecf212778631c8912ba2"
    sha256 cellar: :any, el_capitan:  "291047c821b7b205d85be853fb005510c6ab01bd4c2a2193c192299b6f049d35"
    sha256 cellar: :any, yosemite:    "b11f564b7e7c08af0b0a3e9854973d39809bf2d8a56014f4882772b2f7307ac1"
  end

  depends_on "pkg-config" => :build

  on_macos do
    depends_on MacFuseRequirement => :build
  end

  on_linux do
    depends_on "libfuse"
  end

  def install
    system "make"
    bin.install "ext4fuse"
  end
end
```

**MacOS ScreenSaver Collection**

* [Flux](https://github.com/packagesdev/flux) *([Picture](https://www.reallyslick.com/pictures/flux_th.jpg))*
* [Flocks](https://github.com/packagesdev/flocks) *([Picture](http://www.reallyslick.com/pictures/flocks_th.jpg))*
* [Cyclone](https://github.com/packagesdev/cyclone) *([Picture](http://www.reallyslick.com/pictures/cyclone_th.jpg))*
* [Fireflies](https://github.com/packagesdev/fireflies)
* [MatrixGL](https://github.com/packagesdev/matrixgl)

**Other Utils**

* [mac-cleanup-py](https://github.com/mac-cleanup/mac-cleanup-py) - Python cleanup script for macOS
* [lnav](https://lnav.org/) - log file navigator
* [nerdlog](https://github.com/dimonomid/nerdlog) - remote-first/multi-host TUI log viewer

**Other Resources**

* [Active Directory DC (Domain Controller) on macOS](https://null.53bits.co.uk/page/which-ad-dc)
* [Github: TIL (Today I Learned) macOS CLI Command Utilities](https://github.com/jbranchaud/til/blob/master/README.md#mac)