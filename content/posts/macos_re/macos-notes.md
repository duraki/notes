---
title: "MacOS Notes"
---

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

**Printing and Related**

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

Programatically set macOS login window text:

```
sudo defaults write /Library/Preferences/com.apple.loginwindow LoginwindowText "This system is authorized to ... [redacted]"
```

Speeding up "Quick Look" animation:

```
$ defaults write -g QLPanelAnimationDuration -float 0.1
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

