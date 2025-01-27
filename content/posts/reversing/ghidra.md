---
title: "Ghidra and Related"
---

*Alternatively, check this too* **{{< sup_a " Ghidra Scripts and Plugins ⚜️" "/ghidra-scripts" >}}**

## Installation on Apple Intel {{< sup_a "x86_64" "#" >}}

Clone the repository or download and extract somewhere. In Ghidra, open the Script Manager (`Window -> Script Manager`) click the Script Directory button and add `$REPO/scripts` to the list.

Once the script directory is added to Ghidra you can find the scripts in the Script Manager. You can run the scripts directly from the Script Manager in Ghidra. Additionally, imported scripts can also have Menus entry, and assigned keyboard shortcuts for ease of use. In order to activate the menus and shortcuts, you must click the `In Tool` checkbox next to the scripts you wish to integrate into Ghidra UI.

## Installation on Apple M1/M2 {{< sup_a "aarch64_arm" "#" >}}

I followed [this tutorial](https://lachy.io/posts/properly-installing-ghidra-on-an-m1-mac/) which at the time of writing was pretty fresh. I've first installed **Eclipse Temurin** Java Development Kit, [from here](https://adoptium.net/temurin/releases), but you can use alternative options such is [Amazon Corretto](https://aws.amazon.com/corretto/). **Be sure to download and install the AArch64 build, not the x64 build.**

After downloading `OpenJDK17U-jdk_aarch64_mac_hotspot_17.0.6_10.pkg` and installing the package; use `brew` to install Ghidra.

```
$ brew install --cask ghidra
# ...
# ==> Linking Binary 'ghidraRun' to '/opt/homebrew/bin/ghidraRun'
# ghidra was successfully installed!
```

This will install Ghidra to `/opt/homebrew/Caskroom/ghidra` and add the `ghidraRun` script to `$PATH`. Additionally, [download latest release](https://github.com/NationalSecurityAgency/ghidra/releases) of Ghidra, extract it, and add it manually to `$PATH`.

Be free to add `alias ghidra` which links to `ghidraRun` itself:

```
$ vim ~/.config/.aliases
# ...
# alias ghidra=ghidraRun
```

## Rebuild Native ARM64 Binaries

**To build native binaries**, refer to [instructions on ARM64 Native Binaries Rebuilding](/rebuilding-native-arm64-binaries) page.

## Ghidra Extending

**To see notes about Ghidra Scripts and Plugins**, refer to [Ghidra Scripting](/ghidra-scripts) page.
