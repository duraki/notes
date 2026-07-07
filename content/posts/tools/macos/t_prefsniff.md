---
title: "Hook macOS Preferences"
---

## Install Toolset

Using [prefsniff](https://github.com/zcutlip/prefsniff) utility, we can sniff preferences changes on macOS plist files, and then autogenerate the defaults command to apply those changes.

Install it first:

```
$ pip3 install prefsniff
```

`prefsniff` is a utility to watch macOS `plist` files for changes, and then autogenerate the defaults command to apply those changes. Its intended use is to have `prefsniff` watch a `plist` file while setting a system or application preference.

The resulting defaults command can then be added to a shell script.

## Usage Description

[`prefsniff`](https://github.com/zcutlip/prefsniff) has two modes of operation; *directory* mode and *file* mode.

* **Directory mode**: watch a directory (non-recursively) for plist files that are unlinked and replaced in order to observe what file backs a particular configuration setting.
* **File mode**: watch a plist file in order to represent its changes as one or more `defaults` command.

**Directory Mode**

```
$ prefsniff ~/Library/Preferences
PREFSNIFF version 0.2.2
Watching directory: /Users/$USER/Library/Preferences
Detected change: [deleted]
# ...
```

**File Mode**

```
$ prefsniff ~/Library/Preferences/com.apple.dock.plist
PREFSNIFF version 0.2.2
Watching prefs file: /Users/$USER/Library/Preferences/com.apple.dock.plist
- # generated 'defaults'
defaults write com.apple.dock orientation -string right
```

### References

* [advanced 'defaults'](https://shadowfile.inode.link/blog/2018/06/advanced-defaults1-usage/) - introduction to plist files and the defaults(1) command, includes detailed explanation of each plist type
* ['defaults' locations](https://shadowfile.inode.link/blog/2018/08/defaults-non-obvious-locations/) - various defaults domains and where their corresponding plist files on disk
* [autogen 'defaults'](https://shadowfile.inode.link/blog/2018/08/autogenerating-defaults1-commands/) - prefsniff, and how to use it to autogenerate defaults commands
