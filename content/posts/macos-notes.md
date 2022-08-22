---
title: "MacOS Notes"
---

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

**Mount RaspberryPi / BananaPi SD Card**

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

Make a mountable directory on your Mac and mount the SD card:

```
$ mkdir ~/raspberry # => or /Volumes/raspberry for natural choice
$ sudo ext4fuse /dev/disk2s1 ~/raspberry -o allow_other
```

*note*: adding `allow_other` for this SD card should be readable by everyone

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

(*note*: paste the following in `/tmp/ext2fuse.rb`: 

```
# => cat /tmp/ext2fuse.rb

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