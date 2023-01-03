---
title: "fuse-ext2"
---

## Compiling Manually

Mounting via `fuse-ext2` instead of `ext4fuse`. First install required dependencies:

```
$ brew install caskroom/cask/osxfuse        # => be patient, it's ~300MiB in size
# it is possible that above 'brew install' command will fail, threfore we will 
# continue compiling it on our own. The error message I've got from the brew command 
# is:
#     installer: Error - The FUSE for macOS installation package is not compatible with this version of macOS.
#
# if you get similar error message in the terminal output, continue from next line.

$ brew install e2fsprogs m4 automake autoconf libtool      # => will install required libs to compile manually
```

Clone `fuse-ext2` repository somewhere in working directory and `cd` into it:

```
$ git clone --depth=1 https://github.com/alperakcan/fuse-ext2.git
Cloning into 'fuse-ext2'...
remote: Enumerating objects: 97, done.
remote: Counting objects: 100% (97/97), done.
...

$ cd fuse-ext2/
```

Lets generate installation and build script for our environments. Luckly, the fuse-ext2 project already contains auto generation script:

```
$ ./autogen.sh
Running autoreconf --verbose --install --force
autoreconf: export WARNINGS=
autoreconf: Entering directory '.'
autoreconf: configure.ac: not using Gettext
autoreconf: running: aclocal --force
autoreconf: configure.ac: tracing
autoreconf: running: glibtoolize --copy --force
glibtoolize: putting auxiliary files in '.'.
glibtoolize: copying file './ltmain.sh'
...
fuse-ext2/Makefile.am: installing './depcomp'
autoreconf: Leaving directory '.'
Removing autom4te.cache
```

If everything completed successfully, lets use generated `./configure` script to prepare `Makefile`. Use the `CFLAGS` environment variable to point to our previously installed dependencies:

```
CFLAGS="-idirafter/$(brew --prefix e2fsprogs)/include -idirafter/usr/local/include/osxfuse" LDFLAGS="-L$(brew --prefix e2fsprogs)/lib"  ./configure
checking build system type... x86_64-apple-darwin21.6.0
checking host system type... x86_64-apple-darwin21.6.0
checking target system type... x86_64-apple-darwin21.6.0
checking for a BSD-compatible install... /opt/local/bin/ginstall -c
checking whether build environment is sane... yes
...
config.status: executing depfiles commands
config.status: executing libtool commands
```

Now you just have to `make`, and `make install` to complete the manual compilation of `fuse-ext2`:

```
$ make
/Applications/Development/Xcode.app/Contents/Developer/usr/bin/make  all-recursive
Making all in fuse-ext2
gcc -DHAVE_CONFIG_H -I. -I..    -Wall ... [REDACTED]
        .getxattr       = op_getxattr,
                          ^~~~~~~~~~~
...
** BUILD SUCCEEDED **

make[3]: Nothing to be done for `all-am'.
make[2]: Nothing to be done for `all-am'.
```

To install newly created fuse-ext2 binaries, issue this command in the project directory:

```
$ sudo make install
/opt/local/bin/gmkdir -p '/usr/local/bin'
/bin/sh ../libtool   --mode=install /opt/local/bin/ginstall -c fuse-ext2 fuse-ext2.probe fuse-ext2.wait fuse-ext2.install fuse-ext2.uninstall '/usr/local/bin'
libtool: install: /opt/local/bin/ginstall -c fuse-ext2 /usr/local/bin/fuse-ext2
/opt/local/bin/ginstall -c -d "//usr/local/sbin"
...
```

The following command will be used to forcefully enable `fuse-ext2` write access:

```
$ sudo sed -e 's/OPTIONS="local,allow_other"/OPTIONS="local,allow_other,rw+"/' -i.orig /Library/Filesystems/fuse-ext2.fs/fuse-ext2.util
```

## Usage

Now after you have everything ready and installed, lets continue with `ext4fuse`. The `ext4fuse` is required for `fuse-ext2` FileSystem, in case you want to be able to read `ext4` partitions (such is GNU/Linux partition). Install `ext4fuse` from the Homebrew packages, or manually compile cask [as described here](/macos-notes).

```
$ brew install ext4fuse
$ sudo dscl . append /Groups/operator GroupMembership `whoami`      # => make sure to add user to operator group
```

Insert your SD Card (ie. RaspbianOS), and show available disks using `diskutility`:

```
$ sudo diskutil list
...
/dev/disk2 (external, physical):
   #:                       TYPE NAME                    SIZE       IDENTIFIER
   0:     FDisk_partition_scheme                        *31.9 GB    disk2
   1:                      Linux                         5.2 GB     disk2s1
                    (free space)                         26.7 GB    -
```

Unmount the Disk so we can mount partition:

```
$ sudo diskutil unmountDisk /dev/disk2
```

Finally create a new mount directory, and mount the ext4 partition:

```
$ sudo mkdir /Volumes/Linux
$ sudo fuse-ext2 /dev/disk2s1 /Volumes/Linux -o rw+
```

After you finish changing/editing/viewing the ext4 partition, make sure to always unmount the partition from the filesystem:

```
$ sudo umount /Volumes/Linux
```