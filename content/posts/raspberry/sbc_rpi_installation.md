---
title: "Raspberry Pi Quick Guide"
---

### Installation 

- Use NOOBS or Raspberry Pi official image for hardware environment (ie. PCBs, Electrical Engineering, Breadboard Wiring, Prototypes et al.)
- Use `SD Card Formatter` to quickly partition-overwrite whole SD Card Disk
- Use `balenaEtcher` to quickly write arm_os of your choice
- Use `Raspberry Pi Imager` to quickly write Raspbian OS with custom configuration

### Configuration

Upon installing your favorite `*.img` on your SD Card, make sure to boot the Raspberry Pi at least once, to finish configuration wizard with-in Raspbian OS. **Your Raspberry Pi will not boot up!**, unless you go through this wizard at least once (requires monitor/mouse/kb).

You can check your Hostname configuration, by issuing command on your Pi:

```
$ hostname -I
```

You can use the `hostname` value, rather then directly connecting to the IP address (if not set statically).

``` 
$ ping pi@raspberrypi.local
```

Make sure to configure WiFi connection as well.

### Set APT sources to closer country

Search Raspbian Mirros on [official website](https://www.raspbian.org/RaspbianMirrors), and select the country closest to yours. Here is the example with Slovenia:

```
Europe* Slovenia
ARNES 	(ftp|http)://ftp.arnes.si/mirrors/raspbian/raspbian
		rsync://ftp.arnes.si/raspbian/
```

Edit the `sources.list`:

```
$ sudo vim /etc/apt/sources.list
# => comment the first `# deb` line, and add this below it
# dep http://ftp.arnes.si/mirrors/raspbian/raspbian/ bullseye main contrib non-free rpi
```

Update the changes:

```
$ sudo apt update
```

**Upgrading the System Packages** is simple as:

```
$ sudo apt upgrade -y
```

### Upgrading Rasbian OS Kernel

**Updating Raspberry Pi packages (Tested)**

For details [check Raspberry Pi documentation](https://www.raspberrypi.com/documentation/computers/os.html#updating-and-upgrading-raspberry-pi-os) on updating and upgrading the OS.

```
# => full-upgrade is used in preference to a simple upgrade, as it also picks up any dependency changes that may have been made
$ sudo apt full-upgrade
```

**Updating Raspberry Pi Kernel (Untested)**

Using `rpi-update` will update your Raspberry Pi OS kernel and VideoCore firmware to the latest pre-release versions.

```
$ sudo rpi-update
$ sudo reboot
```

For a full list of options, check documentation in the [rpi-update repository](https://github.com/raspberrypi/rpi-update#options).

### Downgrading Raspbian OS Kernel

If you have done an rpi-update and things are not working as you wish, if your Raspberry Pi is still bootable you can return to the stable release using:

```
$ sudo apt-get update
$ sudo apt install --reinstall libraspberrypi0 libraspberrypi-{bin,dev,doc} raspberrypi-bootloader raspberrypi-kernel
```

### Update Raspberry Pi EEPROM

Updating the bootloader of your Raspberry Pi to the latest preview version is an optional step. You may perform this only if you are facing any problems with your Pi.

You can check whether any updates are available for install by running the following command.

```
$ sudo rpi-eeprom-update
```

If any available update is there, you can give the following command to update Raspberry Pi EEPROM.

```
$ sudo rpi-eeprom-update -a
$ sudo reboot
```

### Clean Up some space

You can do some `clean` to remove all cached `.deb` archived stored in `/var/cache/apt/archives`:

```
$ sudo apt clean
```

### Post-install Settings

Remove the SD Card from your Raspberry Pi after base configuration and wizard setup, and use your MacOS to mount it in your working directory. The instructions are [under MacOS Notes](/macos-notes) down to the bottom.

1. Insert SD Card in your card reader
2. Make a directory for mounting Linux partition
3. Make changes to the Raspbian OS directly from `/boot`

You can use this to edit boot configuration files, enable SSH etc. directly from your Raspbian HDD.

Read the following to [Enable SSH](enable-ssh-on-raspbian-os) on via SD Card.

### Install VNC on Raspberry Pi

The standard image of the Raspberry Pi OS comes with RealVNC Connect software. If required for a custom OS, do it via:

```
$ sudo apt install realvnc-vnc-server realvnc-vnc-viewer
```

Otherwise, use `raspi-config` from the Terminal, and enable the VNC in:

```
Interface Options => VNC => Enable VNC
Display Options => VNC Resolution => 1280x1024
System Options => Boot / Auto Login => Desktop Autologin => Enable
```

Upon changing the settings, reboot your Raspberry Pi and connect from the MacOS using **VNCViewer**.

### References and Links

* [Raspberry Pi Official Documentation](https://www.raspberrypi.com/documentation/computers/getting-started.html)
* [RPI Configuration Parameters](https://elinux.org/RPiconfig)
* [Raspberry Pi Guide](https://raspberrypi-guide.github.io/)