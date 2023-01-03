---
title: "Armbian"
---

## Headless Wireless Configuration

If you want to set up a Wi-Fi Network, and perhaps an SSH server for a freshly-installed Armbian on the SD Card, this is the right place to look at. Sometimes, it can happen that you don't have access to the Monitor/Display and/or physical Keyboard. This notes describes how to configure Wi-Fi connection without having such hardware.
  
After etching the Armbian Operating System image `*.img.xz` on SD Card, [start mounting `ext4` partition](/fuse-ext2) using `fuse-ext2`. This FUSE software will allow you to read/write on the `ext4` partition of the SD Card, from the Host Machine (ie. MacOS). In short:

```
$ sudo diskutil unmountDisk /dev/disk[N]
$ sudo mkdir /Volumes/armbian
$ sudo fuse-ext2 /dev/disk2s1 /Volumes/armbian -o rw+
```

We are interested in `boot/` directory of our `/Volumes/armbian` mount point. Copy the file `boot/armbian_first_run.txt.template` to `boot/armbian_first_run.txt` in your ext4 partition mount point. This is a special Armbian configuration file that gets executed only on the first boot; meaning the settings in the configuration will be applied only once, when the Armbian is booted for a first time. 

```
$ mv /Volumes/armbian/boot/armbian_first_run.txt.template /Volumes/armbian/boot/armbian_first_run.txt

# => edit 'armbian_first_run.txt' accordingly
FR_general_delete_this_file_after_completion=1
#Networking:
FR_net_change_defaults=1
FR_net_wifi_enabled=1
FR_net_ethernet_enabled=1
FR_net_wifi_ssid='*********************'
FR_net_wifi_key='************'
FR_net_wifi_countrycode='BA'          # => via https://en.wikipedia.org/wiki/ISO_3166-1_alpha-2
```

You can read [more details](https://github.com/armbian/build/blob/master/packages/bsp/armbian_first_run.txt.template) about these keys and configuration settings, from the official [armbian/build](https://github.com/armbian/build) repository.

This **Armbian First Run** configuration will do the following:
- Change network interface to enable Wi-Fi
- Set Wi-Fi SSID and Password to which to connect on the first boot (Hardcoded)
- Set Wi-Fi frequency and prefered channel based on the Country

When you complete all necessary steps described above, you can now unmount the ext4 partition, and boot into the SBC (ie. Raspberry Pi).

```
$ cd            # => important, goes to $HOME directory, and does not block /dev/disk[N]s resource 
$ sudo umount /Volumes/armbian
```

Eject and remove the SD Card from your Host machine, and put it in the SBC (Raspberry Pi, Banana Pro et al.). Before powering up the SBC, take a note of all IPv4 assigned on the gateway/router. This way, you can conclude which devices were  already allocated to gateway, and what is the newly created device in the network.

```
# => from the Host OS
$ arp -a -n
? (192.168.0.28) at xxxxxxxxxxxxxxxxx on en0 ifscope permanent [ethernet]
? (192.168.0.29) at xxxxxxxxxxxxxxxxx on en0 ifscope [ethernet]
? (192.168.0.32) at xxxxxxxxxxxxxxxxx on en0 ifscope [ethernet]
? (192.168.0.90) at xxxxxxxxxxxxxxxxx on en0 ifscope [ethernet]
```

**Power and Boot up** your SBC, in my case, a Banana Pro w/ ARM context. Wait around ~5 minutes or so for a Operating System to boot up. In the meantime, you can continuesly `ping` the defined static IPv4 of the Armbian OS, and also dump Address Resolution Network again, to see if the new device has been added in the list.

```
$ arp -a -n
...
? (192.168.0.38) at xxxxxxxxxxxxxxxxx on en0 ifscope [ethernet]
```

Ah-ha! There it is.



