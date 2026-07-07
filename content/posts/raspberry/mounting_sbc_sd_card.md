---
title: "Mounting SD Cards"
---

# MacOS Instructions

The instructions below are only viable for MacOS based Host operating systems. For Linux, please refer to [/linux-notes].

## Mounting `ext4` Linux partition

[Check MacOS Notes](/macos-notes) for detailed instructions.
**todo:** move the instructions in this document

## Mounting `boot` partition

* Insert your SD Card in the Card Reader 
* Open Terminal and enter following commands

```
# => if one fails, try the other one
$ sudo mount /Volumes/boot -o remount,rw
$ sudo mount -uw /Volumes/boot
```

You should be able to write to `boot` partition now, ie.: `touch /Volumes/boot/hey.txt`. [See Raspberry Pi Quick Guide](/raspberry-pi-quick-guide) on how to enable SSH via this method.

# Linux Instructions

**todo:** add linux instructions, if required.

# Other Tricks

**Labeling OS image on the SD Card**

It is sometimes confusing to maintain large number of SD Cards, over large number of SBCs. To easily identify multiple SD Cards from each other, you can simply create a text file in `/boot` partition of your microSD with meaningful names, ie:

`<sdcard>/boot/os-kali-linux.txt` or `<sdcard>/boot/os-raspbian.txt` are meaningful names, and it's easily identified without needing for a boot. Just insert microSD in your card reader, and open the `/boot` partition.

**Use Simple Authentication**

Use simple user and password authentication across all images, ie: `pi:pi` for all Raspberries, Lemaker's Boards and other SBCs. That way you don't need to remember each and all of them.
  
*hint*: additionally, add the `user:pass` auth combo in the `/boot/os-*.txt` file, described in **Labeling OS image on the SD Card**.

**Set Wi-Fi Network Credentials in `wpa_supplicant.conf`**

In the `/boot/` partition, create a new file `wpa_supplicant.conf`, and save it like this:

```
# => wpa_supplicant.conf
ctrl_interface=DIR=/var/run/wpa_supplicant GROUP=netdev
update_config=1
country=BA
network={
	ssid="The Matrix"
	psk="wifi-password-1234	"
	key_mgmt=WPA-PSK
}
```
