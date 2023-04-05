---
title: "SBC and Alternatives"
---

This document explains common use during the operation of SBC (Single-board Computers), such is **Raspberry Pi**, **Banana Pi** and others.

Detail instruction for SBC(s) below:
- [Raspberry Pi Installation and Configuration](/raspberry-pi-quick-guide)
- [Banana Pro Installation and Configuration](/banana-pro-quick-guide)

Check [How to mount SD Cards](/mounting-sd-cards) notes for instruction on how to mount `/boot` and `ext4` partitions directly from the Host OS. Some `ext4` partition mounting explained in [MacOS Notes](/macos-notes).

Detailed instructions for [Enabling SSH on Raspbian OS](/enable-ssh-on-raspbian-os) are also available.

### Raspberry Pi GPIO

A powerful feature of the Raspberry Pi is the row of GPIO (general-purpose input/output) pins along the top edge of the board. A 40-pin GPIO header is found on all current Raspberry Pi boards (unpopulated on Raspberry Pi Zero, Raspberry Pi Zero W and Raspberry Pi Zero 2 W). Prior to the Raspberry Pi 1 Model B+ (2014), boards comprised a shorter 26-pin header.

![gpio](https://www.raspberrypi.com/documentation/computers/images/GPIO-Pinout-Diagram-2.png)

Any of the GPIO pins can be designated (in software) as an input or output pin and used for a wide range of purposes.

![pins](https://www.raspberrypi.com/documentation/computers/images/GPIO.png)

> A handy reference can be accessed on the Raspberry Pi by opening a terminal window and running the command `pinout`.

* [GPIO and the 40-pin Headers](https://www.raspberrypi.com/documentation/computers/os.html#gpio-and-the-40-pin-header)