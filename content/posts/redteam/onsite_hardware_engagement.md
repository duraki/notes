---
title: "OffSec Hardware Fieldkit"
---

### Train Networks Penetration Testing

I've had a chance to prepare and execute penetration testing engagement on one of the European largest train control and monitoring systems, assembled by the ABB Switzerland Ltd. This is the list of stuff I prepared and brung with me. Make sure to note the list of equipment carried by the engagement actor, preferably in the company or embassy invitation letter. There is a potential risk while moving some of the listed equipment in a country where it might be illegal.

- Macbook Pro M1 14"
	- Working Kali Linux virtual machine
	- Working Hardware Emulation vm's (QEMU, UTM, HW IDE)
	- KiCad and other EE documentation
	- Native Wireshark and Emulated Wireshark + tshark
- FTDI USB to RS4xx Converter Cable
- CAT5/6/7 Network Cables
- [Throwing Star Lan Tap](https://shop.hak5.org/products/throwing-star-lan-tap) or [Renkforce Network Switch 5 Port Splitter](https://www.conrad.com/p/renkforce-network-switch-5-ports-100-mbits-1429564)
- CAN Interface with exposed Pin Headers

## Radio Air Network Penetration Testing

During the onsite engagements where I'm testing Wi-Fi Access Point and the subsystems, I'm required to use all of my radio traffic analysis equipment. I'm a sucker for a OnePlus 7T 256GB Android-based Kali NetHunter directly embedded in mobile phone firmware *(rooted device)*. When buying Wi-Fi adapter, make sure to take note on client, monitor, injection, APM, and AHM modes and if they are supported. Make sure to bring at least two (2x) external Wi-Fi interface when on engagement. You never know when you will need to both offer Access Point Mode and also Monitor internal traffic to APM.

- OnePlus 7T 256GB
	- Working rooted Kali Nethunter OS
- Alfa Networks Wi-Fi adapter
- TP-Link Adapter

## Hardware Penetration Testing

My pouch for on-site hardware engagements contain just a simple starting tools that may ease the engagement process. These are few noted that I usually carry on all hardware engagements:

- MTEC Small Wiring Stripper
- Few alligator cables
- USB to Serial/TTL Adapter
- Chip Reader and SOP16/8 to DIP8 Adapter
- Few Protoboards
- Few Resistors of common types
- Small Wire scissors