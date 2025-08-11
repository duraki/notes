---
title: "Hardware Hacking"
---

The hacking of consumer electronics also known as *Hardware Hacking* is a process which users perform in order to customise or modify electronic device s beyond what is typically possible. The process of consumer electronics hacking is usually accomplished through modification of the system software, either an operating system or firmware, but hardware modifications are not uncommon.

Multiple methods are used in order to successfully hack the target device, such as gaining shell access, gathering information about the device hardware and software, before using the obtained information to manipulate the operating system.

Simply put, there are two kinds of PCB Reverse Engineering:

* [Block Diagram](/block-diagram) / BOM Level, used to get *general idea of how the hardware works*
* [Detailed Clone](/schematics-diagram) / Schematics or PCB, used to *trace schematics, get low-level overview*

To start the process of the PCB Reverse Engineering, for any of above methods - create a new BOM *(Bill of Material)* table, as presented in figure below or [download the BOM template](https://github.com/durakiconsulting/templates/blob/master/BOM.numbers).

{{< imgcap title="Initializing a new BOM Table" src="/posts/hw/bom.png" >}}

This table will contain a list of components with its designators, as shown on the actual PCB. Designators are small labels usually printed on the PCB, for each of the component. The package for the specific component will contain package for a specific component, and the marking of the component is shown usually on top of the component such is IC or MCU - usually indicating a part number. When looking for designators, the labels can indicate what kind of component it is: **T**/**Q** prefix indicates a *Transistor*, whereas **R** designator indicates a resistor.

**Introduction**

Before you start with any type of hardware hacking, be sure to introduce yourself to [Electronic Components](/electronics/components), as well as notes on [PCB](/electronics/pcb), the use of [microcontrollers](/electronics/mcu) (MCU) such is [Arduino](/electronics/arduino) and practice the very basics until you feel more comfortable to do any type of reverse engineering. The use of [Logic Gates](hw/logic-gates) is always common in various electrical schemas and consumers electronic.

**Signal Analysis**

* [Logic Analyzer](/hw/logic-analyzer)
  * [DSLogic+ Logic Analyzer](/hw/dslogic-logic-analyzer)
* [Oscilloscope](/hw/oscilloscope) *~TODO*

**Common Hardware Debug Interfaces**

* [EEPROM](/eeprom)
* [DP9](/electronics/dp9) & [RS232](/electronics/rs232)
* [UART](/uart-interface) (4 pins)
* [JTAG](/jtag-interface)
  - ARM JTAG - 20 Pins
  - ARM14 JTAG - 14 pins
  - MIPS EJTAG - 14 pins
  - Toshiba MIPS JTAG - 20 pins
  - Standard JTAG - 12 pins
* [RFID](/hw/rfid-interfaace)
* I2C
* SPI
* [Other common](https://www.mattmillman.com/info/crimpconnectors/) WTB (Wire-to-Board), WTW (Wire-to-Wire), and Crimp Connectors
* [DuPont Connectors](https://www.mattmillman.com/info/crimpconnectors/dupont-and-dupont-connectors/)
* [Common JST Connector Types](https://www.mattmillman.com/info/crimpconnectors/common-jst-connector-types/)

![](https://raw.githubusercontent.com/arunmagesh/hw_hacking_cheatsheet/master/cheatsheet_0.1.png)

**Shell Access**

Getting access to a shell allows the user to run commands to interact with the operating system. Typically, a root shell is aimed for, which grants administrative privileges, to let the user modify operating system files. Root access can be obtained through the use of software exploits, through the bootloader console, or over a serial port embedded in the device, such as a JTAG or [UART interface](/uart-interface).

**Unlocking the Bootloader**

On some Android devices, the bootloader is locked for security to prevent installation of other operating systems. Unlocking it is required before another OS can be installed. See [Bootloader Unlocking](https://en.wikipedia.org/wiki/Bootloader_unlocking) Wikipedia page for more details.

**Getting information**

Getting information on the device's hardware and software is vital because exploits can be identified, which is subsequently used to either gain shell access, port an operating system to the device, etc.

**See Also**

- Notes on [Getting UART Access](/uart-interface) to debug embedded device

Things I carry during on-site hardware engagements *(aka the "Fieldkit") are also described in [Hardware Engagement Fieldkit](/offsec-hardware-fieldkit) notes.

**Recommended Books**

- "Practical Electronics for Inventors", by P. Scherz & S. Monk
  - *A foundational book to get a strong understanding of electronics components, circuits, and debugging tools. This serves as the groundwork for hardware reverse engineering.*
- "The Hardware Hacker: Adventures in Making and Breaking Hardware", by A. Huang
  - *Written by one of the best-known hardware hackers, this book explores how to reverse-engineer hardware, including challenges like chip-level reverse engineering.*
- "Hacking the Xbox: An Introduction to Reverse Engineering", by A. Huang
  - *A classic case study of hardware reverse engineering that teaches the fundamental techniques and mindset.*
- "Practical Hardware Pentesting", by J.G. Valle
  - *Focuses on how to identify, analyze, and exploit vulnerabilities in IoT hardware devices using reverse engineering techniques.*
- "Exploring the Raspberry Pi: Interfacing to the Real World with Embedded Linux", by D. Molloy
  - *While Raspberry Pi-focused, this book is a great primer for understanding embedded systems, interfacing with hardware, and hacking IoT devices.*
- "The Art of Electronics", by P. Horowitz & W. Hill
  - *A must-read for anyone serious about electronics, it delves into advanced concepts that are key for understanding and reverse engineering hardware systems.*
- "Car Hacker's Handbook: A Guide for the Penetration Tester", by C. Smith
  - *This is the go-to guide for reverse engineering modern vehicles, explaining CAN bus hacking, firmware analysis, and security testing of automotive systems.*
- "Practical IoT Hacking: The Definitive Guide to Attacking the Internet of Things", by F. Chantzis
  - *While not purely automotive-focused, it explains hardware and software techniques for IoT devices, which overlap significantly with modern connected car systems.*
- "Automotive Embedded Systems Handbook", by N. Navet & F. Simonot
  - *A comprehensive look at embedded systems in vehicles, covering hardware design and software reverse engineering.*
- "

**Online Tools**

- [Altium365 Electronic Design Viewer](https://www.altium365.com/viewer/)

**Misc. References**

- [Embedded Systems](https://en.wikipedia.org/wiki/Embedded_system)
- [ASIC (Application-specific Integrated Circuit)](https://en.wikipedia.org/wiki/Application-specific_integrated_circuit)
- [Bootloader (Boot Manager)](https://en.wikipedia.org/wiki/Bootloader)
- [Embedded Software](https://en.wikipedia.org/wiki/Embedded_software)
- [Microcontroller (MCU)](https://en.wikipedia.org/wiki/Microcontroller)
- [Micro Channel Architecture](https://en.wikipedia.org/wiki/Micro_Channel_architecture)
- [Single-board Computer (SBC)](https://en.wikipedia.org/wiki/Single-board_computer)
- [System on a Chip (SoC)](https://en.wikipedia.org/wiki/System_on_a_chip)
- [What is 'Bus Pirate' and how its used](https://www.bigmessowires.com/2013/11/19/what-is-the-bus-pirate/)
- [List of Tools & Test Equipment](https://old.reddit.com/r/PrintedCircuitBoard/wiki/tools)
- [Upgrading the RAM in a WRT54Gv2](https://blog.thelifeofkenneth.com/2010/09/upgrading-ram-in-wrt54gv2.html), [Failed WRT54G Upgrade](https://blog.thelifeofkenneth.com/2012/02/another-failed-wrt54g-upgrade.html), [Enabling QoS on WRT54G*](https://blog.thelifeofkenneth.com/2012/04/enabling-qos-on-wrt54gl-tomato.html)
- [Teardown of HP ProCurve 2824 Ethernet Switch](https://blog.thelifeofkenneth.com/2013/02/tear-down-of-hp-procurve-2824-ethernet.html)

**Other Links**

- [Analysis of Mitsubishi ETC navigation terminal communication protocol](https://kaele.com/~kashima/car/metc/)
- [Connecting a PC to a Panasonic VGA Navigation System](https://kaele.com/~kashima/car/navi/vga/)
- [Jailbreaking Subaru StarLink](https://github.com/sgayou/subaru-starlink-research/blob/master/doc/README.md)
- [DIY - Wiring in a Headunit (With Bluetooth Modification)](https://www.bimmerforums.com/forum/showthread.php?2195008-DIY-Wiring-in-a-Headunit-(With-Bluetooth-Modification))
- [Display data from ECU to LCD](https://web.archive.org/web/20150815092259/http://www.bimmerforums.com/forum/showthread.php?2134697-Display-data-from-ECU-to-LCD)
- [Tapping into the BMW 750iL's Phone Keypad](https://i-code.net/tapping-into-the-bmw-750il-phone-keypad/)

**Protocols and Interfaces**

- [Series: Serial Communication Protocols - Part 1: Intro](https://resources.altium.com/p/serial-communications-protocols-introduction)
- [Series: Serial Communication Protocols - Part 2: UART](https://resources.altium.com/p/serial-communications-protocols-part-two-uart)
- [Series: Serial Communication Protocols - Part 3: RS-232](https://resources.altium.com/p/serial-communications-protocols-part-three-rs-232)
- [Series: Serial Communication Protocols - Part 4: RS-485](https://resources.altium.com/p/serial-communications-protocols-rs-485)
- [Series: Serial Communication Protocols - Part 5: SPI](https://resources.altium.com/p/serial-communications-protocols-part-5-spi)
- {{< hrsep >}}
- [DIY ATMEL ISP Breakout Board](https://www.ermicro.com/blog/?p=2348)