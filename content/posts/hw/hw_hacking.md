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

**Common Hardware Debug Interfaces**

* [EEPROM](/eeprom)
* [UART](/uart-interface) (4 pins)
* [JTAG](/jtag-interface)
  - ARM JTAG - 20 Pins
  - ARM14 JTAG - 14 pins
  - MIPS EJTAG - 14 pins
  - Toshiba MIPS JTAG - 20 pins
  - Standard JTAG - 12 pins
* I2C
* SPI

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

**References**

- [Embedded Systems](https://en.wikipedia.org/wiki/Embedded_system)
- [ASIC (Application-specific Integrated Circuit)](https://en.wikipedia.org/wiki/Application-specific_integrated_circuit)
- [Bootloader (Boot Manager)](https://en.wikipedia.org/wiki/Bootloader)
- [Embedded Software](https://en.wikipedia.org/wiki/Embedded_software)
- [Microcontroller (MCU)](https://en.wikipedia.org/wiki/Microcontroller)
- [Micro Channel Architecture](https://en.wikipedia.org/wiki/Micro_Channel_architecture)
- [Single-board Computer (SBC)](https://en.wikipedia.org/wiki/Single-board_computer)
- [System on a Chip (SoC)](https://en.wikipedia.org/wiki/System_on_a_chip)
