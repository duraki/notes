---
title: "Block Diagram"
---

The Block Diagram is a technique used in [PCB and Hardware Reverse Engineering](/hardware-hacking) which investigates BOM (Bill-of-Material) and other Electronic Components used to assemble the PCB. Unlike [Schematics Diagram](/schematics-diagram), this technique tries to identify general workflow of the targeted device or board. The technique follows as:

* Take clean/professional photos of the PCB (*both sides*)
* Go through each of electronic components and identify its purpose
* Label each major component of the PCB:
  - System modules or sensors
  - Identified MCU/SoC/IC on the board
  - Board pins and pads, including available connectors/ports
  - All diodes/transistors/crystals/inductors/PMIC ...
  - All flash storage chips
  - All buttons and switches

Example of the **Block Diagram** traced out is shown below:

{{< imgcap title="Block Diagram - Example during BMW Analog GSM Telephone System RevEng" src="/posts/hw/blockdi-gsm.png" >}}

