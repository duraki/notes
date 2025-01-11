---
title: "ECU Programming"
---

### Hardware Cables for ECU readings

The hardware cables is a cable that contain a microcontroller (MCU) that handles the vehicle diagnostic protocol. The software (usually on the *PC*) talks to the hardware cable with a proprietary protocol. This protocol is specific to the cable manufacturer, and the cable itself translates the communication to vehicle protocol equivalent.

* **VW** req. VAG-COM cable
* **BMW** req. INPA/EDIABAS cable *(preferably with K+DCAN switch)*
* **Volvo** req. VADIS cable

### [Binary ECU File Format](/ecu-file-formats)

The file format is a hexadecimal binary file which contains either full or partial (tune) dump. Read more about [ECU File Formats](/ecu-file-formats) on separate note.

### Immobiliser - EWS Bypass

**Internal**: Assuming the donor ECU is the same part #id as the original ECU, the VIN and other keys are stored in the Body Control Module (BCM). The programmer should use "Parameter reset" feature (if supported by flashing device). This feature matches the synchronisation code between the EWS (Immobiliser) inside the BCM and the PCM (ECU). Without these two, matching the PCM would not allow the Start-Stop command on the vehicle, ignition fire, or fuel consumption.

**External**: The average aftermarket alarm car alarm or car immobiliser is usually designed to interrupt the starter, and cut off Ignition, Crank and Fuel.

### Swapping VIN into donor ECU

TBA: *Details*.

### Milage Correction into ECU or Instrument Cluster

* **Peugeot/Citroen** suffer from a bug where BSI gets corrupt and the millage changes to a random value
* **VAG/Landrover** vehicle milage is contained in the Instrument Cluster
* **Mercedes** vehicles have milage stored in the ABS ECU and the Instrument Cluster

---

## Tuning ECU to Stage1-3

### Stage1 - Tuning ECU

The Stage One (Stage1) ECU tuning tweaks contain around 80-120 parameters in the [ECU Binary File](/ecu-file-formats) based on tweak [Lookup Table](/lookup-tables).

### Stage2 - Tuning ECU

TBA: *Details*.

### Stage3 - Tuning ECU

TBA: *Details*.

### References

* [DME Firmware Data Extraction of the ECU Chip](http://alpinakozou.web.fc2.com/file/costomize2011/20110128.html)
* [RX7 FDS3S 16bit ECU Analysis](https://kaele.com/~kashima/car/rx7.html)
* [Synchronous switching of ECU ROM while driving](https://kaele.com/~kashima/car/spre/index.html)
* [ECU ROM Changer that can be switched while driving](https://kaele.com/~kashima/car/rom_ch/index.html)
* [Toyota ECU Toshiba 8X Series Disassembler](https://kaele.com/~kashima/software/tos8x.html)
