---
title: "Hall Effect Sensors"
---

Hall Effect Sensors can be used to produce ON/OFF signals or modulated square wave. It's a type of [DC Digital Sensors](/dc-digital-sensors) in DC Signals.

Hall Effect Sensors are electronic switches, that react to magnetic fields, to rapidly control the flow of current or voltage ON and OFF. It is assembled of epoxy filled non-magnetic housing, containing a **hall element**, a **magnet**, and a **trigger wheel**.

The Hall element is a thin, non-magnetic plate which is electrically conductive. Electron flow is equal on both side of the plate.

Since everything between the magnet and the hall element is non-magnetic, the magnet (or magnetic field) has no effect on the current flow.

{{< imgcap title="Hall Sensor Disassembly" src="/posts/images/hall-sensor-disass.png" >}}

*If a solid area or other trigger device approaches the sensor, a magnetic field is created between the magnet and the disk. This magnetic field cause the electron flow to stop on one side of the plate, and continue to flow on the other side.*

1) The Hall Sensor Signal is a measurement of the voltage drop between the two sides of the plate. When the magnetic field increases, the voltage "drop" across the two sides of the plate increases. High voltage on one side, low voltage on the other. The signal output from the sensor is **High**.

2) As the disc moves away from the sensor, the magnetic field weakens and is lost. This loss produces very little voltage drop across the plate sides.The signal output is **Low**. 

A rapid switching of the voltage ON/OFF produces a HIGH/LOW signal that the Control
Module uses to recognize speed and position.

## Typical Application of Hall Effect Sensors
* Crankshaft Sensors
* Camshaft Sensors
* Motor Position and Speed Sensors (e.g. Window Motor, Sunroof Motor)
* ...
