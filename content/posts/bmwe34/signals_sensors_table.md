---
title: "Signals Table"
---

### Table

| Symbol | Type | Cycle | Desc. | Function |
| :----: | :--: | :---: | ----- | -------- |
| SQR | A | High / Low | Waveform | Repeated Rapidly |
| B- | D | ON / OFF | ON/OFF input | Low Signal |
| B+ | D | ON / OFF | ON/OFF input | High Signal |
| V+ |   |   | Voltage Positive | Voltage Positive |
| GND |   |   | Ground | Voltage Negative |
  

```
> (where "SQR" - Square-Wave Signal)  
> (where "A" - Analog, "D" - Digital)  
```

### Documentation

* [SQR Signal Documentation](/modulated-square-wave-signals)
* [B- Documentation](/switched-b-low-signals)
* [B+ Documentation](/switched-b-high-signals)

### Bench Test Tricks and Tips

* You can easily send required signal for `B/type` Switches, just by checking the Signal Type of the specific Pin.
* For example:
	- Pin 3, is a "Fuel Level Warning Light" on X13060. It has signal type **B-**.
	- You can ground this pin and the light will turn on, indicating the Fuel Warning.

### Signal Type ⇢ Component Using it

* **Square Wave**
	- Diagnostic Module
	- DME/DDE Control Unit
	- Control Unit
	- Control Module
	- Read Axle reed contact
	- Speed Sensor
* **Switched B+**
	- Ignition Switch
	- Light Switch
	- Reed Switch
	- Seat Belt Switch
	- Hall Effect Switch
	- Brake Light Switch
	- Hazard Warning Relay
	- Fog Light Switch
	- Direction Switch
	- Accessories (ACC) Wire
* **Switched B-**
	- Door Position Switch
	- Window Switches
	- Sunroof Switch

### Terminal Designations

There is a terminal designation for almost every connection of a consumer or switch in the vehicle in order to facilitate the connection. The designation of the individual connections is defined in Germany according to DIN 72552. 

Refer to [DIN 72552](/din) page for more details.

