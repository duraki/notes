---
title: "BMW AG (E34) Learning Materials"
---

This is Bavarian (*E34 5-series focused*) learning materials and resources, mostly related to ECUs, DMEs, Tuning, EE, Wirings et al. I currently daily-drive BMW E34, therefore I collect [my own repair&restoration](/e34-repair-restoration) techniques. The documentation is written and compiled with different models and versions in mind, but keeping the methodologies of the BMW Technical Documentation collected and researched through the years. Nevertheless, a lot of topics and information presented here are #ReverseEngineered from the very low or no available resources, for years in the past. [Thank me later →](https://twitter.com/0xduraki).

## Table of Content

* [Electronic Signals](/electronic-signals)
* [AC & DC Signals](/ac-and-dc-signals)
* [AC Voltage Signals](/ac-voltage-signals)
* [DC Voltage Signals](/dc-voltage-signals)
  - Analog
	* [NTC Sensors](/ntc-sensors)
	* [PTC Sensors](/ptc-sensors)
	* [Potentiometers](/potentiometers)
  - Digital
	* [B+ Signal](/switched-b-high-signals) 
	* [B- Signal](/switched-b-low-signals)
	* [Square Wave Signals](/modulated-square-wave-signals)
* [DC Digital Sensors](/dc-digital-sensors)
	* [Hall Effect Sensors](/hall-effect-sensors)
	* [Magnetoresistive Sensors](/magnetoresistive-sensors)
	* [Designated Value Signals](/designated-value-signals)
	* [Coded Ground Signals](/coded-ground-signals)
* [DC Digital Input/Output Stages](/dc-digital-io-stages)
* [Signals Table](/signals-table)
	* [E34: Speed Signal](/e34-misc-wiring#speed-impulsesignal)
* [Test your knowledge](/bmw-qa)
* See Also
	* [BMW Acronyms](/bmw-acronyms)
	* [DIN 72552](/din)
* Wiring
	* [Circuit Basics](/circuit-basics)
	* [Circuit Debugging](/circuit-basics#how-to-tracing-the-electrical-issues)
	* [E34 Low Cluster - EURO - MY. 88-90 Test Bench](/e34-cluster-wiring-diagram)
	* [E34 Low Cluster - EURO - MY. 88-90 Pinout](/e34-pinout-diagram)
	* [E34 Misc. Wiring](/e34-misc-wiring)

{{< details "Electronic Signals" >}}
Objectives of the [Electronic Signals](/electronic-signals) is to explain inductive sensors, and type of signals one may stumble upon during the reversing and hacking of BMW E34s and possibly other series as well. Upon completion, you should understand the difference between analog and digital signals, know the difference between NTC and PTC sensors, recognizing different signals on the oscilloscope etc. Besides, many EE stuff can be learn from reading the resources published. [Reference](https://ia801005.us.archive.org/11/items/BMWTechnicalTrainingDocuments/ST051%20Body%20Electronics%20I%20%28Archive%201%29/06%20Electronic%20Signals.pdf)
{{< /details >}}

{{< details "Bus Networks" >}}
**BMW** utiliese Bus Networks on their vehicle. Starting from E38, BMW marked the first large scale usage of bus network on BMW vehicles. For the first time, bus networks are used to reduce overall wiring requirements. More about Bus Systems can be found in the [Power Supply and Bus Systems (pdf) (ext)](https://ia801005.us.archive.org/11/items/BMWTechnicalTrainingDocuments/ST052%20Body%20Electronics%20II/02a_Power%20Supply%20and%20Bus%20Systems.pdf).
{{< /details >}}

{{< details "Automotive Electronics Basics" >}}
[Relays / Starter Interrupts](https://www.the12volt.com/relays/starter-interrupt-diagrams.asp), [SPDT and SPST Automotive Relays](https://www.the12volt.com/relays/spdt-and-spst-automotive-relays.asp), [Resistors](https://www.the12volt.com/resistors/resistors.asp), [Blocking Diodes, Isolating Door Triggers and Sensors, Diodes Across the Coil of Relays](https://www.the12volt.com/diodes/diodes.asp), [Car Audio, Mobile Video, Navigation](https://www.the12volt.com/caraudio/caraudio.asp)
{{< /details >}}

{{< details "References" >}}
[Introduction to Bus Systems](https://ia801005.us.archive.org/11/items/BMWTechnicalTrainingDocuments/ST051%20Body%20Electronics%20I%20%28Archive%201%29/10%20Introduction%20to%20Bus%20Systems.pdf), [Breakout Boxes and Connectors](https://ia801005.us.archive.org/11/items/BMWTechnicalTrainingDocuments/ST051%20Body%20Electronics%20I%20%28Archive%201%29/03%20Breakout%20Boxes%20%26%20Connectors.pdf), [Engine Electronics Overview](https://ia801005.us.archive.org/11/items/BMWTechnicalTrainingDocuments/ST055%20Engine%20Electronics/01_Engine%20Electronics%20Overview.pdf), [Air Management](https://ia801005.us.archive.org/11/items/BMWTechnicalTrainingDocuments/ST055%20Engine%20Electronics/03_Air%20Management.pdf), [Ignition Management](https://ia801005.us.archive.org/11/items/BMWTechnicalTrainingDocuments/ST055%20Engine%20Electronics/05_Ignition%20Management.pdf), [Coding and Programming](https://ia801005.us.archive.org/11/items/BMWTechnicalTrainingDocuments/ST052%20Body%20Electronics%20II%20%28Archive%201%29/2%20Coding%20and%20Programming.pdf), [Wiring Diagram Symbols](https://ia801005.us.archive.org/11/items/BMWTechnicalTrainingDocuments/ST051%20Body%20Electronics%20I/02_Wiring%20Diagrams%20and%20Associated%20Documents.pdf), [Electronic Signals](https://ia801005.us.archive.org/11/items/BMWTechnicalTrainingDocuments/ST051%20Body%20Electronics%20I%20%28Archive%201%29/06%20Electronic%20Signals.pdf), [Coding, Individualization & Programming (CIP)](https://ia801005.us.archive.org/11/items/BMWTechnicalTrainingDocuments/ST050%20Technical%20Systems%20%28Archive%201%29/CIP.pdf), [BMW Technical Training Documents](https://ia801005.us.archive.org/11/items/BMWTechnicalTrainingDocuments/)
{{< /details >}}