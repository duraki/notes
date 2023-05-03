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
    * [BMW Sensors Specifications](/dc-digital-sensors)
	* [Hall Effect Sensors](/hall-effect-sensors)
	* [Magnetoresistive Sensors](/magnetoresistive-sensors)
	* [Designated Value Signals](/designated-value-signals)
	* [Coded Ground Signals](/coded-ground-signals)
* [DC Digital Input/Output Stages](/dc-digital-io-stages)
* [Signals Table](/signals-table)
	* [E34: Speed Signal](/e34-misc-wiring#speed-impulsesignal)
* Production Details
    * [Keyword Protocols](/keyword-protocols)
	  - KWP [KW-71](/keyword-protocols#kw71)
    * [Instrument Clusters / Tachometers](/instrument-clusters)
      - [Details: Cluster Low (Normal)](/bmw/clusters/low-normal)
      - [Details: Cluster Low (Redesign)](/bmw/clusters/low-redesign)
      {{< hrsep >}}
      - [Details: Cluster High (Normal)](/bmw/clusters/high-normal)
      - [Details: Cluster High (Redesign/240)](/bmw/clusters/high-redesign)
      - [Details: Cluster High (Redesign 2)](/bmw/clusters/high-redesign-2)
      {{< hrsep >}}
      - [Coding Plugs](/coding-plugs)
* Wiring
	* [Circuit Basics & Debugging](/circuit-basics)
	* [E34 Low Cluster - EURO - MY. 88-90 Test Bench](/e34-cluster-wiring-diagram)
	* [E34 Low Cluster - EURO - MY. 88-90 Pinout](/e34-pinout-diagram)
    * [E34 Headlights Switch Wiring](/headlight-switch-connector-pinouts)
    * [E34 Misc. Wiring](/e34-misc-wiring)
* See Also
	* [BMW Acronyms](/bmw-acronyms)
	* [DIN 72552](/din)
	* [Test your knowledge](/bmw-qa)

**Forums**
* [PCMHacking.NET](https://pcmhacking.net/forums/index.php)
* [Digital-Kaos.CO.UK](https://www.digital-kaos.co.uk/forums/index.php)

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
[Introduction to Bus Systems](https://ia801005.us.archive.org/11/items/BMWTechnicalTrainingDocuments/ST051%20Body%20Electronics%20I%20%28Archive%201%29/10%20Introduction%20to%20Bus%20Systems.pdf), [Breakout Boxes and Connectors](https://ia801005.us.archive.org/11/items/BMWTechnicalTrainingDocuments/ST051%20Body%20Electronics%20I%20%28Archive%201%29/03%20Breakout%20Boxes%20%26%20Connectors.pdf), [Engine Electronics Overview](https://ia801005.us.archive.org/11/items/BMWTechnicalTrainingDocuments/ST055%20Engine%20Electronics/01_Engine%20Electronics%20Overview.pdf), [Air Management](https://ia801005.us.archive.org/11/items/BMWTechnicalTrainingDocuments/ST055%20Engine%20Electronics/03_Air%20Management.pdf), [Ignition Management](https://ia801005.us.archive.org/11/items/BMWTechnicalTrainingDocuments/ST055%20Engine%20Electronics/05_Ignition%20Management.pdf), [Coding and Programming](https://ia801005.us.archive.org/11/items/BMWTechnicalTrainingDocuments/ST052%20Body%20Electronics%20II%20%28Archive%201%29/2%20Coding%20and%20Programming.pdf), [Wiring Diagram Symbols](https://ia801005.us.archive.org/11/items/BMWTechnicalTrainingDocuments/ST051%20Body%20Electronics%20I/02_Wiring%20Diagrams%20and%20Associated%20Documents.pdf), [Electronic Signals](https://ia801005.us.archive.org/11/items/BMWTechnicalTrainingDocuments/ST051%20Body%20Electronics%20I%20%28Archive%201%29/06%20Electronic%20Signals.pdf), [Coding, Individualization & Programming (CIP)](https://ia801005.us.archive.org/11/items/BMWTechnicalTrainingDocuments/ST050%20Technical%20Systems%20%28Archive%201%29/CIP.pdf), [BMW Technical Training Documents](https://ia801005.us.archive.org/11/items/BMWTechnicalTrainingDocuments/), [BMW Sensors Table](https://web.archive.org/web/20130810205612/https://kovsh.com/media/library/312/Sensors%20Europe.pdf)
{{< /details >}}

{{< details "Other Links" >}}
* [IBUS Protocol Reverse Engineering](https://web.archive.org/web/20071022152757/http://www.openbmw.net/bus/)
* [BMW Navigation Systems](https://web.archive.org/web/20050920201133/http://www.openbmw.net/nav/index.html) - [E46 Retrofit](https://web.archive.org/web/20050912001000/http://www.openbmw.net/nav/sys/index.html), [Concepts](https://web.archive.org/web/20050930205915/http://www.ac-schnitzer.de/englisch/produkte/comm_concept/index.htm)
* [BMW PDF Downloads](https://web.archive.org/web/20050830010505/http://www.openbmw.net/downloads/)
* [BMW Programming Tools & CD's](https://web.archive.org/web/20051224055902/http://www.centrallettershop.com/cd.html)
* [BMW AV Connection Pinouts](https://web.archive.org/web/20051023091951/http://www.750i.de/e/av_conns.htm)
* [BMW E38 Navigation System Unit Repair](https://web.archive.org/web/20050828170028/http://www.750i.de/e/repair.htm)
* [BMW K-BUS Data Reader Project](https://web.archive.org/web/20050206003327/http://neiland.com/Kbusproj.htm)
* [BMW Connected iDrive System Reverse Engineering](https://bimmergestalt.github.io/BMWConnectedAnalysis/)
* [BMW i3 API Reverse Engineering](https://shkspr.mobi/blog/2015/11/reverse-engineering-the-bmw-i3-api/)
* [Communicating with the Instrument Cluster](https://hackaday.io/project/334-integrated-rpi-car-audio/log/1078-communicating-with-the-instrument-cluster)
* [Arduino and BMW E46 K/IBUS Interface](https://curious.ninja/blog/arduino-bmw-i-bus-interface-intro/), [Technical Details](https://curious.ninja/project/bmw-e46/e46-k-bus/arduino-bmw-i-bus-interface-technical-details/)
* [BMW E39 INSA, EDIABAS, NCSExpert, DIS, EasyDIS Forum Thread](https://www.bimmerfest.com/threads/making-sense-of-inpa-ediabas-ncsexpert-ncs-dummies-dis-gt1-easydis-progman.561237/page-5)
* [How to use BMW wiring diagrams](https://www.bimmerforums.co.uk/threads/how-to-use-wiring-diagrams.332561/)
* [Serial DSUB-9 and DSUB-25 Connectors](https://tldp.org/HOWTO/Serial-HOWTO-19.html)
* [Oil Pressure in E36 OpenOBC](https://openlabs.co/blog/2014/06/openOBC-oil-pressure)
* [TinyADS DIY Interface for old BMW Diagnostics](https://openlabs.co/OSHW/Tiny-ADS-Interface)
* [BimmerDIY Directory](https://www.bimmerdiy.com), [E36 Start Button](https://www.bimmerdiy.com/diy/e36startbutton/)
* [Injecting UART Messages into BMW Instrument Cluster LCD](https://i-code.net/injecting-custom-uart-messages-into-the-bmw-750il-instrument-cluster-lcd/)
* [Reusing BMW Phone Keypad with Arduino](https://i-code.net/tapping-into-the-bmw-750il-phone-keypad/)
* [E34 Cluster ROM Dump](http://www.bimmerboard.com/forums/posts/490258)
* [rusEFI - Internal Combustion ECU](https://github.com/rusefi/rusefi), (*[w/ BMW E34 Wiring](https://github.com/rusefi/rusefi/wiki/BMW-e34)*)
* [ECU Connectors - Pin Removal Guide](http://vtec.academy/ecu-pin-removal-guide/)
* [Tachocluster EML Control Light Repair](http://bmwe32.masscom.net/johan/eml_bulb/eml_bulb.html)
* [Rear Seat cigarette lighter 🇯🇵](https://dd.jpn.org/BMW_HP/20071125/index.shtml)
* [Under Ashtray LED 🇯🇵](https://dd.jpn.org/BMW_HP/20040829/index.shtml)
* [Alarm Indicator LED on windshield mirror 🇯🇵](https://dd.jpn.org/BMW_HP/20150817/index.shtml), or on [door lock pin](https://dd.jpn.org/BMW_HP/20080705/index.shtml)
* [E34 Electronic DIYs 🇩🇪](http://www.pet-racing.de/E34)
{{< /details >}}
