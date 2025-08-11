---
title: "BMW AG (E34) Learning Materials"
---

This is Bavarian (*BMW E34 Series 5 focused*) learning materials and resources, mostly related to ECUs, DMEs, Tuning, EE, Wirings et al. I currently daily-drive BMW E34 with M50B20TU engine ([probably on MS40.1](https://web.archive.org/web/20080502043725/http://www.madi-auto.ru/articles/36.html)), therefore I collect [my own repair&restoration](/e34-repair-restoration) techniques. The documentation is written and compiled with different models and versions in mind, but keeping the methodologies of the BMW Technical Documentation collected and researched through the years. Nevertheless, a lot of topics and information presented here are #ReverseEngineered from the very low or no available resources, for years in the past. [Thank me later →](https://linkedin.com/in/duraki/).

## Table of Content

* [Electronic Signals](/electronic-signals)
* [AC & DC Signals](/ac-and-dc-signals)
* [AC Voltage Signals](/ac-voltage-signals)
* [DC Voltage Signals](/dc-voltage-signals)
  - Analog [{{< sup_clean "Analog Signal" >}}](/electronics/analog-signal)
	* [NTC Sensors](/ntc-sensors)
	* [PTC Sensors](/ptc-sensors)
	* [Potentiometers](/potentiometers)
  - Digital [{{< sup_clean "Digital Signal" >}}](/electronics/digital-signal)
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
	* [BMW E34: Speed Signal](/e34-misc-wiring#speed-impulsesignal)
* 🚙 Project Car Notes
    * [BMW E34: Repair & Restoration](/e34-repair-restoration)
    * [BMW E34: Upgradeables](/upgrade-wishlist)
    * [BMW E34: Tools & Equipment](/bmw/tools)
* Production Details
    * [General Modding](/bmw/modding/general)
	  - [ECU Chip Modding](/bmw/modding/ecu)
	  - [Steering Wheel Button Panel](/bmw/modding/steeringwheel)
	  - [RPM Shift LED](/bmw/shifter/led)
   	  - [Misc BMW E34 Tutorials](/bmw/misc/tutorials)
	* [Diagnostic ADS Interface](/ads-interface)
    * [Keyword Protocols](/keyword-protocols)
	  - KWP [KW-71](/keyword-protocols#kw71)
    * [IBUS Protocol](/ibus-overview)
	  - [BMW GSM Phone System](/bmw/gsm-phone)
    * [Instrument Clusters / Tachometers](/instrument-clusters)
	  - [Instrument Cluster: Disassembly](/bmw/clusters/disassembly)
	  - [Instrument Cluster: Communication](/bmw/clusters/communication)
	  - [Instrument Cluster: LCD Display](/bmw/e34/ic/displays)
    	  - [Display: Non-VDO LCD Display](/bmw/e34/small-lcd)
    	  - [Display: VDO LCD Display @ 18 Pins](/bmw/e34/vdo-lcd-18pins)
    	  - [Display: VDO LCD Display @ 11 Pins](/bmw/e34/vdo-lcd-11pins)
	  - [Instrument Cluster: Modding](/cluster-modding-inspiration)
	  - [Instrument Cluster: Control Tachometer KM/H](/bmw/clusters/vehicle-speed)
	  {{< hrsep >}}
      - [Details: Cluster Low (Normal)](/bmw/clusters/low-normal)
      - [Details: Cluster Low (Redesign)](/bmw/clusters/low-redesign)
      {{< hrsep >}}
      - [Details: Cluster High (Normal)](/bmw/clusters/high-normal)
      - [Details: Cluster High (Redesign/240)](/bmw/clusters/high-redesign)
      - [Details: Cluster High (Redesign 2)](/bmw/clusters/high-redesign-2)
      {{< hrsep >}}
	  - [Instrument Cluster: Cluster Conversion](/cluster-conversion)
	  {{< hrsep >}}
      - [Instrument Cluster: Coding Plugs](/coding-plugs)
      - [Instrument Cluster: Engine Temp Gauge](/bmw/e34/engine-temp-gauge)
* Wiring
	* [Circuit Basics & Debugging](/circuit-basics)
	{{< hrsep >}}
	* [E34 Instrument Cluster - Test Bench](/e34-cluster-wiring-diagram)
	* [E34 Instrument Cluster - Pinouts](/e34-pinout-diagram)
	{{< hrsep >}}
    * [E34 Headlights Switch Wiring](/headlight-switch-connector-pinouts)
    * [E34 Misc. Wiring](/e34-misc-wiring)
	{{< hrsep >}}
	* [E34 OBC - On-board Computer](/bmw/e34/obc)
* See Also
	* [BMW Acronyms](/bmw-acronyms)
	* [DIN 72552](/din)
	* [Test your knowledge](/bmw-qa)

**Forums**
* [PCMHacking.NET](https://pcmhacking.net/forums/index.php)
* [Digital-Kaos.CO.UK](https://www.digital-kaos.co.uk/forums/index.php)
* [MHHAuto.COM](https://mhhauto.com)
* [E34M5.DE](https://e34m5.de/)
* [forum.e34.DE](https://forum.e34.de/)

{{< details "The BMW E34 Engines" >}}
**518i M40 (113 hp, inline four-cylinder)**
The 518i is considered an insider tip among the E34s. Many people laugh at it because of its small four-cylinder engine, but it has the lowest maintenance costs in the E34 series. If you can do without engine sound and large power reserves, this engine is a good choice. One disadvantage, however, is the often worn-in camshaft - it often fails after just 100,000 km. As a permanent solution, however, you can install Ingo's sports camshaft with roller rocker arms. This means that worn-in camshafts are a thing of the past and the timing belt has a longer service life, as well as a significant increase in power and revving ability. The valves do not need to be adjusted, as this engine is equipped with hydraulic tappets.

**518i M43 (115 hp, inline four-cylinder)**
Basically the same can be said here as with the M40, but this engine already has roller rocker arms and a timing chain instead of a toothed belt as standard. Another robust engine that should easily manage 250,000 km and more if properly looked after. The M43 is overall a more satisfactory engine than the M40.

**520i M20 (129 hp, inline six-cylinder)**
Anyone who has ever driven this engine (M20B20) in the E30 should imagine it with a few hundred pounds more weight. Nothing works at all in the lower speed range, it only comes to life at around 4500 rpm. In other words, it has to be pushed if it is to move forward, but this is noticeable in the consumption, which is unacceptable given the performance. In addition, numerous engine failures are known to occur with the M20 due to cracked heads and worn camshafts, resulting in broken rocker arms. This can be expected from around 150,000 km. The valve train is driven by a single overhead camshaft via a toothed belt and rocker arms. In return, this engine rewards you with a silky smooth engine run and a very pleasant turbine-like sound, for which BMW inline six-cylinder engines are world famous. However, if you can invest a little more money, the 520i M50 is a better option.

**520i M50 (150 hp, inline six-cylinder)**
The M50 is the successor to the M20 and is one of the most robust engines BMW has ever built. In a slightly modified form, it is still in use today in the 530i E60, for example. This engine has a timing chain, two overhead camshafts (24v), hydraulic tappets and a stationary ignition distribution, i.e. each of the six spark plugs has its own ignition coil. The first problem must be mentioned here: the ignition coils in older M50s stop working over time, and the engine then sometimes only runs on 5 cylinders or less. Currently, only ignition coils from Bremi are sold, and no defects are known. The water pump should also be taken a critical look: initially a water pump with a plastic impeller was installed, which becomes brittle over time and rotates loosely on the shaft. The result: the engine overheats, which can then lead to cracked cylinder heads. It is best to check immediately after purchase; the current versions of the water pump have a carbon fiber or metal impeller, which no longer have this defect. The material costs are also quite bearable at around 80 EUR for the pump. The 520i M50 is also a bit sluggish in the lower speed range, but this was remedied in 9/92: from this point on, the M50 is equipped with VANOS (variable camshaft control), which is noticeable in better low-end torque and slightly lower consumption, which has been significantly reduced compared to the old M20. However, something is now installed that can break, but this usually doesn't happen. A mileage of over 400,000 km should be easily achievable with appropriate care and no previous damage (e.g. overheating due to a defective water pump).

**525i M20 (170 hp, inline six-cylinder)**
The same applies here as with the 520i M20, but this engine not only offers significantly more power in the lower speed range, but also consumes slightly less than the 520i M20. Despite all this, worn-out camshafts, broken rocker arms and cracked cylinder heads are not uncommon here either.

**525i M50 (192 hp, inline six-cylinder)**
The same engine as in the 520i M50 with half a liter more displacement. More torque at the bottom and the same consumption as the 520i M50 make this engine without a doubt the best compromise between cost and performance. 245 km/h according to the speedometer is just as possible as consumption well under 9 liters when driving at a leisurely pace.

**530i M30 (188 hp, inline six-cylinder)**
The design of the M30 dates back to the early 1970s. That's not necessarily a bad thing, you get a robust and powerful engine for little money, but it can't keep up with newer engines like the M50 in terms of fuel consumption. Worn camshafts and cracked cylinder heads have also been seen here, but are nowhere near as common as with the M20. It has a single overhead camshaft driven by a low-maintenance timing chain, but no hydraulic tappets, so like the M20, the valve clearance should be checked and adjusted from time to time. In terms of characteristics, it drives very comfortably, with most of the power being delivered at low and medium speeds. The 530i M30 in particular can often be had for little money and is an alternative to the 525i M50, which is usually a lot more expensive to buy.

**530i M60 (218 hp, V8)**
The M60 was produced in 1992 as the successor to the old M30. As a 3-liter version, it is, however, rather weak in the lower rev range. At high revs it is quite good, but there is not a huge difference compared to the 525i M50. However, the fuel consumption is much higher in the 530i M60. Due to a design error, the 3 screws of the oil pump, which are often already in the oil pan, come loose over time: it is best to have them checked immediately after purchase. The M60 also has timing chains and hydraulic tappets. If you are looking for a V8 sound for relatively little money, this engine is a good choice, but the 525i M50 is undoubtedly more economical and is not significantly worse.

**535i M30 (211 hp, inline six-cylinder)**
The same engine as in the 530i M30 with an increased displacement of 3430 cc, which primarily benefits the pulling power. It is not a miracle in terms of fuel economy, but it can be driven very confidently and calmly, and there is no feeling of underpowering at any speed range. The 535i is also usually available cheaply, as it is at least 11 years old. 350,000 km and more should be no problem, but the insurance amounts are almost at M5 level.

**540i M60 (286 hp, V8)**
Same engine as in the 530i M60, but with 4 liters of displacement. A powerful torque of 400 Nm, you can also drive very relaxed, or try out the standard 250 km/h limit in conjunction with the brilliant V8 sound (240 km/h in early models). A great engine, whose biggest weak point is not the engine itself, but the automatic transmission, which is 95% of the time installed: this cannot handle the torque in the long term and usually gives up between 140,000 and 200,000 km, and a replacement costs a good 3,000 EUR or more. It is best to buy a 540i with the automatic transmission already replaced, or put the money aside, although this should be clearly noticeable in the price. The 540i is also available with a manual 6-speed transmission, but these models are rare, sought after and therefore quite expensive. The same applies here as with the 530i M60 because of the oil pump.

**M5 3.6 S38 (315 hp, inline six-cylinder)**
The M5 is the top model in the E34 series, as anyone who has ever driven one will rightly confirm. It's not just the look of the engine with its 6 individual throttle valves that is in a class of its own. However, an M engine also requires a certain amount of attention and care. The wrong oil and high speeds when the engine is cold are fatal for it, the camshaft is driven by a timing chain. The valves have to be adjusted from time to time as there are no hydraulic tappets installed. Spare parts for this engine are significantly more expensive than for the "normal" engines in the E34. However, if you factor this in from the start, you will have a lot of fun with this engine.

**M5 3.8 S38 (340 HP, inline six-cylinder)**
Basically the same engine as in the M5 3.6, but it has been bored out by another 0.2l, now produces 340hp and has a static ignition distribution like the M50 and M60. However, several sources have said that the 3.8l version does not have the smoothness and durability of the 3.6, and there are frequent reports of replacement engines around the 150,000 km mark.

**524td M21 (115 HP, turbo inline six-cylinder, diesel)**
The M21 belongs to the M20 engine family and unfortunately has the corresponding problems (head crack, worn camshaft), so it also has an overhead camshaft that is driven by a toothed belt and no hydraulic tappets. The 524td was the only diesel engine in the E34 until 1991, but is not particularly widespread, but impresses with its relatively low consumption and pleasant running noise. However, you should not expect the miraculous performance of today's diesel engines from this engine. The engine was also installed in the E28 and E30, but there with a mechanical injection system, which is considered to be more robust.

**525td M51 (115 hp, turbo inline six-cylinder, diesel)**
The 525td was launched in 1991 as the successor to the 524td and is based on the M50 engine family. The performance is the same as that of the 524td, and head cracks and worn camshafts were rarely seen. Without a doubt the more modern engine, although it is also a fairly old diesel and does not have technical refinements such as direct injection or common rail.

**525tds M51 (143 hp, turbo inline six-cylinder, diesel)**
This engine is the same as in the 525td, with two differences: it has intercooling and is the most vulnerable engine in the E34. Cracked cylinder heads, blocks, worn pistons and cylinders and defective injection pumps are unfortunately not uncommon, and in any case they cause repair costs that destroy the economical aspect of diesels in every respect. TDS engines with over 400,000 km have been spotted, but that is definitely the exception, many don't even make it to the 200,000 km mark. It was a rocket by diesel standards 10 years ago, but as a swirl chamber diesel it is already past its performance limit. It is better to make do with a 525td or a 525i M50, which can be driven on 8 liters if driven economically and only costs around 50 EUR more per month even if you drive around 40,000 km per year, but it also has an increase in performance of almost 40 HP.

--
Originally seen on [e34.de](https://www.e34.de/e34/kaufberatung-motorauswahl.htm).
{{< /details >}}

{{< details "Electronic Signals" >}}
Objectives of the [Electronic Signals](/electronic-signals) is to explain inductive sensors, and type of signals one may stumble upon during the reversing and hacking of BMW E34s and possibly other series as well. Upon completion, you should understand the difference between analog and digital signals, know the difference between NTC and PTC sensors, recognizing different signals on the oscilloscope etc. Besides, many EE stuff can be learn from reading the resources published. Click here for the [reference *(PDF)*](https://ia801005.us.archive.org/11/items/BMWTechnicalTrainingDocuments/ST051%20Body%20Electronics%20I%20%28Archive%201%29/06%20Electronic%20Signals.pdf).
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
* [BMW Navigation Systems](https://web.archive.org/web/20050920201133/http://www.openbmw.net/nav/index.html)
* [E46 Retrofit](https://web.archive.org/web/20050912001000/http://www.openbmw.net/nav/sys/index.html), [Concepts](https://web.archive.org/web/20050930205915/http://www.ac-schnitzer.de/englisch/produkte/comm_concept/index.htm)
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
* [Display data from ECU to LCD](https://web.archive.org/web/20150815092259/https://www.bimmerforums.com/forum/showthread.php?2134697-Display-data-from-ECU-to-LCD)
* [Reusing BMW Phone Keypad with Arduino](https://i-code.net/tapping-into-the-bmw-750il-phone-keypad/)
* [E34 Cluster ROM Dump](http://www.bimmerboard.com/forums/posts/490258)
* [rusEFI - Internal Combustion ECU](https://github.com/rusefi/rusefi), (*[w/ BMW E34 Wiring](https://github.com/rusefi/rusefi/wiki/BMW-e34)*)
* [ECU Connectors - Pin Removal Guide](http://vtec.academy/ecu-pin-removal-guide/)
* [Tachocluster EML Control Light Repair](http://bmwe32.masscom.net/johan/eml_bulb/eml_bulb.html)
* [Rear Seat cigarette lighter 🇯🇵](https://dd.jpn.org/BMW_HP/20071125/index.shtml)
* [Under Ashtray LED 🇯🇵](https://dd.jpn.org/BMW_HP/20040829/index.shtml)
* [Alarm Indicator LED on windshield mirror 🇯🇵](https://dd.jpn.org/BMW_HP/20150817/index.shtml), or on [door lock pin](https://dd.jpn.org/BMW_HP/20080705/index.shtml)
* [E34 Electronic DIYs 🇩🇪](http://www.pet-racing.de/E34)
* [DIY Cleaning the MAF Sensor](https://qcwo.com/technicaldomain/my-car-engine-hesitates-when-i-accelerate/)
* [Tips & Tricks for the BMW E34 OBC IV (BC Gen4) and Instrument Cluster](https://www.e34.de/tips_tricks/bctips/bctips.htm)
{{< /details >}}

{{< details "External References" >}}
* [BMW E34 M5 OEM Paint Color Codes](https://www.myclassicparts.com/wp-content/uploads/2021/10/BMW_E34_M5_OEM_PAINT_COLOR_OPTIONS.pdf)
* [BMW E34 OEM Paint Color Codes](https://www.myclassicparts.com/wp-content/uploads/2021/10/BMW_E34_PAINT_CODES_OEM_COLOR_OPTIONS.pdf)
* [BMW E34 M5 OEM Wheel Style Options](https://www.myclassicparts.com/wp-content/uploads/2021/10/07_BMW_E34_M5_Wheel_Style_Specs_Options.pdf)
* [BMW E27/E34 Repair and Maintanence Operations](https://web.archive.org/web/20200808144258/http://www.autoprospect.ru/bmw/e28-e34/)
* [BMW E34 Service and OPeration Manual](https://web.archive.org/web/20190328110037/http://automn.ru/bmw-5-e34/)
* [BMW E34 CCM - Check Control Module](http://www.e34-welt.de/tips_tricks/Reparaturanleitung%20CCM%20e34%20e32.pdf)
* [Unofficial BMW Documents](http://www.unofficialbmw.com/images/)
{{< /details >}}