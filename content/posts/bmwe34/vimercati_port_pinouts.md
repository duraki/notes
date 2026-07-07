---
title: Headlight Switch Connector Pinouts
---

I first stumbled upon the so-called "Vimercati" connector, in a BMW E34 Headlight Switch, presumably, also found in other older BMW models - while I was working on Interior LED lighting replacement.

This connector is sometimes also called NSW connector switch, and its original part no. ID is `8 351 235.1`, with its internal Vimercati ID Code `549.3340.11`. Below is a photo showing how this connector looks like.

Below are pinouts for two separate switches:

* **Pinouts for Light Switch**
* **Pinouts for Cluster Dimmer**

{{< imgcap title="DD BMW 61318351235.1 Vimercati Connector" src="/posts/images/1_1648_bmw_headlight_switch_vimercati.jpg" >}}

{{< imgcap title="BMW Fog/Light Switch - containing Vimercati Connector" src="/posts/images/bmw_light_switch-s-l500.jpg" >}}

Besides, on my LAB Vehicle 🚙, the plastic Light Switch contains a tachometer cluster dimmer, unlike the above example containing only an LED on a piece of plastic. The dimmer switch has 3 pins, which corresponds to those of typical variable potentiometer - high (Vin+), low (Vout-), and resistance value.

---

### Pinouts for Light Switch

Looking at the BMW E34 scheme diagrams in 'Electrical Troubleshooting Manual', a light switch is described in Plan 6 (6312.0-01) referencing buslines;

{{< imgcap title="Fog Light-switch (by Vimercati) Scheme Diagram (6312.0-01)" src="/posts/images/bmw_schm_diags/6312_0-01.gif" >}}

{{< notice >}}
Important Errata
{{< /notice >}}
{{< callout emoji="⚠️" text="The above scheme diagram is extracted based on 'Fog Light-switch', although similar scheme is used in 'Beam Light-switch'; the difference is that fog-light switch contains only 5 connector pins, unlike the beam light-switch that exposes 11 pins." >}}

Based on above, we can therefore conclude the pinouts for the component S10 "Fog light switch", as following:

Connector **Pin 2** and **Pin 5** lead to a component `6312.0-00` which provides current from towards the Pin 2 - note that the arrow triangle "C" means current flowing path (downwards). 

The wavy line on Terminal **Pin 5** indicates continuation of the line, presumably from Pin 2 busline.

Connector **Pin 1** is described as a circuit reference line for connection to another circuit. For the BMW "ZKE" supported models, the line is leading to A2w Instrument cluster circuit, and also to General Module (GM).

Connector **Pin 4** is described as a current flow passed to component `8312.0-03`.

Connector **Pin 12** is described as a ground distribution designation, ie. the S10 switch is turned off.

**Pinouts**

| **Pin No.#** 	| **Type**                	| **Description**       	|
|--------------	|-------------------------	|-----------------------	|
| **Pin 1**    	| +12V                    	| Positive Terminal (+) 	|
| **Pin 2**    	| +12V                    	| Positive Terminal (+) 	|
| Pin 3        	| UNKNWN                  	| N/A                   	|
| Pin 4        	| To circuit LBL 63120-03 	| Current Flow          	|
| **Pin 5**    	| +12V                    	| Positive Terminal (+) 	|
| Pin 6        	| UNKNWN                  	| N/A                   	|
| Pin 7        	| UNKNWN                  	| N/A                   	|
| **Pin 8**    	| +12V                    	| Positive Terminal (+) 	|
| Pin 9        	| NOT_USED                	| NOT_USED              	|
| Pin 10       	| UNKNWN                  	| N/A                   	|
| Pin 11       	| UNKNWN                  	| N/A                   	|
| **Pin 12**   	| GND                     	| Ground Distribution   	|  
✮

{{< notice >}}
Test Bench
{{< /notice >}}
{{< callout emoji="🧪" text="Connect all bolded pins to positive power terminal (+12V), and connnect a negative power terminal (-12V) on Pin 12. Place OSRAM 12V 1.2W (T5) LED against two pins in front of the Light Switch, just behind the plastic casing. which creates light switch backlight. The LED should work, indicating successfull test bench." >}}

* [Light Switch Pins 🇯🇵](https://dd.jpn.org/BMW_HP/20090122/index.shtml)

---

### Pinouts for Cluster Dimmer

We can reference to BMW E34 scheme diagrams again to identify jointed circuit on light switch, that describes so called "N3 Dimmer" component. I'm using [MY.'95 Wiring Diagram Schemas](https://www.armchair.mb.ca/~dave/BMW/e34/e34_95.pdf) which disclose these details at schematics `6300.0-00`.

{{< imgcap title="N3 Dimmer (by Vimercati) Scheme Diagram (X517/6300.0-00)" src="/posts/images/bmw_schm_diags/bmw_5_dimmer_circuit.png" >}}

As seen aboce, there are three wires (or pins) on N3 Dimmer connector (*No. X517*), which contains the following pin assignments:

**Pinouts**

| **Pin No.#** | **Type** | **Signal**     | **Description**       |
|--------------|----------|----------------|-----------------------|
| 1            | N/A      | (Empty/No Pin) | N/A                   |
| 2            | E        | +12V           | Positive Terminal (+) |
| 3            | E        | +12V           | Positive Terminal (+) |
| 4            | M        | GND            | Ground Distribution   |
✮  
  
{{< notice >}}
Test Bench
{{< /notice >}}
{{< callout emoji="🧪" text="Connect the N3 Dimmer Pin 4 to Power Supply GND or negative power terminal (-12V). Connect Pin 2, and also Pin 3 to PSU positive power terminal (+12V). The dimmer LED should turn on, emitting low-visible light indicator." >}}

Although the X517 connector on N3 Dimmer contains casing shell for 4 pins, the *Pin 1 does not exists*, and only contains empty space. The pins labeled **Pin 2** and **Pin 3** are positive terminals (12V+), whereas the last **Pin 4** is a Ground Terminal.

In fact, the **Pin 2** is used to control potentiometar inside the N3 Dimmer, and its calculated via base high voltage (Vin+) and base low voltage (Vin-) - by substracting the value of the **Pin 3**. 

{{< imgcap title="N3 Dimmer Pinouts" src="/posts/images/n3_dimmer.png" >}}

