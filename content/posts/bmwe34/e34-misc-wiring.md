---
title: "E34 Misc Wiring"
---

### Valuable Schema Diagrams

- 0670-0, represent the power distribution (fuse box in the engine compartment and equipment carrier at the rear)
- 0670-3, the details of the fuse 0670-4, the ground distributors of all consumers
- 0670-5, the diagnostic connection in the circuit diagrams of the various control units. The supply voltage, fuses, and ground connections are not listed in detail 
- 7000, lists all connectors, if necessary with image references and specifications of the connector type
- 7100, installation location of various plugs and components in the form of images
- 8000, overview of the plug connections of the main cable harnesses
- 8500, list all plug connectors with regard to shape and number of poles

**how-to schema readings:** (*Example*)

- Q: How does the MF clock get the Ignition Switch signal (Terminal R)?
  - Circuit diagram for MF clock (6213-2/page 1) shows a plug X501 and goes to fuse F1 via Terminal R (Switching Plus). More at 0670.3
  - Connector X501 (7000/page 29) shows location of X501 (behind the center console), and pin 26, colored green. There is no picture of the position and the plug can be found on 8500/page 1, position 1.
  - On page 0670.3/page 0, if you take a closer look, you will find the N10 module (MF clock) to which the violet-yellow cable you are looking for, i s connected to Pin 8. These colors were not listed in the circuit diagram of the MF clock. It can also be seen that this cable runs via connectors X1428 and X15, to X225, and from there to F1. The switching plus can also be recognized by the designation **"R"**, above the safety symbol.
  - When looking further, at the X15 connector, for example, there is an image that shows that the connector is installed to the left of the instrument cluster (under the dashboard). Incidentally, this is where the harness connects across the dash to the rest of the vehicle. The combination insutrment is not attached to it, but the hazard warning lights, the cigarette lighter, the MF clock or the BC are available and the connection for the auxilary heating/ventilation (8-pin). above the glove component can also be seen.
  - In this way, cable color, cable cross-section (the number next to the color), position (often even with picture) and connector type can be determined.  

### Tacho (RPM) Signal

**Testing the crankshaft sensor**

The crankshaft sensor (RPM sensor) is mounted on the front face. The speed is measured via the "teeth" of the wheel. If the DME does not receive any signals, the engine will not start!

Testing signals is easy as:
- Pulling out the plug
- Measure the resistance value between 1 and 2 with an ohmmeter:
  - M20/M30 : 540 Ohm +- 10%
  - M50/M60 : 1280 Ohm +-10%

The distance sensor to "teeth":
- 1.0 mm (+-0.3mm )

If the resistance value is not correct, then the sensor is defective and the motronic cannot evaluate it.

### Speed Impulse/Signal

With the E34, the speedometer signal is located in the radio connector, as well as dashboard cluster. There is detailed pinout for [dashboard cluster](/e34-pinout-diagram). The BMW radio signals are [described below](#bmw-radio-pinout), including details for wires.

**Testing the crankshaft sensor**

The sensor is mounted on the right hand side of the throttle body, and cannot be adjusted. The motronic sends a voltage signal to the potentiometerm and measures the returned voltage. The voltage decreases as the throttle valve opens.

Test #1 - Measure Voltage at connector:
- Pull off connector
- Ignition on
- Measure voltage at connector. Target value 5V(DC) (approx.)

Test #2 - Measure Ohm of pins:
- Pull out the plug
- Connect an ohmmeter
- Open the throttle valve and measure the values:
  - Pin 1 to Pin 3: approx. 4.0 KOhm
  - Pin 1 to Pin 2: approx. 1.0 to 4.0 KOhm

*Note:* If you now slowly open the throttle valve, the value must change from 1.0 KOhm to 4.0 KOhm (stop to stop). If this is not the case, replace the potentiometer. Valve cannot be adjusted.

### Cell Phone RJ45 Pinout

1) Remove the armest and roll-top box.
2) Locate the RJ45 connector
3) wire up a male RJ45 with the following config:

PIN 1 -> Constant +12V on car kit
PIN 2 -> Switched +12V on car kit
PIN 3 -> Ground on car kit
PIN 4 -> Radio Mute on car kit
PIN 5 -> Speaker + on car kit
PIN 6 -> Speaker - on car kit
PIN 7 -> Microphone + on car kit
PIN 8 -> Microphone - on car kit

4) Connect your male RJ45 to the connector in the console.
5) On the left side of the trunk above the wheel well find the DB25 connector.
6) Using a male DB25 make the following jumper connections:

PIN 1 -> PIN 5 (switched +12V)
PIN 3 -> PIN 24 (Ground)
PIN 4 -> PIN 6 (constant +12V)
PIN 8 -> PIN 14 (MIC +)
PIN 10 -> PIN 18 (Radio Mute)
PIN 11 -> PIN 19 (Speaker -)
PIN 12 -> PIN 25 (Speaker +)
PIN 14 -> PIN 23 (MIC +)

7) Connect your jumper to the DB25 in the trunk.
8) If your car kit has an antenna output connect it to the antenna wire under the console, connect the two antenna wires together in the trunk, and connect your antenna to the wire in the headliner.
9) If you have DSP you may need to apply +12V to the "cell phone present" signal on the DSP amp. My NAV site details the wiring for this, but I don't have the DB25 PIN assignment for that at this time. If the wire isn't obvious when you do the install then shoot me an email and I'll tear into my connector and let you know.

That should just about do it. Your radio should mute when you are on the phone, and your car kit should use the factory audio. BTW the microphone is in the headliner next to the sunroof switch.

{{< details "Archived References" >}}
Refer to [AndrewP's Phone Wiring](http://www.bmwtips.com/tipsntricks/phonewiring/PhoneWiring.htm).
{{< /details >}}


### BMW Radio Pinout

Two types of the radio connector exists in BMW E34s:
* Connector on the Radio
* Multi-plugin Connector

They have different pinouts, as shown below:

{{< imgcap title="Pinouts for BMW E34 Radio (Connector, Multiplug)" src="/posts/images/bmw-radio-pinout.png" >}}

The following table is valid for both versions:

| Pin | Connection                          | More Info                           |
| --- | ----------------------------------- | ----------------------------------- |
| 1   | Front Left Speaker +                |                                     |
| 2   | Front Right Speaker +               |                                     |
| 3   | Rear Left Speaker +                 |                                     |
| 4   | Phone Mute                          |                                     |
| 5   | Positive (+), Terminal R            | From Ignition Lock Stage 1, +12V    |
| 6   | Rear Right Speaker +                |                                     |
| 7   | NOT_USED                            |                                     |
| 8   | Front Left Speaker -                |                                     |
| 9   | Permanent Positive (+), Terminal 30 |                                     |
| 10  | Speedometer Signal                  | For speed-dependent volume controle |
| 11  | Front Right Speaker -               |                                     |
| 12  | Rear Left Speaker -                 |                                     |
| 13  | Lighting, Terminal 58g              |                                     |
| 14  | Rear Right Speaker -                |                                     |
| 15  | Ground, Terminal 31                 |                                     |
| 16  | Automatic Antenna, (HiFi) Amplifier | Switching Output, +12V              |

You can wire BMW speakers with your custom CD-Player, based on the original wires colors *(base color, and the stripe color)*.

Speakers wire connection is as the following:

| Speaker |     | Left   |        | Right |        |
| ------- | :-: | ------ | ------ | ----- | ------ |
| Front   |  +  | Yellow | Red    | Blue  | Red    |
| Front   |  -  | Yellow | Brown  | Blue  | Brown  |
| Rear    |  +  | Yellow | Violet | Blue  | Violet |
| Rear    |  -  | Yellow | Gray   | Blue  | Gray   |
| ------- || ------- || ------- || ------- || ------- |

**Note:** *for newer generation of BMW vehicles (ie. E38, E39, E46, E53), the assignment is the same, except*:

| Pin | Connection                          | More Info                           |
| --- | ----------------------------------- | ----------------------------------- |
| 7   | I-Bus                               | The newly introduced Information Bus|
|  	  |                                     |                                   - |

{{< details "Archived References" >}}
Refer to [BMW Radiostecker (pdf) (ext) (archive)](https://web.archive.org/web/20170828182529/http://www.treffseiten.de/bmw/info/tipp-pdf/bmw_radiostecker.pdf) for wire color (extended table). For CD Changer, refer to [this forum archive](https://web.archive.org/web/20041214001051/https://www.auto-treff.com/bmw/vb/showthread.php?s=&threadid=63422), as well as [Becker TrafficPro <> BMW Pinout](https://web.archive.org/web/20090715084931/http://www.auto-treff.com/bmw/vb/showthread.php?s=&threadid=52963).
{{< /details >}}