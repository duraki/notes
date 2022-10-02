---
title: "Circuit Basics"
---

## Types of measurements
There are basically two types of measurements; the **voltage measurement** and the **current measurement**. In addition, there is also the resistance measurement or continuity measurement.

### Voltage measurement
	
With a voltage measurement you can track whether and how far the voltage from the voltage source (usually the battery) is carried to the consumer via the switch and fuse. This is always done parallel to the consumer, unless the circuit diagram gives other options because the lamp z. B. is one-sided to ground (body). Then you can also measure against the body. Also, the consumer does not necessarily have to be connected to ground.

{{< imgcap title="a) Consumer is connected to Ground" src="/posts/images/consumer_conn_to_ground.png" >}}

{{< imgcap title="b) Consumer is connected to Plus (Positive), and is switched to Ground" src="/posts/images/consumer_conn_to_plus_switch_to_ground.png" >}}

If you measure as presented in example (b) above; a diode against the body, you will always measure 12 volts, but diode will not burn.

### Current measurement
If it is determined during a voltage measurement that the load is "live", this still does not mean that it is functional. However, we can check this by measuring the current, by setting the multimeter to measure current and looping the DMM into a live line with both test probes. Again, pay attention to the measuring range and set the DMM to the expected current. If the DMM now shows a current value, we can assume that the load is ok.

## Circuit Diagram Symbols
In order to be able to understand a circuit diagram, you have to know a few basic rules and symbols.

{{< imgcap title="Two lines cross here, but there is no electrical connection" src="/posts/images/sym_line_cross.png" >}}

{{< imgcap title="Only through this point (node) is a connection made between the red and the blue line in the circuit diagram" src="/posts/images/sym_line_conn.png" >}}

{{< imgcap title="Two lines cross here, but there is no electrical connection" src="/posts/images/sym_batterypng" >}}

{{< imgcap title="Battery" src="/posts/images/sym_battery.png" >}}

{{< imgcap title="Resistance (Resistor)" src="/posts/images/sym_resistor.png" >}}

{{< imgcap title="Lamp" src="/posts/images/sym_lamp.png" >}}

{{< imgcap title="Connector" src="/posts/images/sym_connector.png" >}}

{{< imgcap title="Earth Point (Ground)" src="/posts/images/sym_ground.png" >}}

{{< imgcap title="Fuse" src="/posts/images/sym_fuse.png" >}}

{{< imgcap title="Pointer Instrument" src="/posts/images/sym_pointer.png" >}}

{{< imgcap title="Switch" src="/posts/images/sym_switch.png" >}}

{{< imgcap title="Light-emitting diode (LED)" src="/posts/images/sym_led.png" >}}

{{< imgcap title="Relay" src="/posts/images/sym_relay.png" >}}

## Circuit Component Descriptions

### Relay

A relay is an electromechanical component consisting of a coil (wire wound around a metal core) and a contact spring. If a current (excitation circuit) is sent through the coil, a magnetic force is created which attracts the contact spring. This closes the working circuit. The excitation current is very small, a few milliamps. A significantly higher current and voltage can now be switched via the working contact. You could use it e.g. B. switch a 220 volt lamp with a 4.5 volt battery. Since both circuits (4.5 volts and 220 volts) are galvanically isolated, there is no risk of shock. The second application is that you can switch huge consumer currents with relatively weak switches (miniature button in the control panel controls the air conditioning compressor).

### Light-emitting diode or LED
An LED is a colored display. When connecting, you have to pay attention to the polarity, it doesn't light up the wrong way around. The short leg is always connected in the direction of ground. Most of the time, the LED on the side is also somewhat flattened. It may only be operated with a series resistor. If it is operated without a series resistor, it will burn out.

### Troubleshooting

**Calculation of the series of resistor:**

```
LED forward voltage:	 3 volts (depending on color and manufacturer)
LED working current:	 20 mA = 0.02 amps (depending on color and manufacturer)
Operating voltage:		 12 volts

12 - 3
------- = 450 ohms
0.02
```

To make sure resistor doesn't burn, we still have to calculate its power:

```
(12 - 3) x 0.02 amperes = 0.18 watts
```

*Conclusion:* A resistor (450 ohms) and 0.25 watts (standard) is completely sufficient.

## How to: Tracing the Electrical Issues

**Simple debugging w/ Multimeter:**

Lets make an example. Our first attempt consists of a 12V battery, a Fuse F1, a Switch S1, two connectors, and a lamp. The issue we are experiencing is that **the lamp does not light up, although the switch is pressed**. The circuit we are testing will look something like this:

{{< imgcap title="Circuit we are testing, alongside the toolset used" src="/posts/images/multimeter_simple_debug.png" >}}

We take our multimeter and use the input for voltage measurement. Measuring range 15 volts. We hold the black test tip to ground. With the red test tip we measure both sides of the lamp. The display shows 0V for both measurements. 

* This is logical on the right side of the lamp, since this is where we measure mass. 
* However, 12.5 volts should be present on the left side. 

We think of the switch S1 as actuated, ie. closed, and current can flow. The cause could be a defective switch, a blown fuse F1 or a dead battery. We measure again with the red test probe directly on the positive pole of the battery and lo and behold, the multimeter shows 12.5 volts.

Now let's assume that we can't do any more voltage measurements on the fuse. What now? How can we check the fuse? Very simple, we do a **resistance measurement** of the fuse. To do this, we remove them from the "bracket" (ie. where fuses sits at). 

We now switch our multimeter to resistance measurement and hold both test probes together. The meter now reads 0 ohms, which is OK. With this, we have tested the cables and possibly adjusted the multimeter to 0. Now we hold both test probes to the fuse. Here, too, we get almost 0 ohms as a measured value. Hooray, the fuse is ok too. If it were defective, the measuring device would display a value approaching infinity.

After we have reinstalled the fuse, we set the measuring device back to **voltage measurement**. With the probe we now measure both connections of the switch (input and output). Here, too, we get 12.5 volts as a measured value in both cases. Everything is fine it seems, and yet there is no voltage on the lamp? 

Only the two connectors and the cable between them remain. Could this be where the error is? So we disconnect both connectors and again make a resistance measurement at the two ends of the cable. The resistance measurement gives a value towards infinity.

**Aha!** So there is a broken cable and we have found the fault.

To be on the safe side, we can still replace the defective cable with our measuring device. We switch the meter to current measurement, measuring range 1 Amp. We hold the black test tip to the one connector that comes from the switch and the red test tip to the other connector that goes to the lamp. The multimeter shows 0.5 amperes and the lamp burns. The cable is thus clearly localized as the source of the error.



