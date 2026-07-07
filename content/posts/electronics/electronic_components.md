---
title: Electrical Components
url: "/electronics/components"
params:
  math: true
---

### Transistors

The transistors are elementary component in all modern electrical systems. They can be used either as a simple switch (ie. to turn `on/off` a device or other component, ie. a `[LED](#led)` et al). Although they are simple in their design, the use of the transistors are various. A "modern" *Pentium*-based CPU has about ~3.5 million transistors, all designed and manufactured differently.

The typical transistor of an electrical system looks like this.

{{< imgcap title="Electrical Transistor (NPN) - Component Example" src="/posts/electronics/_images/LED_tranz_03.jpeg" >}}

The **transistor has 3 pins** (ie. 3 terminals/leads):

- Collector (C)
- Base (B)
- Emitter (E)

The transistor can be a NPN or PNP. If the transistor looks like in example image above, this indicates NPN transistor, meaning if the transistor has the half-cone shape, and if the half-cone shape is looked from the POV, the left side (`C`) is a collector, the right side (`E`) is an emitter, and the middle terminal is a Base (`B`).

The schematics of the `NPN` transistor looks like this (as shown in 3D view example above):

{{< imgcap title="Electrical Transistor (NPN) - Terminal Schematics" src="/posts/electronics/_images/LED_tranz_04.jpeg" >}}

Simple usage of the transistor as an `ON/OFF` switch is made via middle terminal, ie. the Base (`B`). If the electrical current flows into Base, the pathways from Collector (`C`) to Emitter (`E`) will be open. Otherwise, if the current does not flow into transistors' Base (`B`), the pathways will be closed, and no current will flow into it.

Lets take a simple schema to explain this. The following schematics will power `ON` the LED if the [resistor](#resistors) of 2.2k Ohm is connected to "Positive (+)" side terminal.

{{< imgcap title="Powering ON/OFF of the LED via NPN Transistor - Schema Example" src="/posts/electronics/_images/LED_tranz_05.jpeg" >}}

Using a breadboard, this would look similar to following:

{{< imgcap title="Powering ON/OFF of the LED via NPN Transistor - Breadboard Example" src="/posts/electronics/_images/LED_tranz_06.jpeg" >}}

So, if everything is connected correctly, the LED should light up when connected to the 2.2 kΩ resistor to the positive supply terminal (`+`).

**Using it as a switch** in this example, we need to understand **Ohm's law**. In order to calculate how much current flows toward the base of the transistor and through it, we need to know two things about the transistor:

1. When the **transistor is turned on**, the **base voltage is 0.6 V higher than the emitter**.
2. When the **transistor is turned on**, the **collector voltage is 0.2 V higher than the emitter**.

Therefore, when the 2.2 kΩ resistor is connected to 9V DC, the circuit will look like this:

{{< imgcap title="Electrical Transistor (NPN) for ON/OFF switch - Terminal Schematics - LED Example" src="/posts/electronics/_images/LED_tranz_07.jpeg" >}}

The current flowing through the 2.2 kΩ resistor is:

$$
(9 − 0.6) / 2200 = 0.0038 A = 3.8 mA.
$$

The current flowing through the 330 Ω resistor is:

$$
(7.6 − 0.2) / 330 = 0.0224 A = 22.4 mA.
$$

{{< details "Explanaton 💡" >}}
If you want a higher current to flow through the LED, replace the 330 Ω resistor with a smaller one. This does not affect the current flowing into the transistor’s base. From this, we can see that with a very small current we can switch circuits carrying much larger currents, without changing the amount of current at the transistor’s base.
{{< /details >}}

- [Objašnjenje rada tranzistora](https://e-elektro.blogspot.com/2010/04/objasnjenje-rada-tranzistora.html)

### Resistors

Resistor is used in electronic devices to control the flow of an electrical current. The more the resistors value is used, the less electric current will flow, and vice-versa. The resistance value is measured in `Ohm` (commonly using `Ω` (omega) symbol).

Resistors can be placed (ie. *connected*) either in series or in parallel. Read the [`ADALM1000: Series and Parallel Resistors`](https://wiki.analog.com/university/courses/alm1k/intro/series-parallel-2) for more reference and information.

- [How to read resistor values](https://www.ermicro.com/blog/?p=29)
- [DigitalWizard: Resistors](https://digitalwizard.co.in/practical-electronics/resistors)

### Capacitors

Capacitors are two terminal electronic component used to store energy in form of electrostatic field. They are one of the most commonly used components in today PCBs. Amon the many uses, some of them are:

* Providing a bypass path for noise
* Smoothing voltage of a power supply
* Blocking DC current (*allowing only AC current to flow*)

There are few types of capacitors widely available, such are: **Electrolytic Capacitors**, **Ceramic Disk-type Capacitors**, and others.

- [Replacing dead capacitors in consumer electronics](https://blog.thelifeofkenneth.com/2017/07/replacing-dead-capacitors-in-consumer.html)
- [DigitalWizard: Capacitors](https://digitalwizard.co.in/practical-electronics/capacitors)

### Diodes

Similar to resistors and [Capacitors](#capacitors), diodes are very common in various electronics. They are simple components with two terminals on each end. Unlike the resistors, **diodes are polarized**. That means two of its leads on both ends are not equivalent and cannot be swapped - one side is *positive* lead, while the other is *negative*. Typically, a diode is used to disallow draw of current backwards in the engineered circuit.

- [DigitalWizard: Diodes Introduction](https://digitalwizard.co.in/practical-electronics/diodes/introduction)
- [DigitalWizard: What are diodes used for](https://digitalwizard.co.in/practical-electronics/diodes/what-the-diode-does)
- [DigitalWizard: Types of Diodes](https://digitalwizard.co.in/practical-electronics/diodes/types-of-diodes)
- [DigitalWizard: Diode Applications](https://digitalwizard.co.in/practical-electronics/diodes/diode-applications) & [Soldering of Diodes](https://digitalwizard.co.in/practical-electronics/diodes/soldering)

### LED

LED or a Light-emiting diodes is exactly what a typical [Diode](#diodes) is, except that it emits light. The difference between LED and a signal diode is their use of the *voltage* and *current* passed to them. The LED is polarized, one of its leg is used as a VCC while the other is used for ground (GND). Therefore, similarly to signal diode, the LEDs in circuit should not be able to draw current back in the its' circuit.

- [Analog.com: Introduction to Diodes and LEDs](https://wiki.analog.com/university/courses/engineering_discovery/lab_8)
- [Objašnjenje rada LED dioda](https://e-elektro.blogspot.com/2010/04/objasnjenje-rada-led-dioda.html)

### Crystals/Oscillators

The time/timekeeping are quite important in electronic gadgets and devices. The time in electronical devices are measured using frequency. The two commonly used frequency devices utilised in timing applications are **quartz crystals** and **oscillators**.

**Crystals** are passive components and can only function when connected to an external oscillator circuit which is usually present in most [Microprocessors](/electronics/mcu). Quartz crystals are poreferred by experienced engineering designers which provides improved performance. 

**Oscillators** do not require external circuitry to function as it consists of a resonating crystal along with an oscillator IC in a single package. Using oscillators are go-to option for frequency control as they require less design knowledge and are easier to implement in the electronic devices.

- [Crystals & Oscillators Introduction](https://knowhow.distrelec.com/electronics/a-guide-to-crystals-and-oscillators-by-iqd/)
- [What is an Oscillator: Everything you need to know](https://resources.altium.com/p/everything-you-need-know-about-oscillators)
