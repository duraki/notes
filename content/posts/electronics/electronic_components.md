---
title: Electrical Components
url: "/electronics/components"
---

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

### Crystals/Oscillators

The time/timekeeping are quite important in electronic gadgets and devices. The time in electronical devices are measured using frequency. The two commonly used frequency devices utilised in timing applications are **quartz crystals** and **oscillators**.

**Crystals** are passive components and can only function when connected to an external oscillator circuit which is usually present in most [Microprocessors](/electronics/mcu). Quartz crystals are poreferred by experienced engineering designers which provides improved performance. 

**Oscillators** do not require external circuitry to function as it consists of a resonating crystal along with an oscillator IC in a single package. Using oscillators are go-to option for frequency control as they require less design knowledge and are easier to implement in the electronic devices.

- [Crystals & Oscillators Introduction](https://knowhow.distrelec.com/electronics/a-guide-to-crystals-and-oscillators-by-iqd/)
- [What is an Oscillator: Everything you need to know](https://resources.altium.com/p/everything-you-need-know-about-oscillators)
