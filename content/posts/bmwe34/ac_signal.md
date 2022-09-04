---
title: "AC Voltage Signals"
---

## Inductive Signals (Induced Voltage)

- Inductive sensors produce an **AC Sine Wave** (*see below*) signal.
- The AC voltage is induced by the shifting of a magnetic field.
- The sensor consists of an impulse wheel (the moving part), and a coil wound magnetic core (stationary part).

As each "*tooth*" (spike) of the impulse wheel approaches the sensor tip, the magnetic field of the sensor shifts toward the impulse wheel and induces a voltage pulse in the windings.

As the teeth move away from the sensor, the magnetic field shifts back inducing a voltage pulse in the opposite direction.

This shifting of the magnetic field produces an alternating current (Positive to Negative).

Control Module(s) which receive this alternating current, count the impulses (*count shifts from positive to negative*), and interpret the speed of rotation of the impulse wheel.

{{< imgcap title="Graphical Flow Diagram of AC Voltage Signal" src="/posts/images/ac-volt-signals-steps.png" >}}

{{< details "Read More" >}}
Note: Voltage levels are dependent on sensor design. Not all inductive sensors produce 12 Volts.
{{< /details >}}

## AC Voltage Sine Wave

{{< imgcap title="AC Type Signals" src="/posts/images/ac-sigs.png" >}}