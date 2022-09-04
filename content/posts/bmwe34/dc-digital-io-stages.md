---
title: "DC Digital IO Stages"
---

This document presents Input/Output (IO) stages of signals and sensors in [DC Digital Voltage](/dc-voltage-signals).

## Transistor Final Stage Function

- Transistor takes on a number of applications that must be understood to effectively analyze a circuit.
- Transistor during the operation, functions as two parts, much like a relay
- Both the Relay and the Transistor controls high currents with low current signal

{{< imgcap title="Functions of Transistors, and Relays are similar, as can be seen above" src="/posts/images/relay_vs_transistor_stage_functions.png" >}}

The transistor consists of three (3) major sections:
* Base
* Emitter
* Collector

- The **Base/Emitter** functions as the control circuit, activated by the Control Module, **to oversee or control the work**.
- The **Collector/Emitter** functions as the work side of the circuit, **supplying power**, or **switching to work operation**

During the *operation*, the transistor can either be switched ON momentarily; can be supplied a constant power (+) or ground (-). Additionally, the transistor can also be either modulated, or fowarded to supply a [modulated square wave signal](/modulated-square-wave-signals).

{{< imgcap title="I/O both from and to Control Module via Transistor" src="/posts/images/transistor-to_square_wave-or_modulated.png" >}}

### Modulated, Momentary, Constant B- as Input/Output

Lets take an example:

1) The input signal of Control Module "1" is an output signal of Control Module "2".
2) Control Module "2", through activation of its internal transistor, provides a ground input for Control Module "1".
3) The input signal at Control Module "1" is either a momentary/constant signal (i.e. torque convertor signal from TCM to DME), or a modulated signal (i.e. vehicle speed signal ASC to DME).

{{< imgcap title="I/O Stages, as used by Control Module {1, 2}. CM{2} can use, and control Input Signal from CM{1}" src="/posts/images/modulated_constant_b_minus_as_io.png" >}}

### Momentary, Constant B+ as Input/Output Signal

Lets take an example:

1) The input of Control Module "2" is controlled by Control Module "1"
2) Control Module "2" is possible for control through Control Module "1" through internal activation of the transistor
3) Control Module "1" provides power for the input circuit of Control Module "2"

{{< imgcap title="I/O Stages, as used by Control Module {1, 2}. CM{1} can use, and control Input Signal from CM{2}" src="/posts/images/modulated_constant_b_plus_as_io.png" >}}

### Constant B-/B+ to Energize a Component 

> Energizing a component means increasing, storing or providing electrical voltage, or current ot a component.

#### Constant B-

Output function to energize a component. Relay is energized by activation of the transistor inside the module. The transistor provides a ground for the relay coil, related to Control Module.

{{< imgcap title="Energizing a Component, using const. B- signal" src="/posts/images/energize_component_const_b_negative.png" >}}

#### Constant B+

Control Module output function to energize a component. Transistor controls output function of the Control Module. Control Module supplies power to the Relay. The relay is activated by the Control Module, through activation of the transistor which provides a ground for the Relay coil.

{{< imgcap title="Energizing a Component, using const. B+ signal" src="/posts/images/energize_component_const_b_positive.png" >}}

### Modulated B-/B+ To Operate a Component

#### Modulated B-

Output function to operate a component. The idle valve motor is operated by the Control Module through activation of the transistor which provides a ground for the open winding of the valve.

{{< imgcap title="Operate a Component, using const. B- signal" src="/posts/images/modulated_b_neg_component_ops.png" >}}

#### Modulated B+

Output function to operate a component. The motor is controlled by a transistorized function of the Control Module. It provides a modulated voltage, at a specific frequency to the motor. The throttle position is changed by altering the [Duty Cycle](/modulated-square-wave-signals#duty-cycle) of the pulses.

{{< imgcap title="Operate a Component, using const. B- signal" src="/posts/images/modulated_b_pos_component_ops.png" >}}

