---
title: "Modulated Square Wave Signals"
---

A Modulated Square Wave is a series of High/Low signals repeated rapidly.

{{< imgcap title="A Modulated Square Wave appears as a High/Low signal, repeated rapidly over and over" src="/posts/images/modulated-square-wave-traffic.png" >}}

Like the switched signal [B+](/switched-b-high-signals) and [B-](/switched-b-low-signals), the **square wave** has only two voltage levels. These are: **High Level** and **Low Level**.

A modulated square wave has 3 characteristics that can be modified to vary the required signal:

* Frequency
* Pulse Width
* Duty Cycle

### Frequency

The frequency of a modulated square wave signal is the **number of complete cycles or pulses**, that occur in one second (`fq = O(cycle)^1sec`). This number of cycles (or frequency) is expressed in Hertz (Hz). 1Hz = 1 complete cycle per second.

An output function may use a fixed or varied frequency.

{{< imgcap title="Different number of cycles per one (1) second - e.g. Frequency Herz" src="/posts/images/frequency-hz-example.png" >}}

In the above picture, we can conclude: **if 10Hz/sec** then the sensor operates at frequency of 10Hz, else it's operating on 20Hz, 100Hz and so on.

The **frequency is fixed** if the cycles operating in one second is constant. If cycles operating in one second is not constant, we call them **varied frequency**.

## Typical Application of Fixed and Varied Frequency

* **Fixed**
	- Throttle command from EMS2000 to EDR

* **Varied**
	- Hall Effect Crank Sensor
	- Hall Effect Wheel Speed Sensor
	- Hall Effect Camshaft Sensor

### Pulse Width

The **Pulse Width** of a signal **is the length of time a pulse is running**. Vehicle systems may use fixed or varied **ON** times/pulse width. Pulse width **is expressed in milliseconds** (`ms`).

{{< imgcap title="Pulse Width - Time it takes for a single portion of a Frequency Cycle (in milliseconds)" src="/posts/images/pulse_width.png" >}}

In above example, a period of a full cycle equals to pulse width multipled by twice; (since a cycle has a high cycle, and low cycle) - ON/OFF state.

### Duty Cycle

The Duty Cycle of a [Square Wave](/modulated-square-wave-signals) **is the ratio of ON time to OFF time** for one single cycle. Duty cycle is expressed in percentage (%).

In short, Duty Cycle is the ratio/percentage difference between ON/OFF Pulses. If the Square Wave signal consists of 3/ON pulses, and 2/OFF pulses, the ratio is 3/2, which means the Duty Cycle is ~150% for one signel cycle.

Vehicle systems use both fixed duty cycle signals, and also variable duty signals.

{{< imgcap title="Duty Cycle ratio in different cycle signals" src="/posts/images/duty_cycle_example.png" >}}

**Time**
* 1 second = 1000 milliseconds (ms)
* 1/4 second = 250 milliseconds
* 1/100 second = 10 milliseconds
* 1/2 second = 500 milliseconds
* 1/10 second = 100 milliseconds
* 1/1000 second = 1 millisecond

