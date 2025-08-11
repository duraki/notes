---
title: "Oscilloscope"
url: /hw/oscilloscope
---

This note is still *WIP ~ Work In Progress*.

An oscilloscope is essential piece of test equipment in hardware and electrical labaratories that enable engineers to monitor electrical waveforms. By using oscilloscope, any issues within an electronic circuit can be quickly identified, facilitating the repair of electronic devices.

An oscilloscope is instrument used to display and analyse the waveform of electrical signals. Typically, oscilloscopes display alternating current (AC) or pulsating direct current (DC) waveforms in the form of a graph where time is displayed on horizontal scale (from left to right), alongside instantaneous voltage oscillation on the vertical scale.

Oscilloscopes measure characteristics relating to both **timing** and **voltage**, that is:

- **Timing**
  - Frequency & Period: Indicates a number of times that a waveform repeats per second. The period is the number of seconds that each repeating waveform takes.
  - Duty cycle: The percentage of a period for which a wave is either *positive* or *negative*. Measured as a ratio, the duty cycle indicates how long a signal is at "HIGH/ON", versus how long it is at "LOW/OFF" in each period.
  - Rise & Fall: When a signal moves from a LOW point to a HIGH point, this is referred to as the **rise time**, while in reversed scenarios indicates being the **fall tinme**.
- **Voltage**
  - Amplitude: A measure of the magnitude of a signal. While the "peak-to-peak" amplitude measures the absolute difference between a HIGH voltage and a LOW voltage point of a signal, the "peak amplitude" only calculates how HIGH or LOW a signal is, beyond 0V.
  - Max/Min Voltage: Oscilloscopes measure exactly how HIGH, and how LOW the voltage of a signal gets.
  - Mean/Average Voltage: This refers to the calculation of the *average* (signal max. voltage) & *mean* (signal min. voltage) of a signal in general.

### Use case

An oscilloscope is ideal equipment for testing, troubleshooting and researching, the main use case of it is to monitor signal changes in a circuit over specific time. It can be also used to debug [PCB](/electronics/pcb)s and to identify any faults, or to debug I/O that are not working correctly or there are other timing errors.

While an oscilloscope is only used to measure voltage and timing in the circuits, combined with a [transducer](#transducer)[^1], oscilloscopes can be used to measure almost anything.

The oscilloscope is a versatile piece of equipment, and is used extensively by a diverse range of professionals, including automotive technicians, researchers in labratories, hardware hackers, manufacturers, and even engineers in the military and aviation industries, to name a few.

### Usage & Buttons

Digital oscilloscopes have a number of features on the front panel, including:

- Display: This is where the waveforms is shown and enables the user to monitor various elements of the waveform, or change the oscilloscope settings.
- Connectors: Different connectors are visible on the oscilloscope, ranging from the inputs of for each channel, USB & Ethernet ports, and so on.
- Controls: The buttons and knobs on the oscilloscope may include "*Vertical gain/signal input sensitivty*" (measured in `V/cm` where each vertical division represents a number of volts), "*Timebase*" (alerts the speed at which the trace crosses the screen horizontally), "*Triggers*" (allows the stabilisation of repetitive waveforms), etc.

### Types & Features

The way in which an oscilloscope is used alongside its form and size factor describes the model types Commonly, these are usually split into:

- Benchtop: Largest and usually most professional type for hardware labratories
- Handheld: Different size and shapes are available for these scopes, but can be used on-site.
- PC-based: These are commonly also known as [Logic Analyzers]() but may come in other shapes as well

Typical features implemented in the oscilloscope can vary depending on the form, size and price, but most of them implements the following:

* Bandwidth: Describes the range of frequencies that can be measured and are supported by the oscillo. This can range from `50MHz` up to `100GHz` in industrial environments. 
* Sample Rate: This refers to the number of samples that an oscilloscope can obtain *per second*. Devices capable of gathering a large number of samples will display the waveform more clearly and accurately.
* Signal Integrity: This value denotes the ability to represent the waveform accurately, therefore providing important precision and accuracy of the measured values.
* Channels: Oscilloscopes have inputs that can be either [analog](/electronics/analog-signal) or [digital](/electronics/digital-signal). Typically, there are 2x or 4x analogue channels per oscilloscope.
* Probe Compatibility: Probes are used to connect oscilloscope to tested device (DUT). This provides information on what kind of probe is compatible with particular oscilloscope.

Modern oscilloscopes often offer a variety of additional features to the standard functionalities. Depending on the inteded use of the device, certain features may include: storing waveforms for future reference, displaying multiple waveforms at the same time for comparison, spectral analysis, usability with different OS platforms, multicolor display, ability to zoom in/out for more accurate readings, battery power options and so on.


[^1]: Transducer: Used to convert one type of energy into another.

