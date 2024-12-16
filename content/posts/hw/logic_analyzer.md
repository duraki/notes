---
title: "Logic Analyzer"
url: /hw/logic-analyzer
---

### Introduction

A Logic Analyzer can help visualize the transmission of data across data lines (bus). It does this by converting the recorded voltages over time, into a series of binary data (1/0). To use a logic analyzer, several steps are required to capture and analyze the data, listed below:

1. Connect probes to the system/device under test (DUT)
2. Set the sampling mode
3. Configure the triggering conditions
4. Acquire signal data
5. Display and analyze waveforms

{{< details "Logic Analyzer vs Oscilloscope" >}}
You may wonder, **what is the difference between a Logic Analyzer vs Oscilloscope**? In the real world, electrical signals are analog (*including the digital ones!*). An oscilloscpe allows viewing analog voltages and how they change over time. Oscilloscopes are best used for evaluating signal integrity and measuring analog circuit performance. On the other hand, Logic Analzyers represent signals in their digital forms: a logical zeros (`0`) and ones (`1`). This is similar to an oscilloscope with a 1-bit resolution. However, most logic analyzers have many more channels than oscilloscopes. Logic analyzers are great tools for viewing digital waveforms, debugging digital communication (e.g. Serial, I2C), and characterizing digital systems with many lines (e.g. FPGAs).
{{</ details >}}

In my hardware reveng lab, I'm using a [DreamSourceLab DSLogic Plus 16 Channel](https://www.dreamsourcelab.com/shop/logic-analyzer/dslogic-plus/) Logic Analyzer alongisde with its' software called [DSView](https://www.dreamsourcelab.com/download/). Continue reading about [DSL DSLogic+](/hw/dslogic-logic-analyzer) on separate note.

{{< imgcap title="DSL's DSLogic Plus @ 16 Channels" src="/posts/hw/dsldsview.png" >}}

---

### Choosing a Logic Analyzer

Choosing a logic analyzer can be a tedious task, since there are many options to choose from, and looking at the various technical specifications can be intimidating. Typically, a PC-based logic analyzers are used nowadays in hardware reverse engineering labs due to its form factor (portability), and modularity. PC-based logic analyzers require host computers to control the capture parameters and display waveforms. Because of the reliance on a host computer for command and control, PC-based analyzers are limited by their connection speed. Be aware of the type of connection available. For example, USB 3.0 offers higher data rates than USB 2.0.

While a separate computer is required to operate the logic analyzer, the software is usually easy to upgrade, and there are several pros of it, like using one or more larger screens to help aiding the debugging process. Additionally, when paired with a laptop, small PC-based analyzers can be extremely portable, which can be advantageous if the DUT is debugged in a circuit, in a car, or at a conference/presentation talk.

When picking up a logic analyzer for hardware reverse engineering lab, take a note of the following:

{{< details "Logic Analyzer Specs" >}}
* **Channel Count:** This spec provides a number of channels available on the logic analyzer. A channel is an input line with the ability to sample and measure a signal. It is not uncommon to find logic analyzers with 8, 16, 32 and more channels. To examine protocols with few signal lines, such as I2C, SPI, Ethernet, USB, CAN and HDMI, a logic analyzer with up to 8 or 16 channels is more then enough. Likewise, if planning to debug parallel communication buses, such as PCI, ATA, and SCSI, one might need a logic analyzer with at least 32 channels. Performing a state mode analysis of digital components, like FPGAs, microcontrollers, and memory, may require many more channels.
* **Sample Rate:** The sample rate determines the shortest interval in which the logic analyzer can take a measurement from each of the signals. For example, a sample rate of 100 MS/s (mega-samples per second) means that your analyzer can sample a signal 100,000,000 times per second. As an example, if one are planning to debug a SPI bus, which can reach up to speeds of 25 MHz, you would want an analyzer with a sampling rate of at least 100 MS/s.
* **Bandwith:** Bandwidth describes the maximum frequency that the front end of the analyzer can handle. Unlike sample rate, the bandwidth is determined by the analog components used in the probes and buffers. Lets say that bandwidth is given by the `-3 dB` point of signal attenuation. That means if one try to measure a signal with this frequency at our logic analyzer's bandwidth, the voltage of the signal will appear `0.707` times its actual level. It's still possible to measure signals with a higher frequency, but they will appear even more attenuated. With a logic analyzer, this might mean missing *logical highs* because the attenuation brings them below the threshold!
* **Voltage:** There are a few things to consider with voltage. First, what is the maximum safe input voltage range on each of your channels? Some analyzers can only handle 0 to 5 V. Others have protection circuitry that allow for higher voltages. As an example, lets say that a logic analyzer that can safely handle `+/- 25V` inputs - as a result - one can use the logic analyzer to debug `RS-232` without any additional circuitry. Second, think about the kinds of logic levels will be working with. If the logic analyzer is only capable of sampling `5V TTL` levels, it might have `2V` as the *logical high* threshold. If one were to connect this analyzer to a `1.8V` logic circuit, it would not be able to detect any logic highs! As a result, pay attention to the voltage threshold(s) listed on the analyzer.
* **Input Impedance:** Most logic analyzers will have a pull-down resistor on each channel that connects the input signal to ground. This provides a level of safety for the analyzer so that the probe is not floating when disconnected from the circuit.
* **Triggering:** Can this logic analyzer be used to set up complex or nested triggers in the logic analyzer's software?
* **Protocol analyzers:** If daily workload includes working with communication buses, the logic analyzer should be able to decode such protocols (e.g. SPI, I2C, USB, Ethernet etc.).
* **Analog Input:** Some logic analyzers can measure and display analog signals similar to an oscilloscope. This can be a useful feature to help with setting up advanced triggers.
{{</ details >}}

Typically, it's recommended to use an industry tested logic analyzer for best results, notably the:
* [Saleae Logic Analyzer - 16 Chan.](https://www.saleae.com/products/saleae-logic-pro-16) - Expensive, albeit the best
* [DreamSourceLab DSLogic Plus - 16 Chan.](https://www.dreamsourcelab.com/shop/logic-analyzer/dslogic-plus/) - Cheaper, very good

---

### Terminology

A few definitions listed below might help you on the jounrey with logic analyzers.

{{< notice >}}
Channels
{{< /notice >}}
{{< callout emoji="💡" text="A single signal line on the DUT. Logic analyzers are capable of monitoring anywhere from 4 to over 100 channels at the same time, depending on the logic analyzer device used." >}}
{{< notice >}}
Threshold
{{< /notice >}}
{{< callout emoji="💡" text="A voltage level set by the logic analyzer or by the user. Voltages detected by the probe below the treshold are assigned a logical zero (0), and voltages above the threshold are assigned a logical one (1)." >}}
{{< notice >}}
Sample
{{< /notice >}}
{{< callout emoji="💡" text="A single data point that is captured by the logic analyzer at particular moment in time. The logic analyzer simultaneously compares the voltages detected on all probes against the threshold, translates them to logicals ones and zeros (1 & 0), and stores the data in memory." >}}
{{< notice >}}
Sample Rate
{{< /notice >}}
{{< callout emoji="💡" text="How fast should logic analyzer record the samples within a given time period. The maximum sample rate for a logic analyzer is often given in the units of megahertz (MHz) or mega-samples per second (Msps); in both cases, a single unit (1MHz or 1Msps) equates to recording one million consecutive samples per second." >}}
{{< notice >}}
Memory Depth
{{< /notice >}}
{{< callout emoji="💡" text="The amount of memory available by the logic analyzer to store the samples. The maximum memory depth for most logic analyzers is often presented as the number of samples which can be stored per channel." >}}
{{< notice >}}
Trigger
{{< /notice >}}
{{< callout emoji="💡" text="The condition(s) necessary that cause the logic analyzer to begin sampling and recording signals data. For example, a rising or falling voltage on a particular channel or a particular pattern of ones and zeros (1 & 0) across multiple channels can be used as triggers." >}}

---

### Controls and Buttons

Usually, these new-age PC-based logic analyzers like Sealea Logic Analyzer, or DSLogic are normally controlled through virtual *knobs*, using the User Interface (UI) of the applicable software used by the logic analyzer device. The old type of logic analyzers are looking similar to big bench oscilloscopes, and often have a display, as well as set of buttons and knobs that allow for further configuration of capturing parameters or navigation.

Most logic analyzers will have a way to set your sampling mode, sampling rate, and triggers. You can tell the logic analyzer to begin recording data with one of the "Execute" buttons. Once data has been captured, you can navigate through it and search for patterns. Using a software applicable for capturing signals data most likely offers a way to scroll through the data, or zoom into certain parts.

---

### Probe Setup

Capturing a clean signal with the logic analyzer is crucial to debugging digital circuit or DUT. Selecting the proper probe and connecting it to your circuit correctly becomes increasingly important at higher frequencies. When you start working with signals over about 100 MHz, you need to consider grounding, probe impedance, and probe location.

---

**Type of Probes**
Most logic analyzer probes can be organized into two categories: **built-in** and **After the Fact**.

{{< details "Expand Probe Types" >}}
* *Built-in Probes:* When designing a printed circuit board (PCB) for the purposes of prototyping, you may consider adding a special footprint for hooking up a logic analyzer connector. By adding a spot for a logic analyzer connector, you can save yourself lots of time by not having to connect dozens of flying lead probes to individual pins on your board. On the down side, you will likely need to remove the connector footprint from the final design of your product. One built-in option is to use a specialized connector that mates to a connector on the analyzer. This requires soldering a component to your board for the express purpose of debugging. Another option is to create a series of test points with mounting holes in a particular pattern. A compression-type connector will clip to the holes and have leads that touch the test points. This method does not require a separate component soldered to the board, but it still requires board space for the footprint.
* *After the Fact Probing:* When debugging a PCB that does not have a built-in logic analyzer connector, you can use "flying lead" probes. These probes are simply wires that you connect to the circuit in any configuration. Often, you will find flying lead probes with attachment heads that have a hook or grabber. These grabbers allow you to connect to a variety of wires, pins, and test points.
{{</ details >}}

---

**Probing Methods**
If you did not build a specialized logic analyzer connector into your PCB, finding a good spot to connect a probe might be tricky. Here are a few ideas to help you:

{{< details "Expand Probing Methods" >}}
* *Directly to Header:* Some flying lead probes are terminated with a 0.100-inch female or male header pin. In these cases, you can simply connect directly to the opposing header on your board. See [this image](https://www.batterfly.com/shop/image/catalog/blog/saleae/logic-analyzer-tutorial-probe-setup/Directly-Header.jpg) for example.
* *Clip to Exposed Wire, Pin or Header:* Many flying lead probes have heads with hooks or grabbers that let you connect to any exposed conductor. For example, you can them to male headers on a board or to wire ends. See [this image](https://www.batterfly.com/shop/image/catalog/blog/saleae/logic-analyzer-tutorial-probe-setup/Clip-Exposed-Wire-Pin-Header_1.jpg) for example. Some electrical components have leads large enough to grab with these probes. Many plated through-hole (PTH) parts and some surface mount devices (SMD) have leads with enough spacing to attach to. Examples include dual in-line packages (DIP) and small outline integrated circuit (SOIC) packages, as shown in [this image](https://www.batterfly.com/shop/image/catalog/blog/saleae/logic-analyzer-tutorial-probe-setup/Clip-Exposed-Wire-Pin-Header_2.jpg).
* *Clip to Test Point:* Some boards have built-in test points for attaching oscilloscope or logic analyzer probes. Test point components do not need to be populated until you need them, and they make connecting to a node much easier. See [this image](https://www.batterfly.com/shop/image/catalog/blog/saleae/logic-analyzer-tutorial-probe-setup/Clip-Test-Point.jpg) for example.
* *Solder Wire to Test Point, Pin, or Trace:* Sometimes, you do not have an exposed wire or lead that you can connect to. In these cases, you will need to add a wire so that you can connect an analyzer probe. Unlike the test point components shown above, some boards have exposed pads for touching with test bed leads. You can solder a wire directly to these test points if you need to probe them. Some fine-pitch SMD components are too small to grab with probes, but you can still solder 30 AWG wires to the leads, as shown in [this image](https://www.batterfly.com/shop/image/catalog/blog/saleae/logic-analyzer-tutorial-probe-setup/Solder-Wire-Test-Point-Pin-Trace_1.jpg). If no test points or exposed leads are available, you can manually scrape away solder mask to expose a trace and solder a thin wire to it, as is [shown here](https://www.batterfly.com/shop/image/catalog/blog/saleae/logic-analyzer-tutorial-probe-setup/Solder-Wire-Test-Point-Pin-Trace_2.jpg). 
{{</ details >}}

---

**Watch for Ground Loops**
Ground loops occur when you have two points of a circuit that are supposed to be at the same reference potential but have a voltage difference between them. This can happen if you have multiple return paths in your circuit back to a common point.

{{< details "Ground Loop Additional Info" >}}
![](https://www.batterfly.com/shop/image/catalog/blog/saleae/logic-analyzer-tutorial-probe-setup/Example-ground-loop.jpg)
{{</ details >}}

These loops act like inductors, and at high frequencies, they start to impede the changing of current. As a result, you will see a decrease in your system bandwidth.

---

### References

* [How to Use a Logic Analyzer @ batterfly.com](https://www.batterfly.com/shop/en/blog-posts/how-to-use-logic-analyzer)
