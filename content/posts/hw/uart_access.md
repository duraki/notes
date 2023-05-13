---
title: "UART Interface"
---

Part of the [Hardware Hacking](/hardware-hacking) series. *Universal Asynchronous Receiver/Transmitter* (UART) is commonly found in embedded devices, used for the following tasks:

* Send and receive data from devices
* Updating firmware manually
* Debugging and Testing
* Interfacing with underlying systems, and so on ..

The UART works by communicating through two wries (a tranismitter wire, and a receiver wrie), to talk to the microcontroller (MCU) or System on a Chip (SoC) directly. UARTs can be configured for:

- Simplex (One-way Communication)
- Half-duplex (Two-way Communication)
- Full-duplex (Two-way communication Simultaneously)

At minimum, its required to connect two pins: The **TX** and **RX** pins. These two pins need to be crossed between the two devices. The reason for this, and an example is covered in the next section. However, it's recommended that three pins are connected: The **TX** and **RX** pins, plus the **GND** pin, so the serial device and used adapter share a common ground. Generally, hooking up the VCC pin can be skipped, as it’s seldomly needed for testing/hacking purposes since its likely that the device will be powered on. If in doubt, skip hooking the VCC up unless you have a known reason for doing so.

**Crossing the TX and RX Pins** means that the busline wires should be connected in reverse order, because the transmit pin (TX - Out) needs to be connected to the receive pin (RX - In) on both devices. Figure below graphically shows how to cross connect TX and RX pins between the devices:

{{< imgcap title="UART Pins Crossing - Connecting RX to TX and TX to RX between Device 1 and Device 2" src="/posts/hw/uart_crossing.png" >}}

{{< details "Data available on UART" >}}
What sort of data is UART used to communicate depends on the device. Sometimes it might just be real-time sensor readings or logs.  An example of this might be a device such as an IC that is designed to provide some sort of sensor reading, or an MCU that is sending debug messages for diagnostics purposes. Another common type of data you might see when interfacing with UART is diagnostics and calibration menus.  While not a full shell, these are often found on devices for factory or field technicians to help troubleshoot or fix common issues with a device.  Sometimes there can be useful information or neat hidden features here.  This can also provide a possible attack vector for memory corruption bugs since this is being provided by the firmware and likely has not been hardened against software attacks, since only technicians should be using it. Fairly common thing to see on a UART interface in embedded devices - a full Linux `/bin/sh` terminal and can allow you to watch and/or interrupt the bootup (usually UBoot).  Once booted it often turns into a BusyBox `/bin/sh` shell.
{{< /details >}}

### Identify UART Interface

When looking for UART interfaces, they are typically identified by searching for four (4) pads/pins close to MCU/SoC of the targeted Device/PCB/Board.

{{< imgcap title="Identifying Debugging Interface - Linksys WiFi Router" src="/posts/hw/uart_pinouts_sample_wrt_router.png" >}}

In above example, the debugging pins are easy to identify since the pin header is already soldered, and the interface contain four pins - indicating that this is most probably an UART interface. Alterantively, the PCB can contain pads for the UART interface, but not the pin header itself, and the interface may contain more then 4 pads, such is example below, showing UART interface for of an old TP-Link Wireless Router:

{{< imgcap title="Identifying Debugging Interface - TP-Link WiFi Router" src="/posts/hw/uart_pinouts_sample_tplink_router.png" >}}

Another example taken from the Scientific Atlanta (Cisco) EPC2100R2 modem, which contains an UART interface (left), and a (presumably) 8-pin JTAG interface (right):

{{< imgcap title="Identifying Debugging Interface - TP-Link WiFi Router" src="/posts/hw/uart_pinouts_sample_cisco_modem.png" >}}

Besides, you may also identify other debugging interfaces on the targeted device, such is a J-Link Interface (20 pins), MIPS EJTAG (14 pins) and so on. 

{{< notice >}}
Helpful Tip
{{< /notice >}}
{{< callout emoji="💡" text="Once the UART interface have been identified, it's recommended to solder a pin headers on available pads for ease of use." >}}

After you've identified UART interface on the targeted PCB, continue by identifying UART pinouts (below).

{{< imgcap title="Typical UART Schematics (Taken from the Interwebz)" src="/posts/hw/pins_schema.jpg" >}}

### Identify UART Pinouts

Typically, the UART interface won't contain label printed on the PCB, indicating pinouts of the identified interface. A multimeter is needed to determine the pinouts of the possible UART port, or check if this is even an UART pinout to begin with. We will first identify a GND (Ground), and the VCC pin, then we can continue identifying the TX, and RX pin.

**The GND Pin** (Ground)

{{< notice >}}
Helpful Tip
{{< /notice >}}
{{< callout emoji="💡" text="Make sure to turn off and disconnect device from the power supply when identifying ground (GND) pin." >}}

The first pin to determine is the GND or the Ground pin. Easy way to identify the GND pin is by using multimeter's *Continuity* feature. After setting the multimeter to Continuity mode, put the black multimeter probe against the common ground, near the power connection (barrel plug, USB port, battery negative terminal, etc.) or against the metal plate, and put the second (red) multimeter probe against each of the potential UART pins - once a multimeter signals (or *beeps*) continuity on a specific pad, this indicates a ground (GND) connection pin. **Turn off, and disconnect device from the power supply**. Make sure to write down that pin and label is as a ground (GND) pin. 

{{< details "Show: Using Multimeter to identify GND" >}}
![Identifying UART Pinouts - GND (Ground) Pin](/posts/hw/find-gnd.png)
{{< /details >}}

**The VCC Pin** (Power)

{{< notice >}}
Helpful Tip
{{< /notice >}}
{{< callout emoji="💡" text="You may need to reboot device and/or record the voltage readings as the device is booting up, to properly identify VCC pin." >}}

Once a GND (Ground) pin has been identified, one can determine which of the pins is related to VCC. Make sure to **turn on, and connect device to the power supply** to be able to identify VCC pin. Put the multimeter in DC voltage mode (ie. 20V) and place the multimeter black probe against the early identified GND pin. Then, using the positive test lead, poke at the other available pins or pads on the tested board. We are looking at steady, constant voltage readings of either 5 volts or 3.3 volts. 

{{< notice >}}
Helpful Tip
{{< /notice >}}
{{< callout emoji="💡" text="It's not strange to see other pins providing a voltage readings, but they might not be constant and steady, but instead will fluncuate up and down, depending on the data." >}}

{{< details "Show: Using Multimeter to identify VCC" >}}
![Identifying UART Pinouts - VCC (Power) Pin](/posts/hw/find-vcc.png)
{{< /details >}}

**The TX (Transmitter) Pin** (TX/RX)

{{< notice >}}
Helpful Tip
{{< /notice >}}
{{< callout emoji="💡" text="You may need to reboot device and/or record the voltage readings as the device is booting up, to properly identify VCC pin." >}}

Now that we have both the VCC and GND pins of the UART interface, we can move on to identify transmit (TX) and receive (RX) pins. Again, make sure to **turn on, and connect device to the power supply** - and while the device is still powering up (or booting), put the black lead of the multimeter against the GND pin identified earlier, and poke the remaining pins with red probe of the multimeter. If the voltage readings fluctuates between 1V and 2.5V, thats a clear signal that the device is sending something down that pin, indicating a TX pin. If you think about it, when a device boots up, it sends lots of text to the console; and that is where we are seeing these voltage fluctuations. 

{{< details "Show: Using Multimeter to identify TX" >}}
![Identifying UART Pinouts - TX (Transmitter) Pin](/posts/hw/find-tx.png)
{{< /details >}}

**The RX (Receiver) Pin** (TX/RX)

Usually, the last pin that was not identified in the steps above - indicates the actual Receiver (RX) pin of the targeted device UART interface. Sometimes, the available debugging interface will have five (5) available pins or pads for the UART interface, and one can usually trace the leftover (unused) pad, and see where it leads to. Example image below shows identified VCC and GND pins, as well as RX and TX pins, with a single pad unidentified (indicated by the questionmark symbol). By tracing PCB lines of the unknown pin, we can see it doesn't lead anywhere, therefore we can conclude this is another ground (GND) pin left by manufacturing process.

A simple way to identify an RX pin is to also measure voltage readings and look for steady high voltage without any fluctuations. This can indicate RX pin when meassured correctly.

{{< details "Show: Available UART Pinouts" >}}
![Identifying UART Pinouts - Available Pinouts](/posts/hw/pinouts.png)
{{< /details >}}

{{< notice >}}
Helpful Tip
{{< /notice >}}
{{< callout emoji="💡" text="It's not uncommon for some devices (ie. TP-Link) to cripple the RX pin. It might be needed to install a component (usually a resistor), or short two solder pads to make it work." >}}

---

It is possible to use Arduino Uno, flashed with @securelayer7's [PinNinja](https://github.com/securelayer7/PinNinja) firmware, which allows for easy UART identification, simply by connecting the potential UART pins with Arduino's A0-A3 GPIO in any order and opening Serial Monitor. The Serial Monitor should display results indicating which pin is connected to each of the Arduino analog pin.  

### Attaching to UART Interface

Once all pins have been successfully identified, we can continue interfacing UART with a PC. To start off, solder a pin header on the pads exposing the UART interface, so we can easily attach or deattach jumper wires from the tested device, to our UART adapter. An adapter is required to connect UART interface to the computer, called **USB to UART** adapter. Example below uses HW-409 adapter based on CP2102 module, and it's available for cheap on Amazon.

{{< notice >}}
Helpful Tip
{{< /notice >}}
{{< callout emoji="💡" text="To access serial device TTY ports via UART to USB adapter, make sure to install right driver and the software. I use Prolific PL2303 driver for MacOSX. Please, take a look at: https://pbxbook.com/other/mac-tty.html." >}}

Connect the adapter to the known and identified pin layout, and **don't forget to cross the RX and TX** pins, as shown in image below.

{{< imgcap title="Pin Crossing - Connecting UART adapter with tested device" src="/posts/hw/uart_conn.png" >}}

Once the headers are connected to the target device, connect the USB adapter to the computer. You will need to power on and boot the tested device, and look for the virtual serial adapter (*tty*) on the Host OS:

```
$ ls /dev/*usbserial*
/dev/cu.usbserial-0001
/dev/tty.usbserial-0001
```

{{< details "Device Interface: CU and TTY" >}}
In Unix and Linux environments, each serial communication port has two parts to it, a `tty.*`, and a `cu.*`. The difference between the two is that a TTY device is used to call into a device/system, and the CU (call-up) is used to call out of a device/system. Thus, this allows for two-way communication at the same time (known as *full-duplex*). This is more important to know when you are analyzing network communications through a terminal or other program. For the purpose of these notes, always use the tty option for serial communication.
{{< /details >}}

We need to determine the baudrate used by the tested device or hardware, and we can do so using [SickCode's python3-baudrate](https://github.com/sickcodes/python3-baudrate) script. This script is used to connect to the serial device and allow to cycle through common baud rates. To use the script, power cycle the device so it starts spitting out the data of the boot sequence text, and step through various baud rates till it's possible to see a readable text. Take a note of the identified actual baud rate, which we will use later on during the debugging process.

Installing `python3-baudrate`:

```
$ git clone https://github.com/sickcodes/python3-baudrate
$ cd python3-baudrate
$ pip install -r requirements.txt
$ sudo python baudrate.py -h
```

Using `python3-baudrate`:

```
$ sudo python baudrate.py -p /dev/tty.usbserial-0001
```

Google can come handy when searching for correct baudrate, as well as correct stopbits, databits and parity. Write down identified baudrate for the serial interface, and then use software such is `tio` to connect to serial device:

```
$ tio /dev/tty.usbserial-0001 --baudrate 115200 --databits 8 --parity none --stopbits 1
# [20:19:01.879] tio v2.5
# [20:19:01.880] Press ctrl-t q to quit
# [20:19:01.891] Connected
```

**Standard Baud Rates:**

* **More common**: 9600, 19200, 28800, 57600, 115200
* **Less common**: 300, 600, 1200, 1800, 2400, 3600, 4300, 7200, 14400, 39400, 230400

**Resources:**

* [Topmark/Part Marking Database](https://alltransistors.com/smd-search.php)
* [Maxim Topmark Database](https://www.analog.com/en/about-adi/quality-reliability/material-declarations.html)
* [Texas Instruments Topmark Database](https://www.ti.com/packaging/docs/partlookup.tsp)
* [SOT Packages](https://www.topline.tv/SOT.html)

**References:**

* [Hardware Reversing with the TP-Link TL-WR841N Router](https://www.zerodayinitiative.com/blog/2019/9/2/mindshare-hardware-reversing-with-the-tp-link-tl-wr841n-router)
* [Accessing and dumping firmware through UART](https://www.arashparsa.com/dumping-firmware-201/)
* [Getting UART shell in TP-Link Tapo C200 Camera](https://www.hacefresko.com/posts/tp-link-tapo-c200-unauthenticated-rce)
* [Gaining Root via UART](https://konukoii.com/blog/2018/02/16/5-min-tutorial-root-via-uart/)
* [Hardware Hacking and getting the UART shell of TP-Link WR841NV14](https://rickconsole.com/posts/hardware-hacking-tp-link/)
* [Getting shell on TP-Link TD864W](https://denizariyan.com/getting-shell-on-tp-link-td864w-modemrouter-combo)
* [Hunting for Debug Ports](https://jcjc-dev.com/2016/04/08/reversing-huawei-router-1-find-uart/)
* [Router Analysis: UART Discovery and SPI Flash Extraction](https://wrongbaud.github.io/posts/router-teardown/)
* [Dumping and accessing Serial Port on TP-Link Archer AX10](https://github.com/gscamelo/TP-Link-Archer-AX10-V1/blob/main/README.md)
* [MacOS and Serial TTY's](https://pbxbook.com/other/mac-tty.html)