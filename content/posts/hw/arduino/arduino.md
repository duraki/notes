---
title: "Arduino MCU"
url: "/electronics/arduino"
---

An Arduino board is a commonly used hobby [microcontroller](/electronics/mcu) (MCU).

### Arduino Boards

There are many Arduino (ARV) [MCU](/electronics/mcu)s board models on the market ranging by different specs and functionalities. These are listed below:

- **Arduino Uno** [{{< sup_clean "Image" >}}](https://knowhow.distrelec.com/wp-content/uploads/2021/06/ArduinoUNO_SMD_A000073_30101956-01.jpg)
  - Perfect for beginners, provides basic functionalities
  - Used widely and well documented
  - Based on the ATmega328
  - Includes 14 digital I/O pins (6 pins can be used for PWM outputs) 
  - Includes 6 analogue inputs
  - Includes a 16 MHz crystal oscillator
  - USB connection, Power Jack, an ICSP header & a 'Reset' button
- **Arduino Nano** [{{< sup_clean "Image" >}}](https://knowhow.distrelec.com/wp-content/uploads/2021/06/kh-Arduino-2.jpg)
  - Basic board similar to Arduino Uno
  - Comes in a compact package
  - Does not have DC power jack but works via Mini-B USB cable
  - Breadboard-friendly Development board
  - Ideal choice where the size is leading factor
  - Includes 8 analogue inputs
  - Includes a 16 MHz ceramic resonator
- **Arduino Leonardo** [{{< sup_clean "Image" >}}](https://knowhow.distrelec.com/wp-content/uploads/2021/06/kh-Arduino-3.jpg)
  - A variation of the Arduino Uno board
  - Based on the ATmega32u4
  - Includes a built-in USB communication, eliminating the need for a secondary processor
  - Can appear to a connected PC as a mouse/keyboard (in addition to a virtual (CDC) Serial/COM port)
  - Uses a single microconroller to run both Arduino sketch and for USB-PC comm.
- **Arduino Micro** [{{< sup_clean "Image" >}}](https://knowhow.distrelec.com/wp-content/uploads/2021/06/kh-Arduino-4.jpg)
  - Basic board similar to Arduino Leonardo
  - Can be recognized to a connected PC as a mouse/keyboard
  - Small package, making it easy to integrate into everyday objects
- **Arduino Esplora** [{{< sup_clean "Image" >}}](https://knowhow.distrelec.com/wp-content/uploads/2021/06/kh-Arduino-5.jpg)
  - Based on the Arduino Leonardo board
  - Provides a number of built-in, ready to use set of sensors
  - Has onboard sound/speaker & LED output
  - Has onboard input sensors, a joystick, a slider, temperature sensor, accelerometer, microphone and a light sensor
  - Can be expanded with two Tinkerkit I/O connectors
  - Can be expanded with a colour TFT LCD screen via socket pin header
- **Arduino Due** [{{< sup_clean "Image" >}}](https://knowhow.distrelec.com/wp-content/uploads/2021/06/kh-Arduino-6.jpg)
  - A step-up from boards like Uno, Nano, Leonardo, Micro, and Esplora
  - Based on a 32-bit ARM core microcontroller
  - Perfect board for powerful larger scale Arduino projects
  - Includes 54 digital I/O pins (12 pins can be used as PWM outputs)
  - Includes 12 analogue inputs
  - Includes 4 UARTs (Hardware Serial Ports)
  - Includes 84 MHz clock
  - Includes 2 DAC (Digital to Analog) Converter
  - Includes 2 TWI
  - Integrated Power Jack port
  - Provides an SPI header and a JTAG header
  - Provides an USB OTG capable port
  - Comes with a 'RESET' button as well as 'ERASE' button
- **Arduino Mega 2560** [{{< sup_clean "Image" >}}](https://knowhow.distrelec.com/wp-content/uploads/2021/06/kh-Arduino-7.jpg)
  - Designed for more complex projects
  - Includes 54 digital I/O pins
  - Includes 16 analogue inputs
  - Larger memory space for Arduino sketches
  - Recommended board for 3D printers and robotic projects
- **Arduino Zero** [{{< sup_clean "Image" >}}](https://knowhow.distrelec.com/wp-content/uploads/2021/06/kh-Arduino-8.jpg)
  - Simple and powerful 32-bit extension established by the Arduino Uno
  - Provides increased performance, great educational board to learn 32-bit app. development
  - Used in smart IoT devices, wearable tech, high-tech automation, robotics
- **Arduino MKR** [{{< sup_clean "Image" >}}](https://knowhow.distrelec.com/wp-content/uploads/2021/06/kh-Arduino-9.jpg)
  - Based on MKR Family, this board type is ideal for prototyping IoT projects
  - Integrated connectivity via WiFi, GSM, Narrowband IoT, Lo-Ra, SigFox
  - Small package with dimensions of `67.65x25mm`
- **Arduino Yùn** [{{< sup_clean "Image" >}}](https://knowhow.distrelec.com/wp-content/uploads/2021/06/Arduino_Yun_Rev2_30109897-02.jpg)
  - The Yùn differs from other Arduino boards by its ability to communicate with the Linux distribution onboard
  - Similar to the Arduino Leonardo w/ ATmega32u4
  - Offering a powerful networked computer with the ease of an Arduino
  - Can be used to write custom shell or python scripts for robust interactions
- **Arduino LilyPad** [{{< sup_clean "Image" >}}](https://knowhow.distrelec.com/wp-content/uploads/2021/06/kh-Arduino-11.jpg)
  - Innovative Arduino board designed for wearable technology
  - Eliminates the need for power supply
  - Works just like a regular Arduino

**Specs Overview**

<table style="overflow-x: scroll; font-size: 8px;"><tbody><tr><th>Name</th><th>Processor</th><th><strong>Input Voltage</strong></th><th><strong>CPU</strong></th><th><strong>Analog I/O</strong></th><th><strong>Digital I/O+PWM</strong></th><th><strong>EEPROM [kB]</strong></th><th><strong>SRAM [kB]</strong></th><th><strong>Flash [kB]</strong></th><th><strong>USB</strong></th><th><strong>UART</strong></th></tr><tr><td>Uno</td><td>ATmega328P</td><td>5 V/ 7-12 V</td><td>16MHz</td><td>`6/0</td><td>14/6</td><td>1</td><td>2</td><td>32</td><td>Regular</td><td>1</td></tr><tr><td>Nano</td><td>ATmega168<br>ATmega328P<br>&nbsp;</td><td>5 V / 7-9 V</td><td>16MHz</td><td>8/0</td><td>14/6</td><td>0.5121</td><td>12</td><td>16<br>32</td><td>Mini</td><td>1</td></tr><tr><td>Leonardo</td><td>ATmega32U4</td><td>5 V / 7-12 V</td><td>16MHz</td><td>12/0</td><td>20/7</td><td>1</td><td>2.5</td><td>32</td><td>Micro</td><td>1</td></tr><tr><td>Micro</td><td>ATmega32U4</td><td>5 V / 7-12 V</td><td>16MHz</td><td>12/0</td><td>20/7</td><td>1</td><td>2.5</td><td>32</td><td>Micro</td><td>1</td></tr><tr><td>Esplora</td><td>ATmega32U4</td><td>5 V / 7-12 V</td><td>16MHz</td><td>–</td><td>–</td><td>1</td><td>2.5</td><td>32</td><td>Micro</td><td>–</td></tr><tr><td>Due</td><td>ATSAM3X8E</td><td>3.3 V / 7-12 V</td><td>84MHz</td><td>12/2</td><td>54/12</td><td>–</td><td>96</td><td>512</td><td>2 Micro</td><td>4</td></tr><tr><td>Mega2560</td><td>ATmega2560</td><td>5 V / 7-12 V</td><td>16MHz</td><td>16/0</td><td>54/15</td><td>4</td><td>8</td><td>256</td><td>Regular</td><td>4</td></tr><tr><td>Zero</td><td>ATSAMD21G18</td><td>3.3 V / 7-12 V</td><td>48MHz</td><td>6/1</td><td>14/10</td><td>–</td><td>32</td><td>256</td><td>2 Micro</td><td>2</td></tr><tr><td>MKR1000</td><td>SAMD21 Cortex-M0+</td><td>3.3 V / 5 V</td><td>48MHz</td><td>7/1</td><td>8/4</td><td>–</td><td>32</td><td>256</td><td>Micro</td><td>1</td></tr><tr><td>MKRZero</td><td>SAMD21 Cortex-M0+<br>32bit low power ARM MCU</td><td>3.3 V</td><td>48MHz</td><td>7 (ADC8/10/12 bit) /1(DAC10bit)</td><td>22/12</td><td>No</td><td>32KB</td><td>256KB</td><td>1</td><td>1</td></tr><tr><td>Yùn</td><td>ATmega32U4<br>AR9331 Linux</td><td>5 V</td><td>16 MHz<br>400 MHZ&nbsp;</td><td>12/0</td><td>20/7</td><td>01</td><td>2.5<br>16 MB</td><td><br>64 MB</td><td>Micro</td><td>1</td></tr><tr><td>LilyPad</td><td>ATmega168V<br>ATmega328P</td><td>2.7-5.5 V / 2.7-5.5 V</td><td>8 MHz</td><td>6/0</td><td>14/6</td><td>0.512</td><td>1</td><td>16</td><td>–</td><td>–</td></tr></tbody></table>

### Other Resources

* [Display/LCD Animations on the Arduino (Easeing Functions)](https://andybrown.me.uk/2010/12/05/animation-on-the-arduino-with-easing-functions/)
* [Display/LCD Backlight & Contrast Manager in Arduino](https://andybrown.me.uk/2010/11/28/lcd-backlight-and-contrast-manager/)
* [Setup development environment for ATtiny85 MCUs](https://andybrown.me.uk/2010/11/20/an-attiny85-development-environment/), also read [Introduction to the ATtiny85/45/25](https://andybrown.me.uk/2010/11/07/an-introduction-to-the-attiny854525/)
* [Working with Atmel AVR MCU: Basic PWM Peripheral](https://www.ermicro.com/blog/?p=1971)
* [PIC18 PWM DC Motor Speed Controller w/ RPM Counter](https://www.ermicro.com/blog/?p=1461)
* [Interfacing Neopixel LED Strip with Arduino](https://circuitdigest.com/microcontroller-projects/interfacing-neopixel-led-strip-with-arduino)