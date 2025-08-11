---
title: "Analog Signal"
url: "/electronics/analog-signal"
---

An **analog signal** is a type of continuous signal in a form of *wave* that varies smoothly over time, representing data with infinited possible values. For example, sound waves, radio signals, and temperature changes are all using analog signal to represent its value or device/sensor data.

An analog signal uses some property of the *medium* to convery the signal's information. Any information may be conveyed by an analog signal, often such a signal is *measured change* in physical phenomena, such as sound, light, temperature, position, or pressure. For example, in sound recording, changes in air pressure (ie. a *sound*) strikes the diaphragm of a microphone which causes related changes in a voltage or the current in some electric circuit. The voltage or the current is said to be an "analog" of the sound.

Analog signals are more prone to noise and distrotion and they are usually used in [analog electronics](https://en.wikiversity.org/wiki/Analog_electronics). Analog signal can vary in a continuous manner, as opposed to a [digital signal](/electronics/digital-signal) that only takes discrete values.

Reference to [Analog Signal (Wikipedia)](https://en.wikipedia.org/wiki/Analog_signal) page for more details and information. The [sigidwiki.com](https://www.sigidwiki.com/wiki/Category:Analogue) (Signal Identification Wiki) contains a visual representation of analoge signals on different signal samples.

### Analog to Digital (ADC) Convesion

The conversion between the [`Analog<~>Digital Signals`](https://en.wikibooks.org/wiki/Analog_and_Digital_Conversion) is a technique used to convert **Analog to Digital** (**ADC** - *Analog-to-Digital Converter*), and vice-versa, **Digital to Analog** (**DAC** - *Digital-to-Analog Converter*) signals.

The ADC uses so called *resolution* specification, indicating how accurately the ADC measures the analog input signal. Common ADCs are either *8-bit*, 10-bit, and 12-bit. For example, if the reference voltage of ADC is `0V` to `5V`, then an `8-bit` ADC will break it within 256 divisions, so it can measure it accurately up to `5V/256V = 19mV` (*approx.*). In case of a `10-bit` ADC, the break range for same voltage values would be within `5V/1024 = 4.8mV` (*approx.*). Therefore, the `8-bit` ADC wouldn't be able to tell the difference between `1mV ~ 18mV`. Other specifications of the ADCs include *sampling rate* (how fast the ADC can take the readings), among others specs provided by the ADC datasheet.

Reference to blog [Using the ADC of PIC Microcontroller](https://extremeelectronics.co.in/microchip-pic-tutorials/using-adc-of-pic-microcontroller/) for more details on ADC usage in real-world circuits with PIC microcontrollers. Alternatively, reference to [Using ADC of AVR Microcontroller](https://extremeelectronics.co.in/avr-tutorials/using-adc-of-avr-microcontroller/).

Reference to [Visualize ADC data on PC via USART](https://extremeelectronics.co.in/tools/visualize-adc-data-on-pc-screen-using-usart-avr-project/) for detailed tutorial on how to use ADCGraph2 software on WindowsNT via the USART Port.

### Other Resources

* [SerialCouple - Thermocouple ADC](https://blog.thelifeofkenneth.com/2011/06/serialcouple-thermocouple-adc.html): A device that converts thermocouple temperature input into a digital value