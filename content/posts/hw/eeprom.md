---
title: "EEPROM"
---

EEPROM (*Electrically Erasable Programmable Read-Only Memory*) is read-only non-volatile memory whose contents can be erased and reprogrammed using a pulsed voltage often time used in embedded systems. EEPROM is used in variety of systems, either to hold firmware data, the bootloader, or among other use cases.

That means that EEPROM is used for storing digital data permantently, without any power supply needed or required to keep the data alive. The advantage of these kind of ROMs is that they can be eased electrically making them ready for storing any kind of new data. Compared to typical `CD-R` disks, EEPROM can be used to re-write and erease the data, unlike the `CD-R` disks which can be used to record data only once.

A small amount of EEPROM is also available on most of the widely popular AVR MCUs. If the value of data you want to store is small, the integrated EEPROM of the AVR can be used. The internal EEPROM integrated in such AVR MCUs makes the final design small and simple.

If the amount of data exceeds the available EEPROM memory, or is in large amounts (ie. few tens of kilobytes), an external EEPROM is required. The external EEPROM would need an interface connection to the AVR MCU if this requirements is necessary.

The data that can be stored in these EEPROMs can vary, depending on the use case. For a fact, EEPROMs can be used to store pictures/images, sound, database, or long text of data.

SOIC8, it’s programming chip which allows embedded software developers to test EEPROM chips not just you can write changes with it but also read existing data from there or you can say dump the firmware easily.

Now next step is to identify model number of our EEPROM chip and it’s orientation on PCB, challenge here is small size. Due to their very small size it is often impossible to see the text written on the chip with naked eyes. What you can do is use soldering microscope or if you don’t have one you can use camera of your smart phone along with flash light hold at 45 degree angle for best viewing experience since direct flash light on chip will make hard to see the text.

... continue reading [here](https://cjhackerz.net/posts/reading-firmware-from-eeprom-easyway/)

**Interface 24C Serial EEPROM via I2C using AVR Microcontrollers**

There are many kind of EEPROM chips available on the market. One very common family is 24C series serial EEPROM. This model of EEPROM is available in different available sizes, up to `128kb` in some models. The 24C series serial EEPROM uses I2C interface with host controller (MCU), which is very popular serial communication standard.

This section will describe usage instructions of the `24C64` EEPROM Chip which has total available size of `8192 bytes` (ie. `8 kilobytes`, since `8 x 1024 = 8192 bytes`).

Typically, EEPROM chips provide a datasheet with internal documentation details. One of the datasheet section indicates a storage location address offset - a unique address which labels storage cells available in the EEPROM. For `24C64` EEPROM chip, the storage location offset is provided in the official datasheet, ranging from/to  `0x0000-0x8191` offset. Consider the space between these address location offsets as a *storage cells*, which will be used later on by the MCUs or firmware to know where the data can be stored or retrieved from. When developing a new firmware/circuit/microcontroller interfacing with EEPROM, these storage cell locations will be used to tell the chip which cell location we want to read/write.

Address Offset    | Data Stored | Description
:---------------: | :--: | ----------------------------------------
0000  |  8   | Starting Address
0001  |  214   |
0002  |  15   |
0003  |  99   |
...  |  ...   |
8191  |  22   | Last Address

For example, if we want to read location at address offset `0x0003` of the EEPROM, the resulting retrieved data would be decimal `99`. Note that each cell can store up to `8 bit`s of data, so the range that might be stored is from `0-255` (ie. `-128` to `+127`). If storing larger data (ie. an `int` - *Integer*) is needed, such value must be stored in two cells.

Hardware setup to read/write and interface with EEPROM chip via AVR MCU (ie. via *ATmega32*) is as following:

{{< imgcap title="24C64 EEPROM Interface via ATmega32 (from: extremeelectronics.co.in)" src="/posts/hw/eeprom/_images/24c64_schematic_avr.gif" >}}

Download and add the files `24c64.[h|c]` to AVR studio project which is used to interface with this EEPROM chip:

* Download [24c64_atmega32.zip](https://www.extremeelectronics.co.in/avrtutorials/download/24c64_atmega32.zip)

Use the C-Lang implemented functions to interface with EEPROM chip:

- `EEOpen()` - Initialize EEPROM communication channel, must be usedf before any read/write operation
- `EEWriteByte(unisgned int address, uint8_t data)` - Store `8bit` value data in any EEPROM storage cell
- `EEReadByte(unsigned int address)` - Read `8bit` value from any EEPROM storage cell

Take a look at [24C EEPROM I2C Serial Communication via AVR MCU](https://extremeelectronics.co.in/avr-tutorials/easy-24c-i2c-serial-eeprom-interfacing-with-avr-microcontrollers/) for detailed usage description. Similarly, the instructions provided on [24CXX I2C EEPROM Communication using SoftI2C Library](https://extremeelectronics.co.in/avr-tutorials/24cxx-i2c-eeprom-interface-using-softi2c-lib/) is great resource on how to access `24C64` EEPROM chip via Soft I2C Library.

### Other Resources

* [DIY AVR Serial Programmer](https://www.dharmanitech.com/2008/09/diy-avr-programmers.html)
* [DIY ATmega32 Starter Kit: incl. LCD, I2C, SPI, RTC, ADC Interfaces](https://www.dharmanitech.com/2008/08/make-yourself-atmega32-starters-kit.html)
* [Interfacing RTC & Serial EEPROM using I2C Bus via ATmega128](https://www.dharmanitech.com/2008/08/interfacing-rtc-serial-eeprom-using-i2c.html)