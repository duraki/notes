---
title: "ADS Interface"
---

An ADS (sic. *Aktive DiagnoseStecker (DE)*, or *Active Diagnostic Connector (EN)* is a diagnostic interface for older BMWs. It is based on [Keyword Protocol](/keyword-protocols), specifically KW-71 protocol implementation standards. The physical implementation is based on the interaction of two bus line called K and L (K-Line & L-Line), K-Line which produces bidirectional data, and L-Line used to handle in-directional data. There is a provisioned and detailed interface repository hosted privately on my [GitHub's Company Page](https://github.com/durakiconsulting/bmw-tiny-ads-interface) called `durakiconsulting/bmw-tiny-ads-interface`, which goes in details on the corresponding ADS Interface topic.

The [TinyADS Interface](https://openlabs.co/store/Tiny-ADS-Interface) is an open-source implementation of the ADS from the team at openlabs.co, which uses BMW 20-Pin Diagnostic Port in vehicle at one side, and RS232 Serial Interface on the other side, to communicate with PC. Alternatively, you can [build custom BMW ADS adapter](https://deviltux.thedev.id/posts/o/20220219-bmw-tiny-ads-interface.html) via breadboard and a few transistors which I described in details [at my blog](https://deviltux.thedev.id/posts/o/20220219-bmw-tiny-ads-interface.html).

{{< details "Example of DIY TinyADS Interface" >}}
![](https://i.imgur.com/0bzcMJ4.jpeg)
![](https://i.imgur.com/294qmsn.jpeg)
![](https://i.imgur.com/rgva2b7.jpeg)
{{</ details >}}

### Software Requirements

The computer, running on Windows XP would need specific BMW proprietary software toolset installed and configured, to read and diagnose the vehicle. The list of tools and softwares needed to work with this adapter is:

* An old, portable laptop that have natively-integrated COM (Serial) Port
	- If your laptop has an ExpressCard slot, you can get PCMCIA ExpressCard Adapter, albeit this [setup requires additional tool](http://blog.jaroslavklima.com/2011/04/make-ads-interface-work-with-pcmcia.html)
	- If your laptop does not have ExpressCard slot, you are out of luck, either find an old laptop or buy used ThinkPad with ExpressSlot
* The driver programs `EDIABAS` required to connect to ADS via COM1 (Serial) Port
	- Standard Port Address: `03F8`
	- Standard Interrupt: `4`
	- Configure `EDIABAS.INI` file to use `INTERFACE=ADS`
* Desktop application software:
	- BMW INPA: *Factory-developed diagnostic interpreter program that is used to communicate with vehicle via EDIABAS*
	- NCS Expert: *A coding software developed at the factory level by BMW AG for adjusting vehicle options and features*
	- WinKFP: *A programming software developed at the factory level meant for writing/editing or flashing vehicle modules*
	- BMW TIS: *BMW TIS stands for Technical Information System. It contains documentation of the technical information needed for BMW repairs*
	- BMW ETK: *BMW’s Electronic Parts Catalog. It’s the documentation of BMW parts and also acts as parts database*
	- BMW Tool32: *This is a CLI MS-DOS application that you can use to reset the service, apply individual functions on the control units, or read the fault memory of individual control units. It can also be used for BMW coding*

**EDIABAS**: The EDIABAS or *Electronic Diagnostic Basic System* is a BMW AG proprietary communication protocol implementing and describing the control unit description files. This command set (based on BLAKE/2) is developed by BMW and implemented in all their vehicles. All software and tools used by the BMW AG officials uses EDIABAS to communicate with the vehicle. To debug and diagnose older BMW production models, you will need an original `ediabas` library drivers provided by the BMW AG, while for the newer BMW production models, one can use [EdiabasLib](https://github.com/uholeschak/ediabaslib) which is free and open-source alternative replacement for the BWM and VAG Ediabas toolset *(@see: [wiki](https://de.wikipedia.org/wiki/EdiabasLib))*.

**INPA**: So called INPA or *Interpreter for Test Procedures* is an older factory diagnostic software, design to run test procedures.

**NCS Expert**: The NCS Expert is an application provided by the BMW AG used to for [ECU coding and reprogramming](/ecu-programming) (*flashing*).

The software suite distributed by BMW Group AG that contains several interoperating applications and drivers, including *NCS Expert*, *WinKFP*, *NFS*, *INPA*, and others. Other tools exists as well and developed by dealer-level partenrs at BMW AG; some of them are: DIS/DISv44/DISPlus, BMW ISTA/D, BMW ISTA/P and many others.

### Hardware Requirements

Listed hardware requirements and pre-requisits are below:

* An old, portable laptop that have native COM1 (Serial RS232) Port (ie. Dell)
* An old, portable laptop that have native ExpressCard Slot (ie. Thinkpad)
* An RS232 Serial Cable that connects TinyADS with COM1 Serial Port or ExpressCard PCMCIA-SERIAL Adapter

If you have **laptop without "real" serial** *ie. no (COM1) port*, using PCMCIA Serial Adapter via ExpressCard module is viable option, but will require additional WindowsNT application called `AdsPort` [download](/posts/files/AdsPort.exe). AdsPort is a `ring3`-based WinNT driver that translates the default hardware address of the PCMCIA-SERIAL card, to that of required COM1 hardware address used to communicate via EDIABAS - reference to *Adapter Hardware Internals* to understand device communication internals, or alternatively *expand the below section for more details on AdsPort Utility*.

Supported ExpressCards:
* [StarTech 16950 UART Serial Adapter](https://www.startech.com/en-eu/cards-adapters/ec1s952), **confirmed**, used by developer
* [BestConnectivity PCI-E Based ExpressCard I/O Adapter](https://urlr.me/B2m1C), **confirmed**, by [forum user](https://urlr.me/H6ytR)
* [Delock Express Card](https://www.delock.com/produkt/66211/merkmale.html), **probably**, matching specs. to StarTech's adapter
* ... *it is expected that any cheap PCMCIA-SERIAL adapter will work, as long as it creates virtual COM port device* ...

{{< details "AdsPort Utility" >}}
The tool allows you to patch your ADS driver of your hardware adapter device, to a different COM port address - this means that it can be used with standard PCMCIA adapters, but not USB adapters.

![ads bmw virtual port change via pcmcia serial adapter](https://i.imgur.com/y2Wz4ML.png)

To check the hardware address of your virtual COM port:

- Open the Device Manager window
- Right-click on your virtual COM port device
- Select Properties
- Go to the Resources tab *(if there is none, the device probably doesn't have a hardware address and you are out of luck)*
- Write down the first number from the I/O range (something like `03F8`)

*Ref: [blog.jaroslavklima.com](https://web.archive.org/web/20231009212621/http://blog.jaroslavklima.com/2011/04/make-ads-interface-work-with-pcmcia.html)
{{< /details >}}

### Adapter Hardware Internals

The ADS acts as a level converter/shifter from V.24 interface (RS-232-C) to the diagnostic interface in the vehicle. The communication functions and switching/status functions are implemented via the status and data lines of the V.24 interface.

The system drivers support UART (NS8250/NS16450/NS16550) via WindowsNT application software. Some of the functionalities of the ADS interface are: Vehicle diagnostic, controlled accessibility of the vehicles, retrieval of Terminal 15, Terminal 30 and Ignition statuses, access to status line SIA5-RESET, and so on. The ADS interface supports these protocols:

- K1 & K2
- KDS2
- DS
- KWP2000
- KWP20004
- K-Bus2
- OBD2/CARB3

Please reference to [Aktiven Diagnose Stecker (pdf)](https://docplayer.org/14580006-Aktiven-diagnose-stecker.html) official technical documentation, which describes in details how the level shifter works from/to RS232.

The main driver for communicating via ADS and other software applications provided by the BMW AG is using the EDIABAS protocol implementation. The API application interface is the EDIABAS standard program interface across which an application program sends jobs to EDIABAS to operate control unit functions and across which the application program receives the results of the job execution back from EDIABAS.

Technical Documentation (in *PDF*) for EDIABAS (hosted by `obsrus.ru`):

* [EDIABAS: User Manual](https://obdrus.ru/f/user.pdf)
* [EDIABAS: API Interface Description](https://obdrus.ru/f/api.pdf)
* [EDIABAS: API User Manual](https://obdrus.ru/f/apiuser.pdf)
* [EDIABAS: API Function Reference](http://obdrus.ru/f/apiref.pdf)
* [EDIABAS: ECU Simulator](http://obdrus.ru/f/simulate.pdf)
* [EDIABAS: Transparent Mode](http://obdrus.ru/f/tmode.pdf)
* [EDIABAS: Best User Manual](https://obdrus.ru/f/bestuser.pdf)
* [EDIABAS: BEST/2 Language Description](http://obdrus.ru/f/best2spc.pdf)
* [EDIABAS: FAQ *(German)*](https://obdrus.ru/f/faq.pdf)

### Signal Description

The RS-232-C uses standardised levels for its signal, except for `RI` line. The levels are given between +12V *(range +3...+15V)* or -12V *(range -3...-15V)*.

| Signal Line | Description |
|-------------|-------------|
| RX          | Reception from Control Unit; When sending data on TXSG - level change on RX |
| DCD         | *Not Used*; ~(Receive signal input on status line (parallel to RX) for baud rate measurement)~ |
| TX          | Send to Control Unit; Depending on DTR, on line TXSG or RXSG |
| DTR         | A control line for switching the transmission line to the SG; DTR = -12V (Send on RXSG); DTR = +12V (Send on TXSG) |
|             | Signal is only valid if PSU (`Ubatt`) ≥ 8.5V |
| RI          | Read status of KI.30 |
|             | If RI = +13V...+15V: **KI.30 ON and RI = TRUE** |
|             | If RI < 3V: **RI = FALSE** |
| RTS         | Shutdown control |
|             | **If RTS = -3V...-15V**: RTS = -12V, Supply ADS and output PSU (`Ubatt`), RI ON |
|             | **If RTS = +4V...+15V**: RTS = +12V, Supply ADS and output PSU (`Ubatt`), RI OFF |
|             | **If RTS = +12V && Terminal 15 = 12V**: The device is switched-off and automatically restarted after approx. 5.5sec |
|             | **If RTS = +12V && Terminal 15 = 0V**: The device is switched-off permanently. Requires 12V provided to KI.15 to switch on again. |

### Alternative Solutions

It has been confirmed that the diagnostic device called "[Snap-on Solus](https://www.snapontools.com.au/solus-plus/)" manufactured by [Snap-on Tools (Australia) Pty Ltd](snapontools.com.au) can be used to read out diagnostic data from BMW E30 devices over the OBD-1, which supposedly works on BMW E34 models as well. Worth mentioning is that the price of the Snap-on Solus diagnostic hardware is quite pricey, and you need to look for European *car coverage* version of it. Since I have not tested this diagnostic tool myself, I can't guarantee you will be able to read all the diagnostics similar to what the ADS interface can provide, but [this video](https://www.youtube.com/watch?v=1bRQkQjGQgE) on Youtube clearly shows that it can be used to read out [DME/ECU](/ecu-foundations) data of a BMW E30 (MY. 1988), as well as offering additional options.

---

{{< details "External References" >}}
* [BimmerForums: Interface in ADS mode over cheap PCMCIA-SERIAL adapter](https://www.bimmerforums.com/forum/showthread.php?1633825-SUCCESS-Interface-in-ADS-mode-without-a-real-COM-port)
* [BimmerForums: Using USB and 64bit ADS Interface via EdiabasLib](https://www.bimmerforums.com/forum/showthread.php?2419002-USB-ADS-Interface-Working!&p=30379058#post30379058)
* [BimmerForums: Using cheap PCMCIA-SERIAL Adapter with TinyADS](https://www.bimmerforums.com/forum/showthread.php?2270258-HELP-WITH-INPA-DIS-on-an-E34&p=29159137#post29159137)
* [Drive.ru: TinyADS Alternative](https://www.drive2.ru/l/636920698765335698/), also [Schematics](https://drive.google.com/file/d/1WbkMEgDPISKbExbEmsgghqY3aTK6nyVT/view)
* [Drive.ru: Homemade DIY ADS Adapter for BMW E34](https://www.drive2.ru/l/674430263069005051/)
* [Drive.ru: Another DIY Diagnostic Adapter](https://www.drive2.ru/l/532112226748729651/)
* [Drive.ru: ADS Interface bundled with the Plug Cable](https://www.drive2.ru/l/8715174/), also [Schematics](https://disk.yandex.ru/d/iCVabNa74iAbHg)
* [e34.de: Reading BMW E34 Error Codes and building custom diagnostic interface 🇩🇪](https://www.e34.de/tips_tricks/fehlerspeicher/fehlerspeicher.htm), or <a target="_blank" href="/pdf/bmw-e34de-reading-bmw_e34_errors_building_interface.pdf">PDF (English)</a>
{{< /details >}}