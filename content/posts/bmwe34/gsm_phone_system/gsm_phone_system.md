---
title: 'BMW GSM Phone System'
url: /bmw/gsm-phone
---

The BMW E32 7 Series, and E34 5 Series, were in the selection of cellular provision via their GSM Phone/Telephone System. The GSM Phone interface contains 2-Pin Connector **X18503** for the IBUS DAC/LAC general data connection to the Instrument Cluster/CCM/RDS Radio/OBC. The GSM Phone System is part of the CMT1000VR kit. The car GSM Phone/Telephone System uses older technology, which isn't available anymore - the _analog car phones_ do not work in most of the World, and haven't been working for some time now. It might be possible to convert the GSM Phone System to digital GSM networks.

![](https://i.imgur.com/KknmajX.png)

Some possibilities with modding this stuff is:

- Enabling the GSM Phone System to connect to GPSR/G3 networks
- Connecting the GSM Phone System to the Instrument Cluster OBC Display
- Wiring the GSM Phone System to newer mobile phones that support today networks

![](https://i.imgur.com/woZfsje.jpeg)

In BMW E34 Individual/Business version, some models included the FS. Euro Motorola GSM Phone alongside base. Check out the images below.

![](https://i.imgur.com/9KyEYOL.jpeg)
![](https://i.imgur.com/BbF5Wmo.jpeg)
![](https://i.imgur.com/jRmp5Cu.jpeg)
![](https://i.imgur.com/R2FMnqW.jpeg)

Alternative version was also included in some models of BMW E34 that uses newer Phone System (as used in BMW E38). Here is an example of that model:

![](https://i.imgur.com/CI4N7Rw.jpeg)

More GSM Phone Versions are linked in images below:

- [FS. Euro Motorola GSM Phone for E34](https://i.imgur.com/Qa8mcOI.jpeg)
- [CPT8000 Motorola GSM Mobile Phone for E34](https://i.imgur.com/rm3Oa6D.jpeg)

The BMW E34 is prewired to work with a highly sophisticated Motorola/factory phone system that is integrated with both the instrument cluster dash display, the OBC, and the stalk controls.

The power supply to the integrated BMW E34 GSM Phone is provided via the modular connector, which is located under the rear center console section of the car. The pinout of the `8-pin` modular connector is:

```
1       LGnd
2       +9.5
3       TData
4       CData
5       RData
6       AGnd
7       TX - Hi
8       RX - Hi
```

Disregard the other connectors for the interface box, speakers, and microphone ([source](http://www.unofficialbmw.com/e34/interior/e34_cell_phone_prewired.html)).

---

### Custom Standalone GSM Board

**Standalone GSM Board**

The use @okwestern ([Ole Kristian Western](https://www.linkedin.com/in/olewestern/)) posted a thread on [bimmerforums.com](https://www.bimmerforums.com/forum/showthread.php?2415184-OEM-BMW-car-phone-modified-to-work-with-todays-networks) offering a service that will provide a standalone GSM board for the GSM Phone System included in various BMW vehicles to work with todays cellphone networks.

![](https://i.imgur.com/5F3MRFQ.jpeg)
![](https://i.imgur.com/gZXcc2r.jpeg)
![](https://i.imgur.com/PBLQ6Iy.jpeg)
![](https://i.imgur.com/gpr06fI.jpeg)

**Cartel Telephones**

> A company named Cartel did make an old school looking car phone that was digital and has the looks of the older analog phones but, has the digital internals to work on the current digital networks or allows your current digital phone to connect through it via Bluetooth. I kick myself for not grabbing one back when they were available and can't bring myself to pay the $400.00 price when they pop up on EBay every now and again. The BMW E34 model was labeled as **Cartel CT-1000**.

---

### Tapping into the GSM Phone Keypad using MCU

The GSM Phone has a nice looking keypad. This introduces how to tap into the keyboard using a Microcontroller (MCU), to be able to send strings of numbers or similar. The MCU could then know which number is paired to which function, and therefore could control outputs, change settings and so on, all from the built-in GSM Phone system. There was an [old blog post](https://web.archive.org/web/20160714215231/http://i-code.net/tapping-into-the-bmw-750il-phone-keypad/) by James Holladay, but it seems like the images/videos aren't hosted anymore.

Please visit the separate GitHub project titled [Thesis on Reverse Engineering GSM Communication System Modules for BMW E34 Series 5 (1994)](https://github.com/durakiconsulting/gsm_telephone_connection-establish_COM_conn) for more details.

---

## References

* [Wikipedia.com GSM Frequency Bands](https://en.wikipedia.org/wiki/GSM_frequency_bands)
* [R3VLimited.com Bluetooth Car Phone Conversion Service](https://www.r3vlimited.com/board/forum/e30-classified-forums/for-sale-wanted/parts-for-sale/286802-feeler-bluetooth-car-phone-conversion-service?t=317694)
* [BimmerForums.com Eject Box Wiring Pinout for E39](https://www.bimmerforums.com/forum/showthread.php?2411046-Help-Eject-Box-Wiring-Pinouts)
* [BimmerForums.com Custom Standalone GSM Board](https://www.bimmerforums.com/forum/showthread.php?2415184-OEM-BMW-car-phone-modified-to-work-with-todays-networks&p=30346382#post30346382)
* [Drive.RU Regular Phone Part #1](https://www.drive2.ru/l/645179680357360795/), and also [Part #2](https://www.drive2.ru/l/645180504991090987/)
* [BMW Autotelefon (GSM) Operating Instructions](https://www.induleo.com/e34/autotelefon.pdf)
* [Fun with cheap SIP VoIP Hardware](https://blog.thelifeofkenneth.com/2011/05/fun-with-cheap-sip-voip-hardware.html)
* [Sniffing Pager Network Traffic](https://blog.thelifeofkenneth.com/2012/02/sniffing-pager-network-traffic-hardware.html)
* [BMW E34 8-pin Modular Connector under Rear Center Console](http://www.unofficialbmw.com/e34/interior/e34_cell_phone_prewired.html)