---
title: "BMW E34 DME ECU Chip Modding"
url: /bmw/modding/ecu
---

## General DME Information

The DME/[ECU](/ecu-foundations) (Digital Motor Electronics) is a computer with internal pre-programmed and programmable computer chips that controls the key functions of the vehicle engine's operation while maintaining optimum reliability and maximum performance as well as minimizing fuel consumption and emissions that holds vehicle ECU. Some of the things written into ECU are: VIN (Vehicle Identification Number), Immobilizer Data (EWS), Software and so on.

The DME collects data every second such as engine speed, air intake volume, air temperature and density, coolant temperature, throttle position, accelerator position, vehicle speed etc. By using input sensors and output components, it then proceeds to compare and contrast the data received to the rest of the engine’s operations. In the event that there is an error or unreliable data, the DME replaces it with Preset Standard Values. It can also cut fuel flow to the cylinder in case of a spark plug failure in order to prevent engine damage.

The electrical system is also monitored by the DME. Information received from input sensors enables the DME to gauge the condition and level of the engine’s battery as well as the electrical consumption of the car. It uses this information to manage the power and maintain the optimum battery level to prevent a flat battery or any damage.

### ❤️ Custom ECU Chip via [Dsylva-Tech](https://dsylva-tech.ca) + [DC](https://durakiconsulting.com/) Collab

I've inqured Mark D'Sylva, that is, his ECU Tuning Company [Dsylva-Tech](https://dsylva-tech.ca/) one day, asking for a direction on which ECU Performance Chip to buy for my [BMW E34 520i '94](/e34-repair-restoration) since I couldn't find appropriate ECU Chip model on their official website, and Mark himself responded to me a day later, notifying me they didn't have the ECU Performance chip I've asked for. The thing is, while looking up my details on my VIN, it seems that my vehicle came with factory EWS (Immobilizer) option, which looked like an important information when buying an ECU Performance Chip. Although D'Sylva had an ECU Performance Chip for M50B20TU engines for BMW E34 Series 5, he didn't create one for the E34 models that came with EWS - Immobilizer option, therefore this turned like a failed mission.

Quotying Mark D'Sylva:

>
> I didn't make a chip for that ECU with EWS.  I made one for the same engine but without EWS.  I don't think it would work in your case.
>
> Regards,
> Mark

I asked Mark D'Sylva again if he could point me out to someone else who offers quality ECU Performance Chips on the market; quotying partial email transcript below:

>
> Can you share any other vendor on similar industry level like you gents at D’Sylva Tech, that could possibly have ECU Chip I’m looking for?
>
> Much appreciated,
> Kindly,
> Halis

Pretty quickly, D'Sylva asked me if I have enough experience or knowledge to read the current vehicle ECU EEPROM Chip (ie. *if I could dump the firmware for him*), and he could make a custom ECU Chip for my vehicle, that came with factory EWS actived:

>
> do you have any way to read your current chip?  If you can read it and send me a binary file, I should be able to make a chip for you with the EWS active.
>
> Regards,
> Mark

That was awesome on Marks' side and I was astonished to hear that I will actually collaborate with him on creating a new ECU Performance Chip for the specified model. Of course, since I'm doing a lot of [Hardware Hacking](/hardware-hacking) and [Automotive Cybersecurity](/automotive-hacking), both [privately](http://linkedin.com/in/duraki/) and [professionally](https://durakiconsulting.com), I gladly (*and proudly*) accepted the challenge, promising Mark I won't dissapoint him and that I will deliver this ECU firmware dump.

Therefore this collaboration between [D'Sylva-Tech](https://dsylva-tech.ca/) & [durakiconsulting LLC](https://durakiconsulting.com/) was born. The project was split in several different parts, as following:
1. Initial Gathering
2. Disassembly of the DME
3. Extraction of the ECU EEPROM Chip
4. Dumping of the ECU EEPROM Firmware Data
5. Packaging and Delivering ECU EEPROM Firmware Dump

**1. Initial Gathering**  
I firstly needed to get to my garage, open up the hood of my vehicle and get the DME out of the car. To do this, you need to open the hood and find the plastic enclosure box containing the DME on the right side (passenger side) of the vehicle, directly across the cabin glove box location. This plastic enclosure is holding DME firmly in place. Below image visually represents DME location, and also the plastic enslosure box in which the DME is kept firmly.

![](https://i.imgur.com/pPY9Ep1.jpeg)

The DME is located under a plastic cover, as shown by the red arrow in the first image.

Again, the plastic enclosure needs to be unscrewed first to get to the actual DME, as shown visually in the image below. **Note:** the image below shows the position of the screws only - of where the DME is located in BMW E34. Usually, there is another plastic enslosure that sits on top the enclosure box, and it's required to remove this *top* plastic enslosure by unscrewing aftermentioned screws, and ofcourse, finally removing the the top plastic container.

![](https://i.imgur.com/NNtqooF.jpeg)

Please take a look at the YouTube videos referenced below, at the end of this note for more instructions and details on DME removal. Be extra careful when removing the DME, as to not damange anything (ie. *Pinouts*, and other Electronic Components).

**2. Disassembly of the DME**  
Once the DME is removed from the vehicle, it needs to be disassembled. This tasks requires patience, since the DMEs are usually pretty sturdy, fitted in a highly tight enclosures. There are multiple units, as well as some relays below in the box enclosure/container where the DME is located, as shown in the image below:

![](https://i.imgur.com/qWvZoQw.png)

The DME is located and fitted on left side of the plastic enclosure (closer to the vehicle cabin), and on the most right is the ABS/ASC Unit/ECU implementing the assisted breaking system mechanism. In the middle, usually there either 2, or 3 relays (depending on the BMW E34 model).

{{< details "Expand for Relays" >}}
Each relay in the DME box enclosure are used for different functions:
* If it's **White**, it's usually indicating a *DME System/Main Relay*
* If it's **Orange** or **Blue**, it's usually indicating a *Fuel Pump Relay*
* If it's untypical **Black** in color with wires directly to it, it's usually indicating a *Oxygen Sensor Heater Relay*
* If it's an E34 M5 model with **Orange** Relay, it's usually indicating an *Air Pump/Emission Relay*

The easiest way to identify what each of the realy is used for is to use the diagrams and schematics either visible on the sticker (should be visible on covering plastic for the enclosure), or by browsing the internet. Another way is to look at the relays from the top-to-bottom view and observe the visible realys. The relay on the top should always be a DME System/Main Relay, and the unsual black relay with the wires sticking out should always be an Oxygen Sensor Relay. Take a look at the below image for more details and diagram:

![](https://i.imgur.com/siVr5sN.png)
{{</ details >}}

To remove the DME, you will need to pull out the fixation levers used to hold DME in place. These metal fixators can be easily identified visibly, by checking the top and sides of the DME. [Click here](https://i.imgur.com/c2zdyLh.png) to see an image example of the metal fixation levers located on top of the DME. Please take a look at the YouTube videos referenced below, at the end of this note for more instructions and details of DME fixation levers and their removal/disassembly.

By removing the top-holding DME fixation lever, you will also automatically remove the connecting wires/cable that is connected to the DME Backside Pinout. This process is automatic when doing the process correctly (Hah! *German Engineering!!* 🇩🇪).

You should now be able to remove the DME out of the vehicle and its' plastic enclosure by pulling it out, like so:

![](https://i.imgur.com/zIRkJgJ.png)

With DME in hands and on the lab. test bench, proceed to disassemble the metal enclosure box. For this, you will need a flat-head screwdriver and maybe a butane torch to not destroy the metal enclosure. Start by bending out metal fixations of the DME, making sure to do it slowly, and, if required, heating up while unbending if the bent lock is hard to unbend. Take a look at the following images for examples:

![](https://i.imgur.com/B5BPMTQ.png)

Using butane torch to heat up the bent metal parts to ease the process of disassembly:

![](https://i.imgur.com/iq3DOZh.png)

From the bakcside of DME, also unscrew the four (4x) screws holding the DME in place. Take a look at the following image for example:

![](https://i.imgur.com/8klqbLa.png)

The process of disassembly also requires you to separate the backside metal panel of the DME after you unscrewed it. You should now have an exposed DME which might also include a plastic separation layer on top of the DME. See the image below:

![](https://i.imgur.com/ZWIYXsj.png)

Remove the plastic separation layer from the top carefully and using pliers, firmly press the holding plastic on the middle of the DME motherboard to detach the PCB from its enclosure. Once detached, use flat-head screwdriver and *unlock* the fixation lever hinge located on the DME pinout, which will eventually allow us to detach top-view PCB from the motherboard, from its bottom counterpart.

![](https://i.imgur.com/1JG3xx4.png)
![](https://i.imgur.com/ohp4hBf.png)
![](https://i.imgur.com/OFO0VB0.png)

It's should now be possible to separate the top and bottom layers/PCBs of the DME.

![](https://i.imgur.com/npjQETC.png)
![](https://i.imgur.com/8W8QvnE.png)

**3. Extraction of the ECU EEPROM Chip**  
The ECU Chip within the DME should now be visible on one of the separated layers of the PCB. The ECU Chip is easily identifieable due to the *white plastic cover* sitting on top of it, that acts as a protection. It might be possible that this plastic protection cover is not visible on your DME so proceed with caution. In other cases, reference to DME diagrams online to identify the ECU Chip location on the PCB. Remove the plastic protection cover by lifting it up using your fingers. You know should have an exposed/naked ECU Chip visible on the PCB.

![](https://i.imgur.com/kxFtUqY.png)

Once the ECU Chip is exposed, remove the ECU Chip itself out of the PCB, using a hinge removal tools made out of plastic, typically used when repairing mobile phones. You can buy [these repairing kits](https://i.imgur.com/2JHlPUx.png) since they are used for mobile phone and similar repairs. Alternatively, if you don't have these plastic mobile phone repair tools, use a flat-head screwdriver with electrical tape around it, to prevent accidental dischargs or potential electrical shocks.

![](https://i.imgur.com/VuWSUYI.png)

Use the tools from both side as to not brake the legs of the EEPROM ECU Chip while removing it and be extra careful doing this. Destroying the original EEPROM ECU Chip might lead to unresponsiveness of your vehicle. Once the EEPROM ECU Chip feels loosely from both sides, remove it by lifting it up with your fingers. Prior to lifting the ECU Chip from the PCB, it's important to note down the alignment of Pin #1 of the ECU Chip, so that the new chip can be inserted the same way - the easiest way is to take an image while doing the ECU Chip disassembly process.

![](https://i.imgur.com/ESJPlzp.png)

**4. Dumping of the ECU EEPROM Firmware Data**  
*<TBA_-_To_Be_Added>*. We will be using a CH341A Programmer to dump the firmware out of the ECU Chip EEPROM, and using its' reader mode, we will dump the binary/blob of the firmware which will be further used by the [Dsylva Techology, CA 🇨🇦](https://dsylva-tech.ca) to tune the aftermarket ECU Chip and provide new ECU maps.

While reading/dumping the data from the EEPROM ECU Chip, make sure to use the right orientation of the chip and the location of the Pin #1 of the chip. The easiest way to do that is to take a look at the ECU Chip and see if there is a visible marking, usually a *circle*, indicating Pin #1. See the following image for details:

![](https://i.imgur.com/bkcOJrE.jpeg)

It might be required to modify the CH341A EEPROM Programmer to work for automotive use-cases. If so, please reference to the YouTube video [Modify the CH341A EEPROM Programmer (Black Edition) for 5V 93XXX/95XXX Automotive Use](https://www.youtube.com/watch?v=hPKckby54uA) which explains the process in details. **Note:** This was not tested and it might not be required after all. Further research is required prior to modification.

{{< details "Modifying the CH341A EEPROM Programmer for Automotive Use" >}}
The video above covers a combination of programmer software, EEPROM adapter, and programmer's Printed Circuit Board (PCB) modification to allow +5V 93XXX (e.g., *93C66*) and +5V 95XXX (e.g., *95040*) SOIC8 / SO8 EEPROMs to also be supported by the ubiquitous CH341A USB MinProgrammer (Black Edition), in addition to its usual SO8 25XXX/24XXX device support, alongside the new/modified +5V support for 24XXX (e.g., *24C08*). With this support you can use this programmer to change VIN information in most Radio or Body Control Module (BCM) types sold in the USA from the 1990s and early to mid 2000s, as well as to perform odometer mileage correction manually in these same BCMs or an instrument cluster, for example.

In order to reliably write some SO8 EEPROM devices encountered in automotive circuits a +5VDC supply and programming voltage, rather than the default +3.3VDC, is required.   This particular inexpensive programmer can be easily modified for this automotive module voltage requirement and allow for doubling the number of supported devices in doing so as well (from 2 to 4 EEPROM families) as shown in this video.   While not all SO8 EEPROM devices can be written, or even read, in-circuit of automotive module circuit designs many can, and for those that cannot this programmer can still provide a very inexpensive DIY solution for light duty repair projects off circuit as well.  These inexpensive programmers lack the over current protection or pin protection of most general purpose programmers, which allows them to be used for in-circuit reading and writing as well as off circuit for many (though not all) automotive modules.

**Note:** In order to read 93Sxxx security devices you will have to explicitly connect pin 7 (PRE) to ground (pull low) rather than leave it floating like I showed for 93CXXX devices.
{{</ details >}}

It might be possible to use [Minipro TL866 EEPROM Chip Burner](https://www.amazon.com.au/TL866CS-Universal-Programmer-Adapters-Shipping/dp/B07RJBGXHN) instead of the aftermentioned CH341A Programmer without prior modification on the EEPROM reader, as described in this [BimmerForums.com - Chip Burning Tips & Tricks](https://www.bimmerforums.com/forum/showthread.php?2215185-Chip-burning-tips-and-tricks) thread. A new model [XGecu TL866 Programmer](https://www.aliexpress.com/item/1005004434848306.html) is recommended for burning ECU EEPROM Chips in the automotive sector (use search query *TL866 3rd gen*, *TL866-3G*, or *T48*). The manufacturer is [XGecu](http://www.xgecu.com/en/TL866_main.html) which also has its own online stores for ordering the readers/programmers.

Once the firmware has been dumped from the ECU EEPROM Chip, we will deliver the dumps to [Dsylva Techology, CA 🇨🇦](https://dsylva-tech.ca) and wait for his tune to be completed.

**5. Packaging and Delivering ECU EEPROM Firmware Dump**  
*<TBA_-_To_Be_Added>*.

---

## Location of the Unit in Vehicle

Usually, for BMW and MINI Cooper vehicles it is located In plastic box next to the battery beneath the hood. The DME on BMW E34 Series 5 is located under the hood, across the side passenger glove box. Below image visually represents DME location, and also the plastic enslosure box in which the DME is kept firmly.

![](https://i.imgur.com/pPY9Ep1.jpeg)

## Common Problems in DME

* Water or similar damage on DME
* Voltage under 6V can create problems in DME
* *Bricked* ECU or bricked components in DME
* Corrosion of pins on DME PCB
* Corrosion of pins outside the DME socket

### Programmers

* [Xgecu T48 Programmer Step-by-Step](https://www.youtube.com/watch?v=36xP4uufo84)

### References

* [/r/ECU_Tuning](https://old.reddit.com/r/ECU_Tuning)
* [/r/CarHacking](https://old.reddit.com/r/CarHacking/)
* [/r/CarModification](https://old.reddit.com/r/carmodification/)
* [ECU Chip on M50B25 - Removing the DME from Vehicle (*timestamp*)](https://youtu.be/e9-sKvccu4c?si=4xh7ooqLKaCGGWyY&t=80)
* [How to open BMW E34 DME for Chip Replacement](https://www.youtube.com/watch?v=1z2D656InIc)
* [Removing the DME from BMW E34 and Chip Install](https://www.youtube.com/watch?v=gWUon_Iwaps)
* [Installing *ENDTUNING* ECU Chip on BMW E34 M51 TDS](https://www.youtube.com/watch?v=LZqIn1ud1XE)
* [How to tune a BMW E30 DME ECU](https://www.youtube.com/watch?v=WQUWzzpRlPk)
* [How to tune older BMW ECUs](https://www.youtube.com/watch?v=yDXPBlh53Fs)
* [BMW E30/E36 DME Motronic ECU Chip Installation](https://www.pelicanparts.com/bmw/techarticles/E36-DME-Repair/E36-DME-Repair.htm)
* [How To: Open DME Metal Box and Replace ECU Chip in BMW E34 M5](https://www.youtube.com/watch?v=K60N0j3rMlc)
* [How To: Open DME Metal Box for BMW 5 Series](https://www.youtube.com/watch?v=1OaUqVYywMA)
* [Dumping ECU EEPROM Firmware w/ CH341A PRogrammer](https://udayakrishna.medium.com/dumping-firmware-with-ch341a-programmer-13fba277baa5)
* [Modify the CH341A EEPROM Programmer (Black Edition) for 5V 93XXX/95XXX Automotive Use](https://www.youtube.com/watch?v=hPKckby54uA)
* [CH341A Programmer – Burning BIOS Chip](https://www.pcb-hero.com/blogs/lickys-column/ch341a-programmer-burning-bios-chip)
* [Dumping Firmware with CH341A Programmer](https://udayakrishna.medium.com/dumping-firmware-with-ch341a-programmer-13fba277baa5)
* [E34 520i Basic Control Unit DME Part Schematics](https://www.realoem.com/bmw/enUS/showparts?id=HB51-EUR-09-1991-E34-BMW-520i&diagId=12_1689)
* [(PDF) BMW E34 Drive Away Protection System - EWS/Immobilizer Details](https://www.europeantransmissions.com/Bulletin/DTC.BMW/understandthe%20EWS%20BMW.pdf)
* [(PDF) BMW E32 DME Bosch Motronic 1.1/1.3 Technical Details](http://www.opel-scanner.com/files/DME_1.1_1.3.pdf)
* [(PDF) BMW E32/E34 DME Bosch Motronic 1.3 Pinout Diagram](https://www.e34.de/tips_tricks/motronic/m1_3.pdf)
* [Getting the fault codes to appear on the 'Check Engine' Light for DME Motronic 1.1/3.x](http://www.unofficialbmw.com/repair_faqs/motronic.html)
* [DME ECU Swap/Repair w/ Photos](http://www.101projects.com/BMW/Projects/087/pics.htm)
* [BimmerForums.com - E32 ECU/DME Hacking ~lots of details](https://www.bimmerforums.com/forum/showthread.php?1529229-E32-ECU-DME-hacking)
* [BimmerForums.com - E34 EWS v2 Explained in Details](https://www.bimmerforums.com/forum/showthread.php?1603140-EWS-II-Explained-in-Detail)
* [The Prom Tuning Guide Book & FAQ](https://www.thirdgen.org/forums/diy-prom/288763-prom-tuning-guide-book.html)
* [(RU 🇷🇺) Documentation for BMW M50B20/M50B20TU Petrol Engines (Vanos) and the Siemens DME MS40.0/MS40.1 Control Systems](https://oldbmw.ru/documentation/319-dokumentaciya-po-dvigatelyam-bmw-m50b20-i-m50b20tu-sistemy-upravleniya-dme-siemens-ms400-i-ms401.html)
* [DME Performance Chip Install Instructions](http://www.nmia.com/~dgnrg/page_18a.htm)