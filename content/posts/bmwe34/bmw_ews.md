---
title: "BMW EWS"
url: "/bmw/ews"
---

The [EWS](/ecu-programming#immobiliser---ews-bypass) is a part of the vehicle that acts as an integrated vehicle immobiliser. The purpose of the Drive Away Protection (EWS) system was to reduce vehicle theft as mandated by the European Insurance Commission to combat the high theft rate in European Countries.

*Example of EWS2 module from the BMW E36 "Series 3" models:*
![](https://i.imgur.com/5SrYRHx.jpeg)
![](https://i.imgur.com/2srTwwM.jpeg)
![](https://i.imgur.com/xOB0fky.jpeg)

### EWS-I

The EWS I was installed on vehicles beginning production 1/94, replacing the original Drive Away Protection System. The European Insurance Commission published an upgraded compliance requirements, therefore additional component was added called the **Starter Immobilization Relay**. This relay module provides added theft prevention and safety features to the vehicles as expected (at the time) by the EIC regulations.

At the time of introduction, the system was referred to as *Electronic Drive Away Protection* which in German is **Electronische Wegfahrsperre** or simply, **EWS**.

The "EWS I" system consisted of the following major components:

- Starter Immobilization Relay
- Door Lock Cylinders and Switch
- General Module
- Board Computer (if equipped)
- Transmission Range Switch
- DME Engine Speed Signal (Beginning 6/94 Production)
- DWA (E31)

**Principle of Operation:** The EWS *Starter Immobilization Relay* receives it's inputs from the iginition switch, GM (or DWA), BC, Trans Range Switch, and the DME (after 6/94 MY.). The relay will prevent enginge start if:

1. The vehicle is locked from the outside, the GM receives the "HIGH" signal from the door lock switch, and sends a "HIGH" signal to the EWS
2. The BC code function is set
3. A DWA "HIGH" signal is received (for *BMW E31* models only)
4. A "LOW" signal is received from the Trans Range Switch
5. The engine speed signal from the DME exceeds 60Hz (from 6/94 MY. models only)

The ignition and injection functions of the DME are disabled, and the KL50 start signal to the start is opened to prevent starter operation.

{{< notice >}}
Important Errata
{{</ notice >}}
{{< callout emoji="🔑" text="*Starter Immobilization Relays* are different for *manual* and *automatic* vehicles. Make sure use correct relay during installation. The *Starter Immobilization Relay* is not on the 'Diagnostic Link', conventional troubleshooting techniques using the **DISplus**, a *DVOM* and the correct *ETM* are necessary." >}}

{{< notice >}}
Loss of Input Signals
{{</ notice >}}
{{< callout emoji="🔑" text="Loss of input from the GM or BC will allow the engine to start. Loss of input from the Trans Range Switch will **NOT** allow the engine to start." >}}

External instructions that might be of help:

* [BMW E36 "EWS I" Module Bypass](https://www.youtube.com/watch?v=rO0ws9BUawU), *should work on E34 as well*
* [Tuning BMW E36 DME to bypass EWS](https://www.youtube.com/watch?v=JHSuUaKgEw4)

### EWS-II

Starting with 01/1995 production, all BMW vehicles were equipped with a new EWS system titled EWS II. This change was once again brought about to meet the next level of compliancy with the European Insurance Commission regulations.

The purpose of the newly implemented system changes to the European Insurance Commission regulations made it necessary to introduce a
new theft protection system, with greater capabilities and a higher level of security.

The EWS II system operates independent of the actual mechanical key of the vehicle. The mechanical key only makes a request to the vehicle starting system. The electronical verification of the key is required before the starting procedure is initiated by the vehicle.

The system features wireless communication between a programmed [EEPROM](/eeprom) housed in the *ignition key*, and the actual *EWS II control module*. Therefore, a vehicle key which is properly coded to the EWS II control module is required before starting operation of the vehicle continues. 

The EWS II and the DME control modules are synchronized through an *Individual Serial Number* (ISN). The ISN, stored in the EWS II control module, must match that of the DME each time the ignition is switched to "**ON**" position, and before the engine operation of the vehicle is allowed.

The EWS II control system was installed on E31, E34, E36, E38 and E39 vehicles.

Major components of the EWS II systems are:

- Vehicle Key & Transporder
- Ring Antenna
- Transmitter/Receiver Module
- EWS II Control Module
- DME Control Module

**Principle of Operation:** The starting sequence involves communication between all the components of the system. In case of any communication process errors, the vehicle will not start. Expected sequence of the EWS II system is as follows:

1. The vehicle key is inserted into the lock cylinder and switched to "ON" position.
2. The transmitter/receiver module sends 125kHz AM signal to the rign antenna.
3. The sent AM signal induces voltage in the key coil and powers up the transponder.
4. Powered up, the key transporder sends the key identification code to the transmitter/receiver module via the 125kHz AM signal.
5. The transmitter/receiver module converts the received AM signal to a digital signal, and sends it to the EWS II control module.
6. The EWI II control module verified the key identification code and checks to see if the key is enabled.
7. Upon approving the key as valid by the EWS II control module, the EWS II control module then sends a digital password to the transmitter/receiver module, which converts the data to an AM signal.
8. The converted AM signal is sent to the transponder via the ring antenna.
9. If transponder accepts the received password and mark it as valid (ie. *correct*), the transporder releases the changing code (ie. *rolling code*) to the transmitter/receiver module
10. The transmitter/receiver module converts this AM signal to digital signal, and sends it back to the EWS II module.
11. If the changing code received by the EWS II module is correct, the status of the BC (ie. *Board Computer*), transmission range switch, and TD is examined.
12. Upon examination, with correct input status, the internal starter relay (integrated into the EWS module) is energized, and the starter motor begins to operate.
13. At the same time, the EWS II module sends the ISN (ie. *Individual Serial Number*) back to the DME using the single wire communciation bus.
14. If the ISN code stored in the EWS II module matches that of the DME, the drive away protection is cancelled, and injection/ignition is enabled.
15. During the process of sending the ISN to the DME, the EWS II module sends a new changing code to the transported through the transmitter/receiver and ring antenna. The transported stores the changing code until the next starting sequence (ie. system implements *rolling codes*).

**EWS II Replacement Procedures Keys:** The EWS II allows up to 6 additional keys to be ordered, also known as *replacement keys*. The EWS II control module is codeable for up to 10 keys (four (x4) keys delivered with vehicle, and six (x6) of them as replacement).

**EWS II Control Module:** A replacement EWS II Control Modules must be ordered using corresponding vehicle VIN when ordering from OEM suppliers. The EWS II modules contain the VIN (*Vehicle Identification Number*) and is coded right from the factory to be recognized by the key codes. Modules from other vehicles will not recognize keys as being valid and therfore will not allow starting the engine. The EWS II Control Modules store the ZCS (ie. *Central Coding Key*) and the VIN. If the EWS II control module is replaced, the system must be *ZCS* coded (ie. "SIB 61 02 96", and "TRI 61 01 95"). The EWS II module must be synchronized with the DME (alignment of the *rolling codes*). There is no limit to the number of times the ISN may be changed in the EWS II module itself.

**EWS II system in ECU/DME:** The ECU/DME is not ordered VIN specific, and therefore must be programmed during the EWS2/DME replacement. The ISN from the newly purchased DME must be transferred to the EWS II module using the *DISplus* or *MoDic* software solutions.

**Key De/Activation:** Vehicle keys that might be lost or stolen can be deactivated, protecting the vehicle theft. The *SERVICE FUNCTIONS* of the *DISplus* or *MoDic* software solutions with the **EWS II** repogramming option, contains a "*Bar/Release Code*" function. This function activates and deactivates specific keys of the EWS II when such cases are needed. Any vehicle key may be set as "Barred" except the key in the ignition at the time of deactivation and the use of the applicable software. The lost or stolen key can be identified by the identification of the remaining keys. There is no limit to the number of times a key can be activated/deactivated.

{{< notice >}}
Important Errata
{{</ notice >}}
{{< callout emoji="🔑" text="A `barred` key (ie. a vehicle key that allows unlocking of the vehicle doors) will not be able to start the engine; it only allows the vehicle to be unlocked or locked." >}}

**EWS II System Components:** This section describes the common system components implemented in the whole EWS II control module.

1. Key with Transponder
   - Four keys ar einitially supplied with each vehicle (via OEM sales)
   - Each key contains a wireless electornic chip (transporder chip)
   - The function of the transporder chip is to transmit/received data of the EWS II control module
   - The transponder contains a wireless read/write to EEPROM, in addition to a smaller capacitor and coil for self-powering capabilities
   - The function of the EEPROM is to: *store codes for key identification, transmitted passwords, *rolling codes*, and to receive & respond to coded messages from the EWS II control module
   - Power for the transponder is produced via the inductive coil, and stored in the capacitor
   - Each time the key is inserted into the ignition, the AC voltage in the anntenna ring induces voltage in the key's integrated inductive coil
   - All keys, either with included remote functions, or the one without it, including wallets and valey keys, contains the aftermentioned transponders
2. Ring Antenna
   - The *Ring Antenna* is an inductive coil installed around the lock cylinder which provides power for the transponder in the key, and the communication link (ie. *antenna*) between the key and the transmit/receive module
3. Transmitter/Receiver Module
   - The Transmitter/Receiver module supplies power to the transponder via the *Ring Antenna*
   - This module also controls the flow of data between the transponder and the EWS II control module
   - Data transmission between the transmitter/receiver module and the transponder takes place over a radio frequency of 125KHz amplitutde modulated AM signal
   - The transmitter/receiver module converts the analog data received through the AM signal to the digital data
   - The transmitter/receiver module transfers the digital data to the EWS II control module over a single wire bi-directional data interface
   - The location of the transmitter/receiver module is under the dash
4. EWS II Control Module
   - The EWS II Control Module is linked to the *BC*, *GM*, *DME*, *Trans Range* switch and the *starter* for drive away protection operation
   - The module incorporates an integral starter relay and stores data and codes for communication with the transponder chip
   - The function of the EWS II module is to provide improved drive away protection for the vehicle and it incorporates many features of previous systems:
     - Lock out of the *starter* when the code function of the *BC* is set
     - Disable the injection and ignition through the DME
     - Prevent starter engagement with the engine running
     - Recognition of the 'Park/Neutral' position in automatic transmission
   - New features that have been added are:
     - Disable injection, ignition and starter operation until a correct key is recognized
     - EWS and DME synchronization through the use of the ISN
     - Release of *double lock* when a correctly coded key is switched on
   - The EWS II control module stores the following data for the key transponder *inter-link*:
     - Key identification code- up to 10 keys
     - Key password
     - Changing code- up to 10 keys
5. DME
   - The DME is redesigned to incorporate the new ISN code implementation
   - As of production models manufactured from 1/95, all ECU/DME will contain the unique ISN number and will not interchange with previous DME's
   - The following new features are added to the DME:
     - Unique ISN assigned to DME during production (can not be changed/ altered/overwritten)
     - The BC code input to the DME is eliminated
     - The DME and EWS II control module must be synchronized
     - The DME sends the ISN to the EWS II module which stores the number to be replied by the DME
     - The ISN received from the EWS II module during start-up is compared to the internal ISN of the DME
     - The numbers must match before the start operation is allowed to continue
     - The ISN is sent to the DME continuously by the EWS II module with the key "ON"
     - The DME will ignore loss of the ISN after the engine is running
     - The DME retains the ISN information from the EWS II module for 10 seconds after the ignition is switched "OFF"
   - Restarting or switching the ignition on within the 10 seconds cancels the key identification process.

### BMW 5-Series E34

**Models from MY.01/1992 - MY.12/1994:** The built-in BMW E34 immobiliser module named "EWS-I" (ie. *EWS1*) came out in all BMW E34 manufactured from year 1992, up to end of 1994.

**Models from MY.1995:** The BMW E34 immobiliser module named "EWS-II" (ie. *EWS2*) has been used in all production modules manufactured from year 01/1995. This type of immobiliser was implemented in more robust way, and is therefore more invasive and complicated.

{{< details "EWSII bypass on BMW E34 via EWSI module" >}}
It's possible to bypass EWS2 immobiliser module on BMW E34 having the EWS1 chip from another older model ECU/DME that supports it. The procedure requires you to cut two big wires from the original EWS2 module in your BMW E34 and *jump/short* them - ie. by connecting them together. Then, using the EWS1 chip from the older version DME, the procedure requires you to open up original ECU/DME of your EWS2 BMW E34, and replace the EWS2 chip, with the one of the older version EWS1 chip from the donor DME. More detailed explanation can be seen in this [video](http://www.youtube.com/watch?v=lGhaDwDddf4) that shows how to do it on BMW E36 models, but same can be applied to BMW E34 as well. The EWS module on BMW E34 is located under the steering wheel rack enclosure, unlike the BMW E36 which has the EWS located inside the glove box, behind the plastics.
{{< /details >}}

**Module Location:** On all BMW E34, and on some BMW E36 models, the EWS II module is located on the drivers side of the vehicle, under the steering wheel, specifically, behind the left knee bolster plastic. On BMW E31, E38, E39 and some E36 models, the EWS II control module is located behind the glove box in the electrical carrier.

### Other Resources

* [Drive Away Protection/EWS I/II/III Technical Documentation (PDF)](http://www.unofficialbmw.com/images/BMW_EWS.pdf)
* [DIY Immobilizer Bypass on swapped ECU for older Toyota vehicles](https://www.instructables.com/DIY-Immobilizer-Hacking-for-Lost-Keys-or-Swapped-E/)
* [How to test BMW EWS v2 before replacement](https://www.rpmmotorsport.net/pages/bmw-ews2-testing-before-replacement)