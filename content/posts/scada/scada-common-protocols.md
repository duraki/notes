---
title: "Common Protocols in SCADA/ICS/OT"
url: "/scada/protocols"
---

## General Information

SCADA/ICS systems are differentiated from traditional information systems in a number of ways. Probably the most important differentiation are the many communication protocols. Unlike traditional IT systems with their standardized TCP/IP protocols, SCADA/ICS systems are marked by significant variation in their communication protocols.

### Manufacturers in SCADA Industry

There are numerous SCADA/ICS protocols sometimes different protocols within the many manufacturers of hardware. The major manufacturers of SCADA/ICS hardware include:

- Seimens
- Honeywell
- Toshiba
- Allen-Bradley
- Mitsubishi
- GE
- Schneider Electric
- Rockwell Automation
- *and others ...*

{{< notice >}}
Note
{{< /notice >}}
{{< callout emoji="💡" text="Each of these companies makes varied industrial products and therefore use various different protocols, some of which are proprietary and not publicly available or documented. This is one of the many reasons that securing SCADA/ICS systems can be so challenging. At the same time, this industry has benefited from security through obscurity as many attackers are unfamiliar with these protocols, but on the other side, the consultants who are engaging in these fields must throughly understand the environments and systems they are targeting and testing." >}}

### Common Protocols

Among many manufacturers available on the market that produces the PLC and/or other SCADA/ICS systems, there are numerous communication protocols as well. To successfully engage and execute penetration testing on these systems, consultants need at least a rudimentary understanding of these protocols to deliver proper results.

The most widely used protocols in ICS are:

- Modbus (*Usual Port*: `502`)
- DNP (*Usual Port*: `19999`) & DNP3 (*Usual Port*: `20000`)
- ICCP
- CIP (Common Industrial Protocols)
- EtherNet/IP (*Usual Port*: `2222`)
- CompoNet
- ControlNet
- DeviceNet
- OLE/OPC (Process Control)
- Profinet/PROFIBUS (*Usual Port*: `34962-34964`)
- Fieldbus H1 (*Usual Port*: `1089-1091`)
- EtherCAT (*Usual Port*: `34980`)
- *and others ...*

Each of the aftermentioned protocols operates slightly differently, and in some cases, almost totally differently. This section describes short and summarized description of the most common protocols, and these that are used most widely in such systems.

## Modbus

SCADA/ICS systems use many different protocols to communicate than your standard IT systems. The most widely used and the de facto standard is the modbus protocol. Reference to [this link](https://hackers-arise.com/scada-hacking-modbus-master-slave-simulation/) on how to setup modbus master/slave simulation on your local environment for testing and playground purposes.

### Modbus Serial (RTU)

Modbus RTU was first developed in 1979 by Modicon (now part of *Schneider Electric*) for industrial automation systems and **Modicom PLC’s**. It has become the industry standard for a long time. Modbus is widely-accepted, public domain protocol. It is simple and lightweight protocol intended for serial communication, and it has data limit of 253 bytes.

The protocol itself operates at "*Layer 7*" on the OSI model, therefore, there is an efficient communication between the interconnected devices using a simple "`request <-> reply` model. Due to its' simplicity and being lightweight, it requires little processing power and is quite fast when it comes to syn-acking the requests between the connected devices or subsystems.

Modbus was first implemented on either `RS-232C` (ie. *point-to-point*) or `RS-485` (ie. *multi-drop*) physical topology, allowing it to connect up to *32 devices* communicating over a serial link, with each device having a unique ID that is used to represent itself to the network.

Modbus uses a *master/slave* (in simple terms, a *client/server*) architecture. Therefore, only one device can initiate queries or send data messages or requests. The slave device (or *server*), supply the requested data to the master (ie. a *client*), or it might perform an action requested by the master itself. A slave is any peripheral device (*I/O transducer*, *valve*, *network drive*, or *other measuring device*, be it [analog](/ac-voltage-signals) or [digital](dc-voltage-signals) - which in turns processes retrieved information, value or data, and sends its output to the master using the modbus protocol.

The master (or multiple *master devices*) can address individual slaves and/or initiate a broadcast message to all connected slaves. Once received, the slave devices return a response to all queries addressed to them individually, alas, **they do not respond to broadcast queries back to the network**. Therefore we can say that the **slave devices do NOT initiate messages**, meaning **they can only respond to the master**. A master’s query will consist of the slave address (using the "Slave ID" or "Unit ID" identifying the device which is queried), alongside with a *function code*, and including any required data and/or error checking fields that might be required for this query.

The modbus protocol communicates over master/slave interconnection using the "*Function Codes*". These "Function Code" snippets can be used to perform a wide-range of commands.

Reference to table below describing **modbus function codes**:

| Function Code | Function Name                          |
|---------------|----------------------------------------|
| 01            | Read Coil Status                       |
| 02            | Read Input Status                      |
| 03            | Read Holding Registers                 |
| 04            | Read Input Registers                   |
| 05            | Force Single Coil                      |
| 06            | Preset Single Register                 |
| 07            | Read Exception Status                  |
| 09            | Program 484                            |
| 0A            | Poll 484                               |
| 0B            | Fetch Communication Event Counter      |
| 0C            | Fetch Communication Event Log          |
| 0D            | Program Controller                     |
| 0E            | Poll Controller                        |
| 0F            | Force Multiple Coils                   |
| 10            | Preset Multiple Registers              |
| 11            | Report Slave ID                        |
| 12            | Program 884/M84                        |
| 13            | Reset Communication Link               |
| 14            | Read General Reference                 |
| 15            | Write General Reference                |
| 16            | Mask Write 4X Register                 |
| 17            | Read/Write 4X Registers                |
| 18            | Read FIFO Queue                        |

{{< notice >}}
Explanation of Function Codes
{{< /notice >}}
{{< callout emoji="💡" text="The function codes are used in the Modbus RTU to query or perform a wide-range of command and functions from the master device. Each function code can be queried from the master to the slave devices, eventually receiving the information needed to allow proper functioning of the industrial site. Looking at the table, one can see that the function code '08' in the table is missing - the reason for this is that the '08' function code is reserved and used as 'diagnostic function code'. Within the function code '08' there are number of other sub-function codes." >}}

Reference to table below describing **modbus sub-function codes**:

| Function Code | Sub-Function Code | Function Name                               |
|---------------|--------------------|--------------------------------------------|
| 08            | 00                 | Return Query Data                          |
| 08            | 01                 | Restart Communication Option               |
| 08            | 02                 | Return Diagnostic Register                 |
| 08            | 03                 | Change ASCII Input Delimiter               |
| 08            | 04                 | Force Listen Only Mode                     |
| 08            | 05-09              | Reserved                                   |
| 08            | 0A                 | Clear Counters and Diagnostic Reg.         |
| 08            | 0B                 | Return Bus Message Count                   |
| 08            | 0C                 | Return Bus Communication Error Count       |
| 08            | 0D                 | Return Bus Exception Error Count           |
| 08            | 0E                 | Return Slave Message Count                 |
| 08            | 0F                 | Return Slave No Response Count             |
| 08            | 10                 | Return Slave NAK Count                     |
| 08            | 11                 | Return Slave Busy Count                    |
| 08            | 12                 | Return Bus Char. Overrun Count             |
| 08            | 13                 | Return Overrun Error Count                 |
| 08            | 14                 | Clear Overrun Counter and Flag             |
| 08            | 15                 | Get/Clear Modbus Plus Statistics           |
| 08            | 16-UP              | Reserved                                   |

{{< notice >}}
Explanation of Sub-function Codes
{{< /notice >}}
{{< callout emoji="💡" text="The function code '08' allows for quering other 'sub-functions codes', therefore querying function code '08' with '04' on the modbus devices could eventually lead to a DoS (Denial-of-Service) condition, since the '04' sub-function code is used to 'Force Listen Only Mode', allowing other slave devices to constantly send out their data to the master device, leading to potential distrubtion of the industrial site." >}}

### Modbus TCP

Modbus TCP is the Modbus protocol encapsulated for use over the typical IT's `TCP/IP` network stack. It uses the same `request/response` message data model (ie. *function codes*) as the Modbus RTU. Since it uses the same function codes as with the typical Modbus RTU protocol, the same data limit applies for which only 253 bytes can be sent over the network. The *error checking field* used in Modbus RTU **is eliminated** as the TCP/IP link layer uses its own checksum methods, eliminating the need for the Modbus RTU checksum. **Modbus TCP utilizes** the **reserved port 502** to communicate over TCP/IP for interconnected master-slave devices.

Modbus TCP also adds additional "*Modbus Application Protocol*" (usually refered as `mbap`) to the actual Modbus RTU frame. This is *7 bytes* long type data, with *2 bytes* used for the header, *2 bytes* used as the protocol identifier, *2 bytes* describing the length of the data, and the leftover *1 byte* used for the address or the ID of the slave (*Unit/Slave ID*).

### Modbus Security

Modbus has numerous security concerns; some of the simple one to understand are listed below:

* **Lack of authentication** – modbus does not include any form of authentication out-of-the box, therefore an attacker only needs to craft a specific modbus frame packet containing a valid address (ID), a function code, and any other associated data
* **No implemented encryption** – all communication over Modbus is done in cleartext, unencrypted protocol, therefore, potential attackers can sniff (MiTM) the communication between the master and the slaves, and discern the configuration and use-case of the sites' subsystem
* **No implemented checksum** – although *Modbus RTU* uses a message checksum natively, when modbus is implemented over the typical `TCP/IP` network frames, **the checksum is generated** in the *transport layer*, **not the application layer**, enabling the attacker to spoof modbus packets for future exploitation
* **No Broadcast Suppression** – without broadcast suppression, since all addresses (ie. *master/slave* IDs) receive all messages, the attacker can create a DoS condition by abusing the protocol and flooding the network with data messages, function codes, and queries

**References:**

* [Using `modbus-cli` to engage on TM221 Modicon PLC](https://hackers-arise.com/scada-hacking-hacking-the-schneider-electric-tm221-modicon-plc-using-modbus-cli/)

---

## DNP/DNP3

One the most important distinguishing characteristics of SCADA/ICS systems from that of traditional IT systems is that these systems communicate by distinctly different and, sometimes, proprietary protocols. This section examine probably the second most widely used protocol among SCADA/ICS systems called "*Distributed Network Protocol 3.0*" or **DNP3**.

DNP3 was first developed by *Westronic* (now a division of "*GE-Harris*") and was released in 1993. This protocol is widely used among the electrical, oil and gaspipe industry, alongside the wastewater/water utilities and systems. It is preferred among the electric utilities, in part, because;

- (1) *it is resistant to EMI-induced distortion*,
- (2) *it works reliably over varied and low-quality media*,
- (3) *it can address 65,000 devices in a single link*

All these characteristics that are highly-valued among electric and electrical distribution utilities, the oil and gas industry, and similar other sectors with widely remote field stations. The DNP3 protocol was based upon the early drafts of **IEC 60870-5**, and the DNP3 was extended in 1998 to be encapsulated in either a TCP or UDP packet (usually the former is used, ie. *TCP*), and is usually configured to work over the TCP port `2000`.

Importantly, the DNP3 is a robust, flexible, reliable, and its also non-proprietary (ie. is [community managed](dnp.org)) communication protocol. It supports great functionalities such are *multiple data types*, *multiple master stations* are supported for outstations, data types *may be assigned priorities*, *time synchronized* and *time-stamped* events (timesync is very important in SCADA/OT/ICS environments), can *broadcast messages*, and conforms to *data link layer* and *application layer*.

DNP3 is usually configured in a `client<->server` configuration, much like [Modbus](#modbus); where **the control center** (CC/PCCM) **is the SCADA client and the server** within the other remote units (*RTU*, *PLC*, *IED*, et al). The+ differences against the Modbus are obvious and includes extras, where outstation can send an **unsolicited response** to the master (unlike modbus, which allows only master to send unsolicited response), allows for report by exception (ie. *RBE*) - meaning that the SCADA server polls for change of events, and has defined other layers including *application*, *transport* and *data link* layers.

### DNP3 Communication

Each DNP3 packet starts with two bytes `0x05` and `0x64`. These are usually referred to as the "start bytes" or "start frame" bytes or "magic bytes". This starts the *Data Link Layer* frame which is the initial (foremost) section of a single DNP3 packet frame.

The "*Application Layer*" section of the packet includes the instructions, defined similarly to modbus [Function Codes](#modbus). Note that the "Function Code" with byte `0x12` has command to "**Stop Application**". This can be abused to effectively create a Denial-of-Service (DoS) attack, if sent/spoofed by an attacker.

Reference to table below describing **DNP3 function codes**:

| Function Code | Function Code Description              |
|---------------|-----------------------------------------|
| 0x00          | Confirm Function Code                   |
| 0x01          | Read Function Code                      |
| 0x02          | Write Function Code                     |
| 0x03          | Select Function Code                    |
| 0x04          | Operate Function Code                   |
| 0x05          | Direct Operate Function Code            |
| 0x0d          | Cold Restart Function Code              |
| 0x0e          | Warm Restart Function Code              |
| 0x12          | Stop Application Function Code          |
| 0x1b          | Delete File Function Code               |
| 0x81          | Response Function Code                  |
| 0x82          | Unsolicited Response Function Code      |

### DNP3 Security

As is the case with [Modbus](#modbus), similarly, the DNP3 protocol was developed **before security was a major concern**. As a result, DNP3 has no *built-in security*. For instance, **there is no authentication or encryption**; the lack of authentication and also encryption combined with the **standardization of the function codes and data types**, makes spoofing and eavesdropping attacks relatively simple and straightforward.

There are a number of well-known vulnerabilities and exploits in the wild against DNP3 devices and services. These include MiTM attacks, DoS attacks, manipulating time synchronization, suppressing alarms or trigger and more similar widely known examples. 

{{< notice >}}
Implementation of DNPSec v5
{{< /notice >}}
{{< callout emoji="💡" text="The 'DNPSec v5' has been developed in response to address security concerns on the default DNP3 frame and communication mechanism, therefore trying to prevent spoofing, modification, replay attacks, and eavesdropping. As of today, this new and more secure standard has yet to be widely accepted and implemented by the industry manufacturers." >}}

## PROFINET/PROFIBUS

**PROFIBUS** (*Process Fieldbus*) is an *open standard* for industrial communication originally developed in Germany. It began from a joint effort of 21 companies and institutions named the **ZVEI** (short for, *Central Association for Electrical Industry*). This group has been led by the German industrial giant Seimens, and as a result, the PROFIBUS is widely used in Seimens products (in fact, the Seimens controllers that were exploited by Stuxnet in the Iranian nuclear facility at Natanz were running PROFIBUS).

PROFIBUS is a smart, bi-directional protocol where many devices are all connected to one cable or bus. The data frame can represent either "analog" or a discrete "ON/OFF" values. All of the PROFIBUS devices are inter-operable. The low cost, simplicity and high-speed of this protocol makes it an official SCADA industry sites standard. The PROFIBUS protocol uses a *two-wire connection*, for both **power** and the **data transmission**.

Similar to other SCADA/ICS protocols, the PROFIBUS is also a `master-slave` oriented protocol that supports *master* nodes to operate using the token sharing mechanism. Similar to IBM’s legacy *token-ring protocol*, only when the *master* has the "token" can be able to communicate to the rest of the *slaves*. Each PROFIBUS slave can only communicate with one master. The **master node** in PROFIBUS is usually either a *PLC* or an *RTU*, while the slaves typically designed to be *sensors*, *motors*, *actuators* or similar other control/sensory devices.

### Types of PROFIBUS

There are variety of PROFIBUS protocols, each with its own quirks and pluses. These are listed below:

* PROFIBUS FMS
* PROFIBUS DP (*Decentralized Periphery*)
* PROFIBUS PA (*Process Automation*)

The section below shortly explains and describes the difference between each of them.

**PROFIBUS FMS**

This was the initial PROFIBUS protocol described as the 'FMS' type. It was designed to communicate between the industry PLC’s and relevant PC’s with-in the SCADA networks, systems and subsystems. Unfortunately, this simple protocol was not very flexible and, as result, it was not possible to set it up to work in a more complex and complicated networks. Although still in use, the vast majority of PROFIBUS networks use one of the newer versions, either the **DP** or the **PA** types.

**PROFIBUS DP** (Decentralized Periphery)

The "PROFIBUS DP" type supports several different physical layer medias, including the "RS-485", similar to the original [modbus](#modbus) implementation. This configuration enables PROFIBUS to operate at need, with up to `12 Mbps` in data transmission speeds. The "PROFIBUS DP" is probably the most common of the PROFIBUS protocols used widely in the industrial sites. It is simpler and faster than the other types of PROFIBUS and it comes in three separate versions, **DP-V0** (*Cyclic Data Exchange*), **DP-V1** (*Acyclic Data Exchange*), and the **DP-V2** (*Isochronous Slave-to-Slave Mode & Data Exchange*), where each of the version offers additional features or functionalities.

**PROFIBUS PA** (Process Automation)

The "PROFIBUS PA", as the name implies, was developed for *Process Automation* industrial sites. The *PROFIBUS PA* standardizes the process of transmitting measured data and, in addition, was designed and developed to be used in a hazardous environments. This was entirely possible by using the "*Manchester Bus Powered*" (**MBS**) technology that uses lower power and thus reduces the chance of sparks and explosions in such critical infrastructures.

### PROFIBUS Security

Like many other SCADA/ICS protocols, similarly, **the PROFIBUS lacks authentication** as well. This means that any *node/slave* **can spoof a master node**. Since only the master node can control the slaves, this is a major security concern - a **spoofed master node** would be capable to capture the *required* token, *disrupt node functions*, and even cause a Denial-of-Service (DoS). It's important to mention that the "PROFIBUS DP" version uses a *serial connection*, therefore the physical access would be required for an attacker. Alas, the industry has shown again and again that most of the *master nodes* in a "PROFIBUS DP" networks **are connected to an Ethernet** network, making them susceptible to nearly any type of ethernet based attack (ie. over the network, without physical access).

**PROFINET** (Process Field Net)

The "PROFINET" (*Process Field Net*) is another open standard for industrial automation designed for scalability. Instead of exchanging data using the field bus (ie. *serial*), it instead uses Ethernet (*IEEE802.3*) as a transfer medium. It is included as part of **IEC61158** and **IEC61784**. Initially, it employed a standard TCP/IP packet frames. Since it uses standard TCP/IP frames, the PROFINET has a particular strength in delivering large data under tight time constraints where the critical infrastructure expects very high precision. The PROFINET uses IT standards, both the *TCP/IP* and even typical *XML* to communicate with the other devices, and similar standards are used to *configure* and *diagnose* machines, and devices. PROFINET operates at `100Mbit/s` over twisted pair or fiber optic cables making it really great for a high precision environments.

{{< notice >}}
IMPORTANT: PROFINET is not a PROFIBUS
{{< /notice >}}
{{< callout emoji="⚠️" text="The PROFINET protocol IS NOT a 'PROFIBUS over Ethernet', but since they are compatible with the use of additional proxy, its easy to bridge them and have them in the same subsystem networks." >}}

The PROFINET protocol has two function classes: `PROFINET I/O` *(Input/Output)*, and the `PROFINET CBA` *(Component Based Automation)*. With "PROFINET I/O", the protocol allows for connection to the distributed field devices and uses "*real-time*" (`RT`) and "*non real-time*" (`TCP/IP`) communications.

- The "*real-time*" (`RT`) channel is used for time critical data: cyclic process data, alarms, and communication monitoring, and is capable of cycle times of ~10ms
- The "*non real-time*" (`TCP/IP`) channel is used for downloading configuration and parameters, diagnostics, device mgmt, information, and other non-time critical communication with reaction times in the range of ~100ms

In addition to that, a `PROFINET IRT` ("*isochronous real-time*") is used in a drive-operated systems with cycles times of less than ~1ms; it's a hardware-based Layer 2 technology, and therefore it is not routeable. Alongside, the `PROFINET CBA` is designed for *distributed industrial automation* applications, built on the standard **DCOM** (*Distributed Component Model*) and **RPC**'s (*Remote procedure Call*) and **thus inherits the vulnerabilities of both DCOM and RPC** Profinet I/O uses default TCP/UDP Ports `34962`, `34963` and `34964`; the port reserved on `34964` is used for *connectionless* RPC. On other side, the `Profinet CBA` uses default TCP port `135` for communciation.
