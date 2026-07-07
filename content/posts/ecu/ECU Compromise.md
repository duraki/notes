---
title: "How to compromise ECU"
---

Steps to compromise [ECU](/ecu-foundations/) are as following:

1. [Identifying ECUs](#ecu-identification-fingerprinting) for potential vehicle intrusion (_fingerprinting_)
2. Remote access to ECU or similar attack proximity identification
3. Access to in-vehicle network via gateway, vulnerable ECU or other vehicle subsystem
4. Bridging domain boundaries using [reverse engineering](#ecu-reverse-engineering)
5. Access to targeted ECU over gateway or directly 
6. Manipulating ECU or vehicle behavior via different vectors

Find more info about Car Hacking on [notes](/posts).

Potential automotive cyber attacks surface and vectors are mentioned in [here](https://payatu.com/blog/automotive-attacks/).

## ECU Identification (Fingerprinting)

Modern vehicles contain tens of Electronic Control Units (ECUs), several of which communicate over the Controller Area Network (CAN) protocol. As such, in-vehicle networks have become a prime target for automotive network attacks. To understand the security of these networks, we argue that we need tools analogous to network mappers for traditional networks that provide an in-depth understanding of a network's structure. [An automotive network mapping tool](https://www.usenix.org/conference/usenixsecurity19/presentation/kulandaivel) that assists in identifying a vehicle's ECUs and their communication with each other [has been developed by researchers](https://www.usenix.org/conference/usenixsecurity19/presentation/kulandaivel), providing design and implement of **CANvas**, an automotive network mapper that _identifies transmitting_ ECUs with a pairwise clock offset tracking algorithm and identifies receiving ECUs with a forced ECU isolation technique, as desribed in the [whitepaper published here](https://www.usenix.org/system/files/sec19-kulandaivel.pdf). 

To compromise in-vehicle [Electronic Control Units](/ecu-foundetaions/) (ECUs) and control the vehicle maneuver, initial step is required during the _recon_ phase which includes identifying ECUs to gather information of safety-critical systems and other in-vehicles components, relevant to other attack vectors and techniques. To fingerprint the ECUs and counter potential vulnerabilities (_incl._ defense mechanisms, strong protection, segemntation of safety-critical ECUs, protectiona gainst in-vehicle network attacks), an attacker can use a set of periodic in-vehicle messages sent to the vehicle system network. Over the CAN bus, using this method, the tested vehicles and bench prototypes can reveal wide range of ECUs and their informational data, allowing an attacker to further expand attack surface.

See the external reference: [Fingerprinting ECUs for Vehicle Intrusion Detection](https://www.usenix.org/conference/usenixsecurity16/technical-sessions/presentation/cho), a research paper published in 2016 describing software modules and external interfaces that are prone to different fingerprinting techniques via CUSUM detection.

[This research](https://www.usenix.org/conference/usenix-security-11/comprehensive-experimental-analyses-automotive-attack-surfaces) published in 2011 and titled "Comprehensive Experimental Analyses of Automotive Attack Surfaces" presents feasible and broad range of attack vectors that can be executed against vehicle systems in a remotely-based surface, and while previous research has shown that the _internal networks within some modern cars are insecure_, the associated **threat model**, ie. **requiring prior physical access** has justifiably been viewed as unrealistic, this works seeks to put this question to rest by systematically analyzing the external attack surface of a modern automobile.

The presentation and whitepaper showcased in [Plug-N-Pwned: Comprehensive Vulnerability Analysis of OBD-II Dongles as A New Over-the-Air Attack Surface in Automotive IoT](https://www.usenix.org/conference/usenixsecurity20/presentation/wen) detailed comprehensive security analysis on all wireless **OBD-II** [OBD](/obd) dongles available on Amazon in the US (as of _Feb, 2019_).

## ECU Reverse Engineering

In-vehicle protocols are very important to the security assessment and protection of modern vehicles since they are used in communicating with, accessing, and even manipulating [ECU](/ecu-foundations/)s (Electronic Control Units) that control various vehicle components. Unfortunately, the majority of in-vehicle protocols are proprietary systems, without adequant publicly-available documentations. Although recent studies proposed different methods to reverse engineer the CAN protocol used in the communication among ECUs (ie. UDS), they cannot be applied to vehicle diagnostics protocols, which have been widely exploited by attackers to launch remote attacks.

Take a look at external reference: [Towards Automatically Reverse Engineering Vehicle Diagnostic Protocols](https://www.usenix.org/conference/usenixsecurity22/presentation/yu-le), describing a novel framework used to automatically reverse engineer vehicle diagnostic protocols by leveraging professional diagnostic tools for vehicles. This research has been published in 2022 and is still usable today both as a backlink reference and threat model investigation. Its highly advised to read [Automatic Wireless Protocol Reverse Engineering](https://www.usenix.org/conference/woot19/presentation/pohl) whitepaper first, and then move on the _aftermentioned_ vehicle diagnosting protocols research paper, easing the process of understanding the prior linked reference. Interestingly enough, students at UOM (University of Michigan) have documented their research on [Automated Discovery of Denial-of-Service Vulnerabilities in Connected Vehicle Protocols](https://www.usenix.org/conference/usenixsecurity21/presentation/hu-shengtuo) using CV (_Connected Vehicle_) technologies, a wireless communication protocol used in modern vehicles, allowing traffic infreastructure and other vehicle exchange systems, therefore allowing "safety and mobility information exchange in real time", however, the integreated capability has increased vehicle attack surface, resulting in other security oriented consequences - including flaws and issues in this communication protocol, especially due to its remote requirements.

**References**

* [KeenLab: Experimental Security Assessment of BMW Vehicles](https://keenlab.tencent.com/en/2018/05/22/New-CarHacking-Research-by-KeenLab-Experimental-Security-Assessment-of-BMW-Cars/)
* [KeenLab: Exploiting Wi-Fi Stack on Tesla Model S](https://keenlab.tencent.com/en/2020/01/02/exploiting-wifi-stack-on-tesla-model-s/)
* [Updating Maps in RNS315 Radio Navigation Multimedia](https://blog.danman.eu/updating-rns315-maps-for-fun-and-profit/)
* [Playing with CANBus with CAN Controller](https://blog.danman.eu/playing-with-can-bus/)
* [Recovering an ECU Firmware using Disassembler and Branches](https://blog.quarkslab.com/recovering-an-ecu-firmware-using-disassembler-and-branches.html)
* [Usenix.org ~ Fingerprinting ECUs on a vehicle (`pdf`)](https://www.usenix.org/system/files/conference/usenixsecurity16/sec16_paper_cho.pdf)
* [Usenix.org ~ Towards Automatically Reverse Engineering Vehicle Diagnostic Protocols (`pdf`)](https://www.usenix.org/system/files/sec22-yu-le.pdf)
* [Presentation: Security and Privacy Vulnerabilities of In-Car Wireless Networks: A Tire Pressure Monitoring System](https://www.usenix.org/conference/usenixsecurity10/security-and-privacy-vulnerabilities-car-wireless-networks-tire-pressure) (Case Study) ~2010
* [Presentation: Comprehensive Experimental Analyses of Automotive Attack Surfaces](https://www.usenix.org/conference/usenix-security-11/comprehensive-experimental-analyses-automotive-attack-surfaces) **Remote Attacks** ~2011
* [Whitepaper: Application level attacks on Connected Vehicle Protocols](https://www.usenix.org/conference/raid2019/presentation/abdo) **Application-level Attacks** ~2019
* [Whitepaper: A Security Analysis of an In-Vehicle Infotainment and App Platform](https://www.usenix.org/conference/woot16/workshop-program/presentation/mazloom) **Application-level Attacks** on Infotainment Systems ~2016
