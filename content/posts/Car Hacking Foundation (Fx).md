---
title: "Automotive Hacking"
---

- Readout publication, and expand your knowledge:
  - [Remote Exploitation of an Unaltered Passenger Vehicle](https://illmatics.com/Remote%20Car%20Hacking.pdf)
  - [Car Hacking: For Poories](https://illmatics.com/car_hacking_poories.pdf)
  - [Adventures in Automotive Networks and Control Units](https://illmatics.com/car_hacking.pdf)
  - [Securing Self-Driving Cars](https://illmatics.com/securing_self_driving_cars.pdf)
  - [A Survey of Remote Automotive Attack Surfaces](https://illmatics.com/remote%20attack%20surfaces.pdf)
  - [CAN Message Injection](https://illmatics.com/can%20message%20injection.pdf)
  - [Experimental Security Analysis of a Modern Automobile](https://www.autosec.org/pubs/cars-oakland2010.pdf)
- Link [ECUs](/ecu-foundations) to avoid wires (weight, size, cost)
  - [ECU Programming](/ecu-programming)
- Network Protocols allow ECUs to share information quickly and precisely ([Ethernet](/ethernet-specifications) & [CANFD/CAN](/canfd-specifications))
- Networks used between ECUs are based on Serial Communications
  - Serial means that items of information are sent via a single stream of communication
- Speed of communication is measured in number of bits sent per second (bps)
- CAN (Controller Area Network) bus was developed to meet needs of up to 1 million bits per second (1Mbps)
- LIN (Local Interconnect Network) introduced to give a lower cost, lower speed altenative (~20 kbps)
- FlexRay was developed for more fault-tolerant, higher speed (10Mbps) network
- Ethernet (100Mbps) for videos and advanced driver assistance systems (new vehicles)

Special ECU are used called "gateways" to interconnect different network protocols (CAN + LIN, or Ethernet + FlexRay etc.)

## Vehicle Diagnostics

- [ECUs](/ecu-foundations) provide diangostis services
- OBD standardises requests and responses related to diagnostics
- ISO 14229-1 (UDS) Standard
  - Defines structures and content of how data is interpreted
- Read Fault Memory in the form of Diagnostic Trouble Codes from the ECU (detect faults)

## Attack Classes

In the context of automotive systems, an attack is an action that is performed by an adversary that aims to either compromise the vehicle information or the vehicles ability to carry out its operational, security, or safety objectives. One might wonder why would an adversary attack a vehicle in the first place. As we have seen from famous hack of enterprise and IT systems, one main motivation for attackers is financial gain. A classic attack example is to roll back the vehicle odometer to cheat the leasing company from mileage overage charges. A more recent type of attack on vehicles is bypassing electronic security systems to facilitate vehicel theft. Another financially motivated attack is modifying vehicle features to gain better performance or unlock features that the **original equipment manufacturer** (OEM) hides behind a paywall. But not all attackers are financially motivated as some organized crime or even nation states may be interested in mounting attacks that cause targeted crashes and mass casualities. Throw in the prospect of autonomous driving and heavy-duty trucks, and you can start seeing a bigger attack space in which attackers are motivated to cause mass chaos against people and infrastructure. From a computer security perspective, attacks can be classified as either passive or active.

{{< notice >}}
Important Errata
{{</ notice >}}
{{< callout emoji="✅" text="Attack types should not be confused here with attack techniques. To learn about attack techniques, you are encouraged to check out the MITRE corporation’s Industrial Control Systems (ICS) Attack Matrix due to its relative similarity to the automotive control systems." >}}

### Passive Attacks

When performing passive attacks, the attackers primary objective is to gather information about the target without being discovered. Whether it is an IT network or a vehicle network, a passive attack will involve some form of eavesdropping or reconnaissance activity. Taking the example of the in-vehicle network, such is [CAN](/canfd-specifications), a passive attack against such networks involves a malicious network participant who is listening on the communication channel and recording the protocol message data (ie. CAN, FlexRay, or Ethernet frame). The figure below shows a sample CAN network trace in which an attacker managed to record messages from the engine and breaking [Electronic Control Units (ECUs)](/ecu-foundations). Once the network traffic has been recorded, the attacker can later replay those frames to manipulate vehicle functionalities - for example, they can cause an unsafe change regarding the engine or ABS functions. The other nodes on the vehicle network are unable to detect this type of attack because listening to the network traffic is considered normal behaviour.

{{< imgcap title="CAN message traffic captured using Vector CANalyzer" src="https://i.imgur.com/XaEbuZd.png" >}}

Another common type of passive attack is intercepting software updates that are intended to modify the vehicle software. An attacker who positions themselves between two parties without their knowledge is commonly referred to as a **man-in-the-middle** (MITM). In the software update scenario, an MITM can capture a software binary package with the intent of analyzing its contents. If the attacker can disassemble the binaries, they may discover a vulnerability that can be exploited through a different attack path. In the next few sections, we will learn how to limit the impact of passive attacks through cryptographic methods that can conceal data and reduce the likelihood of undetected message replay.

{{< notice >}}
Note
{{< /notice >}}
{{< callout emoji="💡" text="MITM attacks are also used in active attacks, where the MITM aims to modify the data that they are intercepting, as we will see next." >}}

### Active Attacks

Active attacks require interference with the target through modification, deletion, insertion, or blocking of data or system functions. While attackers interfering with a target ECU or vehicle network are normally not worried about being detected, in cases of nation state or sophisticated threat agents, they may be interested in hiding their traces to prolong the exploit as long as possible. Lets explore the various type of active attacks.

**Spoofing**

With spoofing, the attacker’s objective is to masquerade as another party when communicating with the target, making the target believe that the communication is coming from a trusted source. When the target does not properly verify the identity of its peers or the source of the data that its consuming, spoofing attacks become possible. An example spoofing attack is when a fake diagnostic tester initiates a diagnostic session and requests a restricted diagnostic service. If the ECU does not verify the identity of the diagnostic client, the fake client can masquerade as a legitimate diagnostic tester, resulting in the execution of privileged services such as rolling back the odometer to a lower mileage value. Another popular spoofing attack is constructing messages with CAN identifiers that belong to other ECUs on the CAN network. The receiving ECU is unable to determine if the message truly originated from the source ECU or has been constructed by another entity masquerading as the source.

**Replay**

The attacker’s objective is to cause the target to react to old data. If the target ECU does not check for data freshness, then replay attacks become possible. As we saw with passive attacks, a successful eavesdropping attack results in the attacker possessing communication messages that can be replayed at the time of the attacker’s choosing. One of the easiest ways to influence a vehicle network is to replay old CAN messages to cause the desired change in the vehicle’s behavior, such as increasing the engine’s torque. Another example is replaying diagnostic commands that have been captured from a diagnostic client to access privileged services.

**Tamper**

The attacker’s objective is to interfere with the target by inserting, deleting, or modifying its data or system functions. Tampering attacks in automotive systems can affect the ECU configuration settings, the ECU firmware or calibration data, sensor input data, vehicle network inputs, and more. To tamper with the ECU firmware, the attacker may launch a passive attack to capture the unmodified ECU firmware. Then, through careful analysis, the attacker can determine the parts of the firmware that need modification to produce the desired adverse effect. Finally, the attacker needs a way to program the tampered ECU firmware into the target, such as through a replay of the flash programming sequence (through the flash bootloader), but this time using the tampered ECU firmware. The attacker may also be an MITM who can intercept the data, modify it, and retransmit it without the knowledge of the original sender and target receiver. For vehicle network messages, tampering attacks can target the physical layer to manipulate individual message frame bits.

**Denial of Service**

“The attacker’s objective is to reduce or completely disable the functions of the target. **Denial of Service** (DoS) attacks have a wide scope in automotive systems. An example of a powerful DoS attack is erasing the ECU firmware, resulting in a bricked ECU. With network data, a common DoS attack is transmitting back-to-back CAN messages with the highest priority CAN identifier to deny other ECUs access to the shared CAN bus. In other scenarios, the attacker may terminate a programming session by injecting invalid diagnostic frames that violate the programming sequence and trigger the ECU to terminate the diagnostic session. If done repeatedly, this type of attack would deny an ECU the ability to update its software. Resource exhaustion attacks are a branch of DoS attacks that aim to reduce the target’s ability to perform its normal functions by exhausting its computational resources. For example, a target ECU that gives high priority to externally initiated requests to store data in persistent storage can easily deplete its CPU runtime bandwidth and non-volatile memory capacity as it is overwhelmed by requests for storing data in persistent storage. It is also noteworthy that frequent erasing and programming requests to non-volatile memory can be a powerful attack method to wear out the memory, causing it to eventually fail.

**Side channel attacks**

A special type of attack is one that aims to exfiltrate sensitive data through covert channels, also known as side channels. Like any computer system, automotive systems leak information through various side channels, such as timing, temperature, power, and shared cache memory. Although we have not discussed the topic of cryptographic material yet, one of the primary objectives of side-channel attacks is to discover the contents of cryptographic keys inside an ECU or a smart sensor by observing variations in the side channel. These attacks can be launched from outside the target (if the attacker has physical possession of the device) or from within the target, such as in the case of a multi-tenant domain controller or vehicle computer.

The topic of side-channel attacks is quite rich and therefore we will only present a brief overview focusing on the main areas that impact automotive systems. Typically, the attacker modifies the target hardware so that power or electromagnetic traces can be captured that can be correlated to the key material. Based on the knowledge of the crypto algorithm in use, the attacker can exfiltrate the full key material if enough power traces are captured. Figure below shows an example trace of the power variations of an ECU while a key is in use with the **Rivest-Shamir-Adleman** (RSA) algorithm. This type of analysis exposes the plaintext secret bits of the key while the key is in use by the target hardware:

{{< imgcap title="A trace based on simple power analysis (SPA) to extract the private key used with an RSA implementation" src="https://i.imgur.com/ConLGRr.png" >}}

Side-channel attacks are normally grouped with fault injection attacks. A special category of fault injection attacks, called glitch attacks, can alter the hardware state, causing changes in the software control flow to bypass critical code sections. As a result, we may observe that the CPU skips a specific instruction, leading to certain security critical features being bypassed. One such example is bypassing the boot authentication checks, enabling an attacker to execute non-genuine software on the ECU.

The following figure shows a typical setup where the **device under test** (DUT) is subjected to electromagnetic wave pulses through a glitch controller:

{{< imgcap title="A typical setup for fault injection attacks" src="https://i.imgur.com/VHP4Yok.png" >}}

The probe is positioned at the proper location to yield the desired perturbation in the silicon. This type of fault injection causes a cryptographic function to produce observable changes in the output of the ECU, causing the eventual leakage of secret keys if the ECU is susceptible to these types of attacks. Due to the relative ease and declining cost of acquiring fault injection and side-channel analysis equipment, automotive designers must consider these types of attacks as viable and plan the proper countermeasures.

{{< notice >}}
Note
{{< /notice >}}
{{< callout emoji="💡" text="To gain a better perspective of side-channel attacks mounted from within a single compute environment, look up Spectre and Meltdown vulnerabilities to see how attackers can abuse the hardware behavior to infer information about tenants sharing the same computing platform. For externally mounted side-channel attacks, you are advised to look up simple power analysis (SPA), differential power analysis (DPA), and electromagnetic fault injection (EMFI) attacks, which leverage the power and electromagnetic fault injection-based analysis to discover cryptographic key material." >}}
