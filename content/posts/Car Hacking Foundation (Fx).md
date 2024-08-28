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
