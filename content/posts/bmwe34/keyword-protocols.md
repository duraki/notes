---
title: "Keyword Protocols"
---

Keyword Protocol is a communication protocol used for *on-board vehicle diagnostics* (**`OBD`**) that predates *OBD2* interface implementation. This protocol uses usually K and L line, which is powered by, typically, serial TX and RX buslines found inside [vehicle bus](https://en.wikipedia.org/wiki/Vehicle_bus).

* [Keyword Protocol 2000](#kwp2000) - *(MY.2000 and up)*
* [Keyword Protocol 71](#kw71) - *(MY.1999 and below)*
  - [Protocol Description](/kw71-protocol-description)

On BMW vehicle models produced between 1988-2000, the OBD vehicle diagnostic port is a 20-Pin Connector located in under the hood.

{{< details "BMW OBD 20-Pin Connector" >}}
![20-Pin BMW OBD Diagnostic Proprietary Connector](https://connector.pinoutguide.com/diagram/car_obd_20p.gif)
**Note:** Pin 17 and Pin 20 may be shorted in diagnostic cable since a vehicle may use a single busline (K-Line) for RxD/TxD, instead of two-wire (K/L-Line) vehicle bus for RxD (K) and TxD (L) separately. Take a look at [Pinout Guide](https://pinoutguide.com/CarElectronics/car_diag_pinout.shtml) for reference.

| Pin | Signal                           | Description                             | Some Models           |
|-----|----------------------------------|-----------------------------------------|-----------------------|
| 1   | TD                               | Engine rotation speed                   |                       |
| 2   | CAN-High                         |                                         | CAN OBD-II |
| 3   | CAN-Low                          |                                         | CAN OBD-II |
| 4   | Shielding                        |                                         | CAN OBD-II |
| 7   | Oil Sensor Reset | Service/Inspection                                       | CAN OBD-II |
| 11  | External starter turn on         | N/A. Might be N/C.                      |                       |
| 12  | Battery indicator                | N/A. Might be N/C.                      |                       |
| 14  | Battery power                    | +12V                                    |                       |
| 15  | ISO 9141-2 L Line                | ISO 9141-2; RXD - Diagnostic Data link. |                       |
| 16  | Ignition +12V                    | KL.15 power                             |                       |
| 17  | ISO 9141-2 K Line                | N/A. Might be N/C.                      |                       |
| 18  | PGSP                             | Programming Line                        |                       |
| 19  | GND                              | Ground                                  |                       |
| 20  | ISO 9141-2 K Line                | TXD - Diagnostic data link.             |                       |
{{< /details >}}

{{< details "Vehicle Bus" >}}
A vehicle bus is a specialized internal communications network taht interconnects components inside a vehicle such is [ECUs](/ecu-foundations). An electronic **bus** is simply a device that connects multiple electrical and electronical devices together. Ref//  [Wiki](https://en.wikipedia.org/wiki/Vehicle_bus), [Automotive Buses](http://www.interfacebus.com/Design_Connector_Automotive.html).
{{< /details >}}

{{< details "Automotive Protocol Buses" >}}
* [Controller Area Network](https://en.wikipedia.org/wiki/CAN_bus) ([CAN](/canfd-specifications))
* FlexRay
* IDB-1394 ([IEEE1394](https://en.wikipedia.org/wiki/IEEE_1394#IDB-1394))
* IEBus ([IEB](https://en.wikipedia.org/wiki/IEBus))
* J1708
* J1939, and ISO11783
* Local Interconnect Network ([LIN](https://en.wikipedia.org/wiki/Local_Interconnect_Network))
* Media Oriented Systems Transport (MOST)
* Vehicle Area Network (VAN)
* UAVCAN
{{< /details >}}

### KWP2000

The [KWP2000](https://en.wikipedia.org/wiki/Keyword_Protocol_2000), or *Keyword Protocol 2000* is a communication protocol used for [on-board vehicle diagnostics](https://en.wikipedia.org/wiki/On-board_diagnostics) (OBD) systems used by Suzuki (SDS), Kawasaki (KDS), Yamaha (YDS), Honda (HDS).

It is standardized by the [ISO 14230](https://www.iso.org/obp/ui/#iso:std:iso:14230:-1:ed-2:v1:en) and it is compatible with [ISO 1941](https://www.iso.org/obp/ui/#iso:std:iso:9141:-2:ed-1:v1:en), both uses single-line called **`K-line`** by sending a compatible Parameter IDs (known as PIDs), to the [Electronic Control Unit](/ecu-foundations) (ECU).

* [Keyword-Protocol-2000](https://github.com/aster94/Keyword-Protocol-2000)
* [Using Raspberry Pi w/ Honda CTX-700 ECU](https://gonzos.net/projects/ctx-obd/)
* [ISO14230-4-KWP](https://github.com/martinhol221/ISO14230-4-KWP) 🇷🇺

### KW71

Some old cars like older BMWs pre-dates OBDII implementation, and instead contains a multipin connector under the hood, which provides access to the cars TxD/RxD buslines (sometimes refered as K/L-Lines).

KeyWord Protocol "KW-71", describes the interaction of diagnostic tools (DS) with electronic blocks and ECUs in BMW cars produced before 1995. These include model E30, E32, E34, E36.

A BMW licensed service tools **`INPA`**, and **`DIS`** connnect to this interface via [an ADS adapter](https://deviltux.thedev.id/posts/o/20220219-bmw-tiny-ads-interface.html).

Little to no technical information is available on the web for this protocol, but its been said that BMW's (Bosch Motronic) ECUs use protocol KW71 for diagnostics to the DME, EML and EGS. Other modules in the vehicle uses a different protocol (presumably a serial-line bus).

A reverse engineering test-bench was used to connect INPA to a tested LAB Vehicle, and, by capturing the serial messages sent by the software back and forth - a protocol diagram was created.

![](http://www.km5tz.com/images/850i/KW71diagram.jpg)

Looking for patterns in the data sent and received on the vehicle bus, messages were separated for message boundaries. The protocol is **not similar** to typical BMW's IBUS.

Reference to [Protocol Description](/kw71-protocol-description) for more details on the KW71 Protocol implementation.

* [kwp71scan](https://github.com/kaihara/kwp71scan) (*[circuit schema](https://github.com/kaihara/kwp71scan/wiki)*)
