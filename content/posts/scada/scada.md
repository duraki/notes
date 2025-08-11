---
title: "SCADA"
url: "/scada"
---

**SCADA** or *Supervisory Control and Data Acquisition* are all operational infrastructure systems that might be used for *electrical transmission systems*, *nuclear power plants*, *chemical plants*, *water treatment plants*, *HVAC systems*, *home or industrial heating*, *manufacturing sites* and so on.

## Default Passwords

Most SCADA systems are still provisioned with their default passwords from the manufacturer.

| Vendor                        | Device                                | Default Password                                           | Port     | Device Type                     | Protocol        |
|------------------------------|---------------------------------------|------------------------------------------------------------|----------|----------------------------------|------------------|
| ABB                          | AC 800M                               | service:ABB800xA                                           | -        | Controller                      | -                |
| ABB                          | SREA-01                               | admin:admin                                                | 80/tcp   | Ethernet Adapter Mk             | http             |
| Adcon Telemetry              | Telemetry Gateway A840 and W          | root:840sw                                                 | terminal | Base Station                    | -                |
| Adcon Telemetry              | addVANTAGE Pro 6.1                    | root:root                                                  | 8080/tcp | HMI                              | HTTP             |
| Advantech                    | Advantech WebAccess browser admin     | admin:blank                                                | -        | browser-based HMI               | HTTP             |
| Allied Telesis              | IE200 Series: AT-IE200-6GT, AT-       | manager:friend                                             | -        | Industrial Ethernet Switches   | -                |
| B&B ELECTRONICS              | CR10 v2                               | root:root                                                  | 80/tcp   | Industrial router               | http             |
| B&B ELECTRONICS              | Conel 4.0.1                           | root:root                                                  | 80/tcp   | Industrial router               | http             |
| B&B ELECTRONICS              | SPECTRE Router                        | root:root                                                  | 80/tcp   | Industrial router               | http             |
| B&B ELECTRONICS              | ER75i/ER 75 DUO/ER 75i SL/ER7         | root:root                                                  | 80/tcp   | Industrial router               | http             |
| B&B ELECTRONICS              | LR77 v2 Libratum/LR77 v2              | root:root                                                  | 80/tcp   | Industrial router               | http             |
| B&B ELECTRONICS              | UR5i v2                               | root:root                                                  | 80/tcp   | Industrial router               | http             |
| B&B ELECTRONICS              | UCR11 v2/UCR11 v2 SL                  | root:root                                                  | 80/tcp   | Industrial router               | http             |
| B&B ELECTRONICS              | XR5i v2/XR5i v2/XR5i/XR5i SL          | root:root                                                  | 80/tcp   | Industrial router               | http             |
| Beckhoff Automation GmbH     | CX5020                                | webguest:1                                                 | 23/tcp   | PLC                              | Telnet           |
| Beck IPC                     | IPC@CHIP                              | PPPSERVER:, ppp:pppps                                      | -        | PLC                              | pap/chap         |
| BinTec Elmeg                 | BinTec X1200 II                       | admin:bintec                                               | -        | Router                           | -                |
| BinTec Elmeg                 | any routers                           | #unknown (not known or any char), #unknown:snmp:           | -        | -                                | -                |
| BinTec Elmeg                 | BinTec R230aw                         | admin:funkwerk                                             | -        | -                                | -                |
| BinTec Elmeg                 | BinTec W2002T-n                       | admin:funkwerk, admin:admin                                | -        | WLAN Access Point for applications | -              |
| Carlo Gavazzi                | PowerSoft                             | admin:admin, user:user                                     | -        | modular software                 | -                |
| Contemporary Control Systems | BASRT-B                               | admin:admin                                                | 80/tcp   | Router                           | http             |
| Datasensor                   | UR5i/UR5i SL                          | root:root                                                  | 80/tcp   | Router                           | http             |
| Digi                         | AWC 500                               | root:rf7800 (admin), default:1234 (user)                   | -        | Advanced Wind turbine Controller | -                |
| Digi                         | DC-ME-01T-S                           | root:digi                                                  | -        | Networking Module               | http             |
| Digi                         | Digi Connect SP, Digi Connect        | root:digi                                                  | 80/tcp   | Network Device Services         | http             |
| Digi                         | Digi Connect ES 4/8/8 with Swt        | root:digi                                                  | 80/tcp   | Concentrator                     | http             |
| Digi                         | Digi Connect TS 4, ConnectPort        | root:digi                                                  | 80/tcp   | Terminal Server                  | http             |
| Digi                         | Digi Connect WAN, Digi Connect        | root:digi                                                  | 80/tcp   | Industrial router               | http             |
| Digi                         | Digi TransPort WR21/WR44              | username:password                                          | 80/tcp   | Router                           | http             |
| Digi                         | DigiOne IAP Serial                    | root:digi                                                  | 80/tcp   | Gateway                          | http             |
| Vendor                         | Device                                             | Default Password                                                   | Port       | Device Type                     | Protocol                 |
|--------------------------------|----------------------------------------------------|----------------------------------------------------------------------|------------|----------------------------------|--------------------------|
| Echelon                        | i.LON SmartServer                                 | ftp for iLON and hs servers; ilon:ilon                               | -          | router                           | ftp, L2TP                |
| Electro Industrie/GaugeTech   | Nexus 1500+, Nexus 1500                            | anonymous:anonymous                                                 | 80/tcp     | Power Quality Meter              | HTTP                     |
| Electro Industrie/GaugeTech   | Communicator EXT 3.0                              | eigengineering:10                                                   | -          | Power Monitoring S               | HTTP                     |
| Emerson                        | DeltaV Digital Automation System                  | administrator:deltav                                                | -          | DCS                              | -                        |
| Emerson                        | Liebert IntelliSlot Web Card                      | Liebert:Liebert, User:User                                          | -          | Web Card                         | telnet                   |
| Emerson                        | Smart Wireless Gateway 1420                       | admin:default, maint:default, oper:default, exec:default            | -          | Gateway                          | http                     |
| Emerson                        | Network Power MPH2 Rack PD                        | admin:admin                                                         | 80/tcp     | Rack PDUs                        | http                     |
| Emerson                        | UL33 UPS                                          | 123456                                                              | -          | UPS                              | Serial                   |
| Emerson                        | Control Link Refrigeration System                 | -                                                                    | -          | Controller                       | -                        |
| Emerson                        | Ultrasite                                          | User 01:0100, User 05:0200, User 09:0300, Engineer:400               | -          | Software                         | -                        |
| Emerson                        | Avocent ACS 6000 Advanced Console Server          | admin:avocent, root:linux                                           | -          | Console Server                   | console port, www        |
| Emerson                        | ROCLINK 800                                       | LOI:0400                                                            | -          | Software                         | Console                  |
| Emerson                        | ControlWave Micro Quick                           | for download project, SYSTEM:66666666                               | -          | PLC                              | -                        |
| Emerson                        | IP-KVM Avocent MergePoint 4                       | -                                                                    | -          | -                                | -                        |
| Emerson                        | Ovation DCS                                       | wdpF                                                                | -          | Switch for Distribute            | Telnet                   |
| Emerson                        | Ovation DCS                                       | SNMP community string: wdpFRO                                       | -          | DCS                              | SNMP                     |
| Endress+Hauser                | Fieldgate FXA520                                  | supersuper                                                          | -          | Gateway for remote               | HTTP                     |
| ENTES                          | EMG-10, EMG-02, EMG-12                             | snmp2 (for EMG12), em1g2 (for EMG10), emg02 (for E80)               | -          | MODBUS Gateway                   | http                     |
| eWON                           | all                                               | adm:adm                                                             | 80/tcp     | Router                           | http                     |
| General Electric Intelligent Platforms | IC695PNC001                               | admin:systems                                                       | 23/tcp     | PROFINET Controller              | Telnet                   |
| General Electric Intelligent Platforms | IC695CMM850                             | admin:system                                                        | -          | -                                | -                        |
| General Electric Intelligent Platforms | IC695ETM001, IC695CPK305, IC695CRU320 | admin:admin                                                         | -          | Remote field/programmable controller | -                   |
| General Electric Intelligent Platforms | IC698CPE030, IC698CPE040, IC698CPE020 | ic6:usersytems                                                      | 21/tcp     | Programmable cont ftp            | -                        |
| Helmholz Systeme               | NETLink PRO HW 1-1a1 and F                       | NETLink PRO PoE:admin                                               | -          | Ethernet Gateway to HMI          | -                        |
| Hirschmann                     | RS20/RS30, MICE                                   | user:public, admin:private                                          | 80/tcp     | Switch                           | http                     |
| Hirschmann                     | RSP 20/25/30/35                                   | user:public, admin:private                                          | 80/tcp     | Switch                           | http                     |
| Hirschmann                     | MACH 400 family/MACH100                          | user:public, admin:private                                          | 80/tcp     | Industrial router                | http                     |
| Hirschmann                     | OCTOPUS 8M..., OCTOPUS 16M...                     | user:public, admin:private                                          | 80/tcp     | Industrial router                | telnet                   |
| HollySys Automation Technology | LK SERIES PLC                                     | FTP blank, Telnet blank                                             | 21/23      | PLC                              | FTP, Telnet              |
| Honeywell                      | Honeywell XL                                      | Guest:guest, SysAdmin:honney                                        | -          | Controller                       | http                     |
| IBM                            | 2210                                              | -                                                                    | -          | Multiprotocol Router             | -                        |
| Kostal Solar                  | PIKO-Inverter 3.0, 3.6, 4.2, 5.5, 7                | pvserver:pvwr                                                       | 80/tcp     | solar inverter                   | http                     |
| Mitsubishi                    | PLC QnUCPU QnUDVCPU                              | MELSEC:MELSEC                                                       | -          | PLC                              | FTP, HTTP                |
| Mitsubishi                    | PLC QnUCPU QnUDC(H)CPU                            | QnUDCCPU:QnUDCCPU                                                   | -          | PLC                              | -                        |
| Moxa                           | AirWorks AWK-3131-RCC                            | moxa:moxa                                                           | -          | Industrial 802.11 with router    | http                     |
| Moxa                           | Remote I/O (Logik IEI at Port 9020:1)            | 1:noneroot, 2:noneroot                                              | -          | Remote Ethernet I/O              | -                        |
| Moxa                           | MGate MB3000/MG                                  | admin:blank; root:blank (on port 9900 / 9000); root:root            | 9900/9000  | MODBUS RTU controller            | telnet                   |
| Moxa                           | VPort 461 Industrial Video Encoder               | admin:admin, <none>:<none>                                          | -          | Industrial Video Enc             | http                     |

### Other Resources

- [How to enum/recon and exploit SCADA using `nmap`](https://hackers-arise.com/scada-hacking-finding-and-enumerating-scada-sites-with-nmap-and-nmap-scripts/)
- [Monitoring SCADA industry sites with Splunk](https://hackers-arise.com/scada-hacking-monitoring-scada-sites-with-splunk/)
- [Using Metasploit SCADA modules during Cybersecurity Assessment](https://hackers-arise.com/scada-hacking-metasploit-scada-modules/)
- Part #1: [Conducting Risk Assessment on SCADA](https://hackers-arise.com/scada-hacking-scada-ics-risk-assessment-and-management-part-1/)
- Part #2: [Conducting Risk Assessment on SCADA](https://hackers-arise.com/scada-hacking-scada-risk-assessment-with-cset/)
