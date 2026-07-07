---
title: "OSINT on SCADA Networks"
url: "/scada/osint"
---

## SCADA Hunting & OSINT

All of these systems usually have both the digital and analog controls which might be vulnerable to attack on the industry sites network. The SCADA systems are a huge concern for *national defense agencies*, as a nation that has its SCADA systems disabled or compromised would likely have a hard time waging a successful war against its adversaries. This is why organizations such as the U.S. Homeland Security are concerned about the SCADA security and its regulations and implementations in the national industry sites. Most cyber war experts expect that all future wars will have a SCADA cyber attack element one way or another.

Be sure to check [SCADA default password](/scada) list as well.

**Shodan**

Since [we know that modbus runs over port 502](/scada/protocols), one can simply search Shodan for all IPv4 that have exact port open/available and/or exposed to the Internet. If found, these IPv4 most likely are running modbus, and might be a part of some company’s SCADA infrastructure.

Using Shodan queries, finding all devices with port `502` open is easy, using: `port:502`; for a specific country it's possible to also add `country: BA`, resulting in a final query `port:502 country:BA` to list all potential modbus exposed systems in Bosnia-Herzegovina.

Keep exploring the exposed IPv4 and accessing the HTTP webpages of found devices, if applicable. Usually, these systems may expose additional information and with a little research over the internet, the PLC's may be further identified or pinpointed to exact manufacturer.

Even if the webpage of the device asks for a authentication or password login, since the host is know to run a port `502` for modbus communication, it is likely also susceptible to modbus spoofing and/or DoS attack on that port.

You should be able to find other SCADA devices by searching for ports `19999`, `20000`, `1089-1091`, `2222`, `34980`,  `34962-34964`, and many others.

---

Sometimes it's possible to find SCADA systems by the manufacturer name, or a PLC device name, identifier and/or version number. 

Shodan uses the content of the systems and web banner and in most cases, these systems do display some kind of banner or information detailing the manufacturer name, PLC model, or the version of the device. 

For example, the *Schneider Electric* in Paris (France) is now the parent of the company that first developed the modbus protocol called "**Modicon**". They produce a wide variety of ICS systems most of which use the modbus protocol.

Begin looking for those systems by simply entering the company name "*Schneider Electric*" into the Shodan’s search engine enclosed in double quotes (ie. `"[manufacturer name]"`). This should result in a list of all the systems and hosts that contain the given search name in their banner.

Upon searching, Shodan identified almost *3000 systems* around the world with the name "**Schneider Electric**". This strongly implies, of course, that the system is among the family of Schneider Electric products.

It's even possible to be more specific, for example, the "Schneider Electric" company also builds an automated building system that they call "**SAS**" (short for "*Schneider Automated Server*". It is used to automate the heating, colling and security of high-tech buildings and industry sites. Including this additional term into the Shodan search, the results of this would be equivalent to a subset of the original search for the manufacturer name.





