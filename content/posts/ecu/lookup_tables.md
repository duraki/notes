---
title: "Lookup Tables"
---

The ECU Lookup Tables is a special file format "BDM". It is used to read the contents of the ECU and dumping the parameter values that describe specific tune.

Modifying the contents is done by searching the hex for known patterns in a hexadecimal editors based on these *Lookup Tables*. There is a large number of lookup tables describing parameter details such as: *throttle position vs rpm*, *coolant temp vs rpm*, and so on.

When you modify the contents of this binary [ECU File Data](/ecu-file-formats) in a hexadecimal editor, you are changing a specific tune and therefore increase or decrease the performance and overall state of the vehicle itself.

Typically for Stage1 map (ie. the *tweaks* of your tune), would change between 80 to 120 parameters.
