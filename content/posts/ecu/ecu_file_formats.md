---
title: "ECU File Formats"
---

The Binary File Format containing the ECU data (or *flash*) is a hexadecimal file containing the map contents of the ECU. The `maps` can be stored in the microcontroller of the ECU, or in a separate flash or **EEPROM** chip on the PCB.

Typically extension:

- `*.bin`
- `*.cod`
- `*.dtf`

Common size of the dumps:

- 512KB
- 1024KB
- 2048KB

The file can be read with just normal hexadecimal editors (ie. *HexView*). Using hex editors allows for versatility by directly forcing the content of the binary (*flash*) data and their values, depending on the vehicle sensor. This works by BDM, a format for reading the ECU contents through a dedicated connection directly on the PCB of the ECU.

Modifying the contents is done by searching the hex for known patterns that are called *[Lookup Tables](/lookup-tables)*. There is a large number of lookup tables describing parameter details such as: *throttle position vs rpm*, *coolant temp vs rpm*, and so on.

### Tuning Software vs Hex Editors

The use of all the Tuning Software is that they allow plotting the hex values on a graph against its location, to give you image of the data, something the human eye can recognise quickly and easily. The tuning software usually contains the [Lookup Tables](/lookup-tables) databases, so you can open the table and change the values in each column/row as you would in any database client.

Using hex editors is an old-school choice, and should be used only by experienced tuners and car hackers. The content of the hexadecimal binary file is easy to find if your lookup table contains a hexadecimal pattern corresponding to that parameter or value. Some parameters are easier to find, for example, to find possible location of the RPM values in the binary content, you would search hexadecimal pattern for values that are multiple of 250. It's good to dump the binary flash of your vehicle and explore the data and the content that it may contain to get the feel for working with the raw material.

Software List:

- RomRaider [web](https://www.romraider.com) - [GitHub](https://github.com/RomRaider/RomRaider)

