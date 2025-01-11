---
title: "ECU Foundations"
---

## Intoducing the Engine Control Unit (ECU)

The Engine Control Unit (ECU, also called *Powertrain Control Module* or *PCM*), which is a key player in virtually every system involved in running the vehicle. In an automotive sense, the ECU is the "all-knowing", powerful "entity" that makes it go. The ECU is the most powerful computer on modern vehicles. It uses a variety of **sensors** to monitor and control most of the engine functions, including the **electrical, fuel** and **emissions control systems**. Among other tasks, the ECU controls the **fuel injectors** on fuel-injected engines, fires the **spark plugs**; and controls **valve timing**, the **fuel/air mixture**, **battery charging**, and even the cooling **fan**. By continually measuring and monitoring these reading in conjuction with a series of "maps" or programs, the ECU ensures that the engine is operating correctly. It's the key to the diagnostics that pinpoint problems and is primarily responsible for managing the fuel efficiency and performance of the vehicle. If the ECU malfunctions, it usually needs to be replaced.

The ECU is responsible for continually setting and adjusting ignition timing, air/fuel ratio (where applicable), and boost, relative to such input variables as:

- Outside air temperature
- Altitude
- Octane of fuel in your car’s gas tank

The ECU/ECM performs these basic functions:

- Confirms that your emissions equipment is functioning correctly
- Sets rev and speed limits on your car
- Controls fuel cut and boost cut to prevent over boosting in the event of a wastegate malfunction on turbocharged engines
- Sets speeds for underhood radiator and intercooler fans

Your ECU interfaces with a number of on-board modules, including those that handle the operation of factory-installed

- Cruise control
- Airbags
- Air conditioning
- Traction control
- ABS brakes
- Anti-theft system
- Throttle-by-wire and drive-by-wire systems

The car’s ECU performs these calculations continuously — often within milliseconds — for the entire life of your car, and makes adjustments on what it has learned about your driving habits and the environment.

{{< notice >}}
Technical Information
{{< /notice >}}
{{< callout emoji="💡" text="What kind of awesome computing power does it take to run all of these calculations quickly and reliably? Surely the auto manufacturers must be equipping cars with 8 GHz processor boards that can run laps around home computers. If only this awesome processing power could be used to run video games... In reality, **a modern car’s ECU runs only around 30–40 MHz**. Not very fast at all compared to home computer standards. The trick to the ECU’s performance is a very efficient and simplified method of processing information from your engine’s output devices." >}}

## Upgrading

The appropriate changes to the vehicle ECU can be done any time:

- **Change the vehicle ability to take in or expel air:** Adding a cold air intake doesn't mean the ECU upgrade is needed. However, it's recommended to upgrade the ECU in a set of more aggressive cams or install a much bigger turbocharger (or add a turbocharger or superchager where one didn't previously exists).
- **Change the vehicle ability to ignite the air/fule mixture:** To get the most out of changing over to a colder heat range spark plug and/or ignition apmplifier, it's recommended to make appropriate changes to the vehicle ignition timing maps.
- **Add or subtract fuel flow:** Installing a larger capacity fuel pump doesn't mean ECU upgrade is needed. The ECU changes are required if the injectors are replaced with larger ones, or if auxiliary injectors were added.
- **Alter its internal dimensions, such as compression, displacement, or airflow:** Putting in a new head gasket, stronger forged pistons, or heavy-duty head studs doesn't necessarily warrant changing anything in the ECU. The ECU upgrade is needed, however, if the new engine parts include *change in compression ratio*, *increase in displacement* (stroking or boring), or *increase in airflow* through the cylinder head.

## Interface Systems

When deciding upgrade on the factory ECU, one must choose between what is called an *open* and *closed* interface systems.

- A *closed interface* ECU upgrade, like a reflash or chip swap, is not generally user accessible
- An *open interface* ECU upgrade, like a standalone ECU or piggyback controller, allows the access and alternation of the maps when changing performance hardware under the hood

**Closed Interface**

A closed interface isn’t easily accessible. As such, it’s ideal if you don’t often want to retune or recalibrate your ECU, and you prefer a plug-and-play solution. Examples of closed interface upgrades are:

- ✅ ECU chip swaps
- ✅ Reflashes
- ✅ Pretuned ECUs

A closed interface upgrade has a couple of benefits:

- ✅ It doesn’t require any guesswork or Dyno time. Once installed, the car can be started and driven hard.
- ✅ It looks and behaves much like a stock ECU, which is desirable while your car is under warranty and subject to dealer scrutiny during scheduled maintenance appointments.

The biggest disadvantage of a closed interface upgrade is that you can’t easily tune or adjust it:

- ✅ If you’re constantly trying new engine hardware, a closed interface makes incremental changes to the car’s ECU much more difficult,  time-consuming, and expensive.
- ✅ If your plans involve either leaving your car stock, or making all of the upgrades at one time and then not changing the car for a while, the lack of adjustability may not be a problem for you.

**Open Interface**

Open-interface ECU upgrades, like standalone ECUs or piggyback controllers, allow you to modify your ECU maps to reflect hardware changes under the hood. For example, your car may have one set of engine mods at the time you first upgrade the ECU, but a week or year later, may have very different bolt-on modifications under the hood, necessitating an entirely different tune.

This flexibility has a price due to hidden costs:

- ✅ Dyno Time
- ✅ Tunner Fees
- ✅ Datalogging
- ✅ Open-interface ECU upgrades are more likely to be spotted by service technicians when the request for factory warranty repairs are inquryied

It's recommended to use reflashes or EEPROM chip swaps which is quite stealthy and difficult to detect, and it allows the raise the factory rev limit. The ECU is also providing faster responses using this method. Reference to [ECU Chip Modding](/bmw/modding/ecu#reflashes-and-eeprom-swaps) note for more details on ECU Repogramming.

## ECU

- Electronic Control Unit, or simply the "ECU"
	- Reading of the various sensors in the vehicle: 
    	- Oxygen sensor
    	- Airflow meter (AFM/MAF) or Mass Air Pressure sensor (MAP)
    	- Temperature sensors
    	- Knock sensors
- Doing calculations or apply rules in the vehicle system
	- Calculation example of ECU
	- Meassure "Speed (km/h)"
	- ECU would "calculate":
			- **speed (km/h) = wheel (rpm) x 3.6**
- Apply a tiny part of logic
	- If speed is above 5km/h, then lock the doors
- ECUs are wired to sensors, mothers, and other actuators
- One ECU can be used for different vehicles
- They use microcontroller (have memory/storage unlike microprocessor)
- Uses embedded software, via special hardware that converts electrical signal to numbers (and vice-versa), collectively IO (input/output)
- Uses networking hardware, via in-vehicle networks (like CANBus)

## ECU Software

**Layers**
- Control functions that ECU runs are referred to as "application software", (ie window control, etc.) (ASW)
- Network connections of IO of ECU are managed via "basic software" (like an operating system layer) (BSW)
- Runtime environment "RTE" glues both Network and Control functions, takes output from ASW to BSW
- To update ECU software, we can use UDS and Flash Bootloader a special piece of ECU that updates the firmware

## Diagnostis

- OBD protocol (On Board Diagnostics)
- Use OBD to diagnose ECU's
- Use [XCP and Callibration](/ecu-calibration) to Diagnose ECU

## HCP (New era of ECU's)

- There is new generation of ECU called high-performance computing platform (HCP)
