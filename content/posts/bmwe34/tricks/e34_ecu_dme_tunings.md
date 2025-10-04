---
title: "ECU (DME) MS40.1 Tuning on BMW E34"
url: /bmw/e34ms40
---

## Engine: `M50B20TU` **~** `MY.94`

The [Github repository](https://github.com/zarboz/BMW-XDFs) maintained by user `@zarboz` contains [TunerPro `XDF`  File Specs Definition](www.tunerpro.net) (the *ECU's* firmware dump or other EEPROM flash destinations containing the tunemap, in a specific formatted definition files, eg., `*.xdf`)

Resources:

* [Discoord URL Chat](https://discord.gg/vdVsypF)
* [What is XDF File?](https://tuniverse.it/bin-definition-files/) 

## TunerPro - `XDF` Files

An XDF (`eXtended Definition File`) is an essential component for ECU tuning using [TunerPro](www.tunerpro.net). It tells the software (firmware) how to interpret the data inside the ECU bin/dump file, unlocking access to editable maps, turning them into final [tuned maps](https://tuniverse.it/tuned-files/), by their mapping stage.

## WinOLS - `OLSX` Mappack Files

**WinOLS** tuning software is able to edit the binary files read out from the ECU/ECM (engine control unit) and TCU/TCM (transmission control unit). All the data and maps are saved inside a project file, *also called mappack*. **WinOLS Damos** (“data monitoring system”), on the other hand is different. Compared to *mappacks*, the *damos* are using extension `*.dam`, `*.damos`, `*.a2l` and `*.asap2`. Furthermore, **they contain full maps** *and all other data* used by the engine control unit (ECU) and transmission control unit (TCU). Sometimes they might be refered as **super mappack**.

### Other Resources

* [Labda Sensor downstrema disable/removal in the exhaust system](https://oldskulltuning.com/special-functions-lambda-removal/)
* [Rev Limiter and its functions in RPM restrictions](https://oldskulltuning.com/special-functions-rev-limiter/), implemented in two common styles
  - **Soft cut:** limiters are a type of revolution limiters that partially cut off fuel. The engine will start to cut fuel or retard the ignition timing before the set RPM until it slowly reaches it and remains there.
  - **Hard cut:** limiters completely cut fuel or spark of the engine. These limiter types activate at the pre-set RPM and bounce off of it if throttle is applied.
* [Speed Limiter (max `kmh`, *vehicle speed*, etc.)](https://oldskulltuning.com/special-functions-rev-limiter/) vehicles has these protections implemented in specific models, and it can only have a **single point** (a fixed max vehicle speed), or **multiple points** (a fixed max vehicle speed, but if the area is hightway, then a second max speed limiter, ie. `130km/h`). See also  [Toreque Limiter](https://oldskulltuning.com/torque-limiters/ docs
* [MAP Sensor Scaling](https://oldskulltuning.com/special-functions-map-calibration/) explains its usage due to how engine works. Engines are are typicaly *fuel-injected*, therefore, MAP sensor supplies a *real-time* **manifold pressure** to the **Engine Control Unit** *(ECU/ECM)*. The MAP sensor data is used to calculate *air density*, and determine the *engine’s air mass flow rate*, *which* in turn *determines the required fuel for optimum* **combustion** and **influence** of ignition timing.
* [MAF Sensor Linearization and Scaling](https://oldskulltuning.com/special-functions-maf-scaling/). - The MAF Sensor is used to determine the mass air flow entering a [*fuel-injected* engine](https://oldskulltuning.com/fuel-delivery-ecu/). It is installed between the air filter and the intake manifold of the engine. In *modern vehicles*, an *intake air temperature* (ie. `IAT`) sensor is built instead of using Mass Air Flow *(MAF)* sensor. See also [MAF based VS SPEED DENSITY based ECUs](https://oldskulltuning.com/maf-based-ecu-vs-map-based-ecu/)
* [Open Loop vs Closed Loop](https://oldskulltuning.com/open-loop-vs-closed-loop/) intro for begginer ECU tunners
* [Tuning ECU for total beginners](https://oldskulltuning.com/how-to-tune-your-vehicle/)
* [Theory of Volumetric Efficiency in ECU tuning](https://oldskulltuning.com/volumetric-efficiency-maps/))
* [Bosch ECU/DME Insights](https://oldskulltuning.com/bosch-ecu-insights/)
* [Fuel delivery to the vehicle via ECU - Overview](https://oldskulltuning.com/fuel-delivery-ecu/)
* [Detection of `ignition timing` and `knock detection` for perfect ECU timing adjustment and synchro](https://oldskulltuning.com/ignition-timing-maps-and-knock-detection/)
* [Throttle Position Sensor (TPS)](https://oldskulltuning.com/throttle-position-sensor-and-ride-by-wire/) *ride-by-wire* based Electronic Throttle Control (ETC) which differs in its implementation of wiring system and the connection to the ECU `i/o`, having better values and combination results of the throttle system
* [Boost Pressure and Boost Limiters](https://oldskulltuning.com/boost-pressure-boost-limiters/), refers to the increase in air pressure inside the intake manifold of a forced-induction engine, such as a turbocharged or supercharged engine, which is above atmospheric pressure; and its usually meassured or labeled as `psi`, `bar` or `kPa` (*kilopascal*).
* [TunerPro Youtube Playlist for Begginers](https://www.youtube.com/playlist?list=PLiVpvgq8w2uEkzzLg6AGjGBu8AUp4cEjo), and [editing a binary dump file using TunerPro](https://oldskulltuning.com/how-to-edit-a-binary-file-using-tunerpro/)