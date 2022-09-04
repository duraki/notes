---
title: "Magnetoresistive Sensors"
---

This type of sensor is particulary suitable for advanced stability control applications, in which sensing at zero, or near zero speed is required.

1) A permanent magnet in the sensor produces a magnetic field, with the magnetic field stream at a right angle to the sensing element

2) The sensor element is ferromagnetic alloy. It changes its resistance based on the influence of magnetic fields.

3) If the high portion of the pulse wheel approaches the sensing element, a deflection of the magnetic field stream is created. This creates a resistance change in a thin film ferromagnetic layer of the sensor element.

An example of magnetoresistive sensors components is as following:

{{< imgcap title="Example - Magnetoresistive Sensors Component" src="/posts/images/magress-part-list.png" >}}

After assembly of listed components, such magnetoresistive sensor will look like this:

{{< imgcap title="Example - Post-assembly of listed Components" src="/posts/images/magress-assembled.png" >}}

The sensor element **is affected** by the direction of the magnetic field (not the field strength). 

{{< details >}}
The field strength is not important, as long as it is/above certain level. This allows the sensor to tolerate variations in the magnetic field strength (caused by age, temperature, mechanical lifetime ...).
{{< /details >}}

The resistance change in the sensor affects the voltage that is supplied by the evaulation circuit. A small amount of voltage is provided to the sensor elment; which is monitored, and the voltage changes (1 to 100mV) are converted into current pulses by the evaulation module.

{{< imgcap title="Conversion of voltages to current pulses if sensor element voltage is changed" src="/posts/images/sensor_conversion_to_current_pulses.png" >}}

The sensor is supplied 12V by the Control Unit. Output voltage from the sensor is approximately 10V. The Control Unit counts the high and low current pulses to determine the wheel speed.

## Typical Application of Hall Effect Sensors
* Currently used for wheel speed sensors