---
title: "Vehicle Speed"
url: /bmw/clusters/vehicle-speed
---

### Controlling KM/H Vehicle Speed on Instrument Cluster

The vehicle speed indicates how fast does a vehicle travel, with `km/h` (EUR) designation labels. It's possible to wire the instrument cluster interface pinouts against the Arduino PWM GPIOs and manipulate the signal of the tachometer (km/h) needle on the cluster itself. To do so, you will need to wire up the cluster mandatory pins as explained in [BMW E34 Cluster Wiring Diagram](/e34-cluster-wiring-diagram), and attach Arduino Uno R3 to the Host OS with the following firmware:

```
/**
 * Controling KMH needle on BMW E34 Instrument Cluster via PWM
 * based on Arduino Uno R3 board. The firmware below should be
 * uploaded and wires as per the diagram.
 *
 * Author: H. Duraki <h@durakiconsulting.com>
 * Copyright (c) durakiconsulting, LLC 2023
 *
 **/

    /** gpios **/
const int PIN_TACHPWM = 3;            // the PWM pin attached to clusters' x271/8 vehicle speed (positive/+), and/or any LED indicator

    /** vars **/
int tach_speed = 0;             // current tachometer kmh speed
int slowdown_amount = 5;        // how many points to simulate vehicle slowing down and/or brakes

void setup() {
  pinMode(PIN_TACHPWM, OUTPUT); // declare pwm pin to be an output
}

void loop() {
    /** @see below for available loop samples **/
}
```

*A dynamic needle* which signals tachospeed at ~120-150km/h in revving demo:

```
// ...
void loop() {
  analogWrite(PIN_TACHPWM, 10); // set the tacho speed
  analogWrite(PIN_TACHPWM, 50000); // set the tacho speed at 120kmh
  analogWrite(PIN_TACHPWM, 50000 * 2); // set the tacho speed at 150kmh
}
```

*Percentage needle* is a modulation which makes the gauge needle to increase each 2.5 seconds:

```
// ...
void loop() {
    tone(PIN_TACHPWM, 33.3333333333333);
    delay(2500);
    tone(PIN_TACHPWM, 66.66666666666667);
    delay(2500);
    tone(PIN_TACHPWM, 100);
    delay(2500);
    tone(PIN_TACHPWM, 133.3333333333333);
    delay(2500);
    tone(PIN_TACHPWM, 166.6666666666667);
    delay(2500);
    tone(PIN_TACHPWM, 200);
    delay(2500);
    tone(PIN_TACHPWM, 233.3333333333333);
    delay(2500);
    tone(PIN_TACHPWM, 266.6666666666667);
    delay(2500);
    noTone(PIN_TACHPWM);
    delay(2500);
}
```

Addition to mandatory pins to power up the instrument cluster, display and backlight - you also need to wire up the **X271** (*12 Pin*) interface as following:

* X271 Pin 8 - To Arduino Uno R3 Pin D3 (lbl `3`)
* X271 Pin 10 - To Arduino Uno R3 Pin GND (lbl `GND`)

{{< imgcap title="Arduino Uno R3 GPIOs connected to the X271 connector (Instrument Cluster)" src="/posts/bmwe34/clusters/tachospeed_kmh/control_tacho_kmh_ard-w_pwm.png" >}}

---

### BMW Speed Frequency Pulse Generator

There is an open-source Arduino code hosted on [GitHub](https://github.com/jmsmuy/BMWSpeedoPulseGerator) that provides a way to generate speed on the BMW E30/E28/E24/E23 Instrument Clusters.

### Controlling RPM Engine Speed on Instrument Cluster

The Engine Speed Signal (RPM) from the DME (.5mm^2 black, "TD") is a clean, 50% duty cycle, 12V, active low square wave with a frequency of 1Hz for every 20 RPM. Click to see [more details on RPM and other DME pinouts](http://www.fekzen.se/StandAlone/).

{{< imgcap title="Sending data and RPM value to Instrument Cluster, out from the DME" src="/posts/bmwe34/clusters/tachospeed_kmh/control_tacho_rpm.png" >}}

---

### Identifying correct I/O signals for Instrument Cluster pinouts

It is sometimes difficult to identify what each pinout on the instrument cluster expects in a form of signals. A good workaround for this is to reference to an older or newer technical or electrical documentation of the similar vehicle models. For example, the following BMW E30 Instrument Cluster contains pinouts for each of the backpanel port, and also the output and input signals the pinout expects:

{{< imgcap title="Plug connections on Instrument Cluster (BMW E30 Series-3)" src="/posts/bmwe34/clusters/tachospeed_kmh/E30clusterpinout.jpg" >}}

If we reference on the pinout table, we can see that the **Analog Speed. outlet** on "Pin Board III" outputs frequency (PWM) signal, and the **Analog Speed** (Pin 16) of "Pin Board IV" is also used for that. Therefore we can conclude that newer Instrument Clusters also use same signals.