---
title: "Vehicle Speed"
url: /bmw/clusters/vehicle-speed
---

### Controlling KM/H Vehicle Speed on Instrument Cluster

The vehicle speed indicates how fast does a vehicle travel, with `km/h` (EUR) designation labels. It's possible to wire the instrument cluster interface pinouts against the Arduino [PWM](https://www.instructables.com/How-to-use-Pulse-Width-Modulation/) GPIOs and manipulate the signal of the tachometer (km/h) needle on the cluster itself. To do so, you will need to wire up the cluster mandatory pins as explained in [BMW E34 Cluster Wiring Diagram](/e34-cluster-wiring-diagram), and attach Arduino Uno R3 to the Host OS with the following firmware:

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

### Speedometer Needle Control

To control the speedometer needle, we need to transmit the pulse-width modulation (PWM) to `X271`'s Pin no# `8`. We can calculate the PWM count using the formula `X = K * 100 (km) / 60 (minutes) / 60 (sec)`, where the `X` indicates the number of pulses per second we need to send this PWM signal. To test this on Low version of Instrument Cluster, use the pinout `X13060 // Pin 13` from the connector, defined as output signal for "Engine/Vehicle Speed Input (+)", ie. the Position Pulse of the vehicle speed.

Next, connect the Arduino and set the pulse count using the `tone()` function. The signal pin receiving this information is connected to the base of a *field-effect transistor*, which supplies and removes voltage from `X271`, specifically the Pin No# `8`. It is required for transistor because the signal should be `12V`, and the Arduino supplies `5V`. To connect the transistor, simply add it between the signal wire of the Instrument Cluster, alongside the GPIO of the Arduino used to send the `tone()` signal.

If everything worked out, you'll be able to set any speedometer value from the program above `40 km/h`. The fixed value of `40 km/h` is because the `tone()` function produces a square-wave signal (the `pwm` signal is set "ON" 50% of its time, while its being "OFF" for 50% of its time); while a real sensor produces a signal approximately `75%` on and `25%` off, therefore the difference in nominal value required by the Aruduino program/firmware sending the signal.

It is possible to make it work well below `40 km/h`, and while this won't be described here, one needs to write an implementation using Arduino timers library in conjuction with the `tone()` function to send correct PWM.

### Tachometer Needle Control

To control the speedometer, specifically, the tachometer needle (RPM), we need to transmit the pulse rate to `X16`, on Pin No# `18` using similar PWM technique. The `X16 // Pin 18` in High version of Instrument Cluster equals to `X13060 // Pin 26` in Low version of Instrument Cluster, which is known as "TD Signal" output signal, expecting a Square-wave Analog modulation, where this TD signal on the tachometer is used for RPM.

Approximately, `50 Hz` (*pulses per second*), equals `~1000 RPM`, but it works strangely different due to mixing of the analog and digital signals. The following ratio (first it centeres the RPM needle, then calibrate it so it also shows correctly at `1k` (rpm) and `6k` (rpm) no matter what signal ratio is required) forumal was used:

```
X = (engineRPM - (engineRPM - 3500) / 19.7) / 19.4; // where X = num of pulses per sec
```

Using above formula, the signal is also not **square**, rather, it's `66% high` (signal present, ie. being "ON"), while the rest of the modulation is `34% low` (no signal present, ie. its "OFF").

### Controlling the Fuel Economy Meter Needle

To control the fuel economy meter, we need to transmit the number of pulses to `X16`, specifically on  Pin No `17`. In Low version of Instrument Cluster, this pin is defined as `X16 // Pin 20` - known as TI (DME Control Unit) Signal. The TI (DME Control Unit) Signal is output signal expecting a **Square-wave Analog** modulation, used during fuel economy calculations.

There's very little information about this needle online. I had to come up with something, and it turned out to be somewhat complicated albeit works fine. The problem is that the vehicle receives pulses from the DME (presumably, using the "number of injections" and their "duration"), then somehow (using math) converts them into "*liters per 100 km*", taking into account both *current speed* and relevant *RPM* on the received signals.

Using trial and error, the following formula was proved to match fuel ratio calculus in this Instrument Cluster:

```
X = engineRPM / 20; // where X = num of pulses per sec
```

Worth mentioning, the signal ("injection") length also plays a role here. Therefore, the value of `1 / X` equals the lenght of one pulse. Using this, we may fixate value `litersPer100km`, which indicates how much does the fuel economy meter needle should move on the gauge, likewise, in combination and while using `currentSpeed` as the current speed of the vehicle.

Next, we need to calculate the length of the signals High phase (ie. when the signal is "ON"), using formula:

```
Y = (1 / X) * litersPer100km * currentSpeed / 3000
```

The calculated value `Y` is the lenght of the signals High value phase (signal is "ON"), while the lenght of the signals low phase (the signals is "OFF") should equal to `(1 / X - Y)`.

Using this combination, when the speed (km/h) or the RPM needle changes, the current fuel consumption per 100 km is recalculated and forced via its High value.

### Complete code (tested on **High** version of Instrument Cluster)

```c
// Original author: https://www.drive2.ru/l/483191930771997064/


#include <FrequencyTimer2.h>

const int kMinSpeed = 0;
const int kMaxSpeed = 100;

const int kSpeedPin = 3;
const int kTachoPin = 2;
const int kEconomPin = 5;

unsigned long speedSignalHighDuration = 0;
unsigned long speedSignalLowDuration = 0;
unsigned long speedSignalChangeTime = 0;
bool isCurrentSpeedSignalHigh = false;

unsigned long tachoSignalHighDuration = 0;
unsigned long tachoSignalLowDuration = 0;
unsigned long tachoSignalChangeTime = 0;
bool isCurrentTachoSignalHigh = false;

unsigned long economSignalHighDuration = 0;
unsigned long economSignalLowDuration = 0;
unsigned long economSignalChangeTime = 0;
bool isCurrentEconomSignalHigh = false;

unsigned int currentTacho = 0;
unsigned int currentSpeed = 0;
unsigned int currentEconom = 0;


void setup() {
  // put your setup code here, to run once
  Serial.begin(9600);
  delay(2);

  pinMode(kSpeedPin, OUTPUT);
  pinMode(kTachoPin, OUTPUT);
  pinMode(kEconomPin, OUTPUT);
  changeEcomometer(0);
  changeSpeed(100);
  changeEngineRPM(2800);
  
  FrequencyTimer2::setPeriod(90);
  FrequencyTimer2::enable();
  FrequencyTimer2::setOnOverflow(checkTime);
}

void loop() {
//  for (int i = 600; i < 4800; i= i + 10) {
//    changeEngineRPM(i);
//    delay(3);
//  }
//
//  for (int i = 4700; i > 2000; i= i - 10) {
//    changeEngineRPM(i);
//    delay(4);
//  }
//  
//  for (int i = 2200; i < 7200; i= i + 10) {
//    changeEngineRPM(i);
//    changeSpeed(i / 120);
//    delay(5);
//  }
//  changeEngineRPM(5500);
//  delay(90);
//
//  for (int i = 4200; i < 8000; i= i + 10) {
//    changeEngineRPM(i);
//    changeSpeed(60 + (i - 4200) / 70);
//    delay(7);
//  }

    if (Serial.available() > 0) {  // if there is available data returned from the serial, 
                                   // translate its value using changeEngineRPM() function.
        changeEngineRPM(Serial.parseInt());

//      changeSpeed(Serial.parseInt());
//      changeEcomometer(Serial.parseInt());
    }
}

void changeSpeed(long speed) {
  currentSpeed = speed;
  float signalPerSecond = speed * 1.25944444444;

  speedSignalHighDuration  = 10000 / signalPerSecond * 75;
  speedSignalLowDuration  = 10000 / signalPerSecond * 25;
  changeEcomometer(10);
}

void changeEngineRPM(long engineRPM) {
  currentTacho = engineRPM;
  float signalPerSecond = (engineRPM - (engineRPM - 3500) / 19.7) / 19.4;

  tachoSignalHighDuration = 10000 / signalPerSecond * 66;
  tachoSignalLowDuration = 10000 / signalPerSecond * 34;
  changeEcomometer(10);
}

void changeEcomometer(float litersPer100km) {
  float signalPerSecond = currentTacho / 20;
 float signalLengthMilisec = 1000000 / signalPerSecond;
  economSignalHighDuration = signalLengthMilisec * litersPer100km * currentSpeed / 3000;
   
 economSignalLowDuration = signalLengthMilisec  - economSignalHighDuration;
}

extern "C" void checkTime(void) {
  unsigned long currentMicroTime = micros();
  if (isCurrentSpeedSignalHigh) {
    if ((speedSignalChangeTime + speedSignalHighDuration) <= currentMicroTime) {
      digitalWrite(kSpeedPin, LOW);
      speedSignalChangeTime = currentMicroTime;
      isCurrentSpeedSignalHigh = false;
    }
  } else {
    if ((speedSignalChangeTime + speedSignalLowDuration) <= currentMicroTime) {
      digitalWrite(kSpeedPin, HIGH);
      speedSignalChangeTime = currentMicroTime;
      isCurrentSpeedSignalHigh = true;
    }
  }

  if (currentMicroTime < speedSignalChangeTime) {
    speedSignalChangeTime = currentMicroTime;
  }

  if (isCurrentTachoSignalHigh) {
    if ((tachoSignalChangeTime + tachoSignalHighDuration) <= currentMicroTime) {
      digitalWrite(kTachoPin, LOW);
      tachoSignalChangeTime = currentMicroTime;
      isCurrentTachoSignalHigh = false;
    }
  } else {
    if ((tachoSignalChangeTime + tachoSignalLowDuration) <= currentMicroTime) {
      digitalWrite(kTachoPin, HIGH);
      tachoSignalChangeTime = currentMicroTime;
      isCurrentTachoSignalHigh = true;
    }
  }

  if (currentMicroTime < tachoSignalChangeTime) {
    tachoSignalChangeTime = currentMicroTime;
  }

  if (isCurrentEconomSignalHigh) {
    if ((economSignalChangeTime + economSignalHighDuration) <= currentMicroTime) {
      digitalWrite(kEconomPin, LOW);
      economSignalChangeTime = currentMicroTime;
      isCurrentEconomSignalHigh = false;
    }
  } else {
    if ((economSignalChangeTime + economSignalLowDuration) <= currentMicroTime) {
      digitalWrite(kEconomPin, HIGH);
      economSignalChangeTime = currentMicroTime;
      isCurrentEconomSignalHigh = true;
    }
  }

  if (currentMicroTime < economSignalChangeTime) {
    economSignalChangeTime = currentMicroTime;
  }
}
```
