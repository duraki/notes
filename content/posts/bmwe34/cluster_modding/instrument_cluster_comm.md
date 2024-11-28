---
title: "Instrument Cluster Communication"
url: /bmw/clusters/communication
---

# Basic Message Transmission

This note introduces to BMW E32/E34 Instrument Cluster communication protocol against its' OBC. This tutorial only works on Instrument Cluster 'High' Version, either [Cluster High (Normal)](/bmw/clusters/high-normal), [Cluster High (Redesign/240)](/bmw/clusters/high-redesign), or [Cluster High (Redesign 2)](/bmw/clusters/high-redesign-2). Instructions written here do not work for any of the Cluster 'Low' Version.

### Powering up the Instrument Cluster

To start communicating with the Instrument Cluster OBC display, you need to wire up the Instrument Cluster on test bench. To power up Instrument Cluster, please take a look at [Cluster Wiring Diagram](/e34-cluster-wiring-diagram) for the 'High' version, as well as [Cluster Pinout Diagram](/e34-pinout-diagram) described in separate note. Make sure to power up Instrument Cluster only with basic stuff while experimenting (ie. *Ignition*, *Power*, *Backlight*).

For example, to power up BMW E32/E34 Instrument Cluster made after 1991 (these usually have a blue plastic backpanel), you would need to:

- X16 Beige (26-pin Connector): Hook Pin #7, Pin #12, Pin #13 to **Positive (+)** power line
- X17 Brown (6-pin Connector): Hook Pin #3, Pin #15 to **Positive (+)** power line
- X17 Brown (6-pin Connector): Hook Pin #1, Pin #13 to **Negative (-)** ground line

After hooking the above Instrument Cluster pins to breadboard, use the power supply unit supplying 12V and at least 800mA of current. It should show about 750mA of current draw when the check control display is **ON**, and closer to 500mA when its **OFF**.

### Remove the Brake Line Warnings

We are required to remove the brake line warnings. As long as the warning is there, it will block any messages we attempt to display. To remove brake line warnings, again, on the Instrument Cluster made after 1991, you would need to:

- X17 Brown (6-pin Connector): Connect (ie. *short connection*) Pin #25 to Pin #10 on the same connector; 
  - This completes the circuit and removes the brake error message.

### Prepare the Instrument Cluster to listen for Messages

To prepare Instrument Cluster to listen for our messages, we need to:

- X16 Beige (26-pin Connector): Connect Pin #3 to **Negative (-)** ground line

Normally, modules in the car that want to speak to the Instrument Cluster wait for this line to be at High (at 12V). Once this line is as High (12V), they then connect it to the **Ground**, signaling to all the other modules that the specific device is using this line. Since we don't have to worry about any other modules right now, we can connect this pin to **Ground** and forget about it.

### Connecting Instrument Cluster to the Microcontroller

**WARNING:** Whatever microcontroller (MCU) is used, it probably won't talk at 12V on its serial communication line. We would need a level shifting circuit, which will be used to transition the signal from whatever voltage our microcontroller (MCU) runs at, to the 12V the Instrument Cluster runs at. You can use any Logic Level Converter to aid the process, for example this [SparkFun Logic Level Converter](https://www.sparkfun.com/products/12009). The Transmission Wire goes from the Arduino's Transmit pin, to the Logic Level Shifter/Converter; and then from the Logic Level Shifter to X16 Pin #23. Therefore, once you have prepared the Logic Level Shifter in the circuit, you may:

- X16 Beige (26-pin Connector): Hook Pin #23 to the Logic Level Shifter
- Logic Level Shifter: Hook the used Level Converter pin to Arduino Transmit Pin

{{< details "Expand for Wiring Example" >}}
![](https://i.imgur.com/kKFl11g.jpeg)
{{</ details >}}

### Programming the Microcontroller

Finally, we are ready to program our microcontroller to talk with the Instrument Cluster. To display anything on the cluster, we will need to format it properly. The cluster expects serial communication to be at 9600 baudrate, with 8 data bits, even parity, and 1 stop bit. This is not the standard form of serial communication that an Arduino uses, since Arduino use 8 data bits and 1 stop bit, but it does not use parity. To set the serial communication protocol properly in the code, we must start with a slightly tweaked version of `Serial.Begin` code:

```c
Serial.begin(9600, SERIAL_8E1);     // Indicates that Serial Comm. should transmit at 9600baud, 8 data bits, and 1 stop bit
```

Having set the correct baudrate and the corresponding data bits, the Instrument Cluster should now able to understand our MCU.

When sending a message to the Instrument Cluster, it expects 16 bytes of data and 1 checksum byte. The checksum byte is required, as the cluster will not display anything without it. The 16 data bytes will be converted to ASCII characters. To calculate the checksum, we will add all the first 16 bytes up in a decimal form, then take that sum, and add 1 to it. Finally, throw away everything but the least significant byte.

**Example of Checksum Formula**

Lets say that we have a message "2222222222222222", which is 16 *"2"*'s. First, we need to sum their values - a `2` written using ASCII is represented in a decimal form as `50`. If we multiply `50` by `16` (since we have 16 characters), we would get `800` (ie. `50 * 16=800`). We then add `1` to this value, and the result is `801` (ie. `800 + 1 = 801`). Next, we would convert the final value from decimal (`801`) to hexadecimal (`0x321`), and throw out everything but the last two hex values (ie. the last byte, so `0x321 => 0x21`). Thus, the `0x21` becomes the checksum we need to send. Below is simplified version in steps:

1. Create a message string up to 16 characters
   - If the message string is less than 16 chars, the message must be padded with `0x20` until the message contains 16 bytes
2. Convert each ASCII character to decimal value
3. Sum up each character decimal value (ie. `dec(c1)+dec(c2)+...+dec(cn))`)
4. Multiply the sum of all character decimal values with number of characters in a message (max. 16 characters)
5. Add `1` to the previous multiplication sum
6. Convert the final value from decimal to hexadecimal
7. Ditch all first bytes from the final value hexadecimal but get last byte (ie. `0x321` would be `0x21`, `0xAB32` would be `0x32` etc.)
8. The last byte hexadecimal value extracted previously is a checksum to be sent

**Important Information regarding Messages**

The Insturment Cluster also requires the message to be resent constantly for it to stay on the Check Control Display. The tests shows that the message has to be sent at least 10x/sec to not flicker or change (every 100ms). The Instrument Cluster requires the message to **always send 16 data bytes**. If the message is shorter than 16 characters (16 bytes), the message must be padded to fill remaining bytes. The message can be either padded with ASCII `<Space>` value, or the corresponding hex value for the `<Space>` which is `0x20`. The message must be padded/filled with `0x20` until all 16 bytes are used.

**Sending the Message**

With everything aftermentioned, we may now program our MCU to send the message defined in variable `Message[17]` as described above:

```c
char Message[17] = "Hello world";       // We use `17` bytes buffer here, since we have [MSG 16byte] + [MSG_CRC/CHECKSUM 1byte]

void setup() {
    Serial.begin(9600, SERIAL_8E1);
}

void loop() {
    delay(95);
    writeMessageToCluster(Message);
}

void writeMessageToCluster(char *input) {
    int x = 0;
    int sum = 1;
    int len = 16;

    for (int i = strlen(input); i < 16; i++) {
        input[i] = 0x20;            // Padding the message if required
    }

    Serial.write(input);            // Send the actual message string

    while (len > 0) {               // Calculate CRC/Checksum
        sum += input[x];
        len -= 1;
        x += 1;
    }

    Serial.write(sum);              // Send CRC/Checksum
}
```

### Result

![](https://i.imgur.com/Wi8D4br.jpeg)

---

# Advanced Message Transmission w/ Bluetooth Integration

The following shorthly explains how to integrate a bluetooth module, a microcontroller (MCU), and an amplifier to deliver the audio from mobile phone to the bluetooth reciever module, and finally outputing the current playing song in the Instrument Cluster itself. The microcontroller has the necessary level shifting circuit to communicate with the Instrument Cluster. The below circuit wiring is a working example of amplifier chip ready to start up and start playing some music.

![](https://i.imgur.com/F0Sy8SV.jpeg)

**I2S Bus** *a/k/a* Inter-IC Sound Bus
The I2S bus (Inter-IC Sound) bus is used in below setup to transmit digital audio signals between the MCU and the audio amplifier module. The I2S bus is a standard for digital audio communication - it transmits high-quality audio data in a digital format, avoiding the noise and degradation associated with analog signals. It's used in this circuit due to involvement of sound processing, digital-to-analog (DAC) conversion, and audio streaming. The MCU sends the digital audio data over I2S to an audio DAC or amplifier module. The amplifier module would then convert the digital audio data into analog signals to drive the connected speaker. This configuration allows for previse, high-fidelity sound output from an MCU (or digital source). For I2S, the connection lines used are: SCK (Serial Clock) - which synchronizes the data transfer, WS (Word Select) - indicates whether the current audio data is for the left or right channel (stereo), SD (Serial Data) - carries the actual audio data. In our setup, these connections are between the microcontroller (MCU) and the amplifier module.

### Integration Schematics

Below schematics is a bearbone version of Instrument Cluster communication alongside Bluetooth module. The placeholder 3.3V regulator is replaced with a permanent one manufactured by Maxim. There is a fuse added for overcurrent protection, and to stop the reverse polarity protection diode from destroying itself. Board also has all the necessary connections, including a **microphone jack** for bluetooth phone calling. The schematics are splitted across two images due to its size.

![](https://i.imgur.com/YI5VCmm.jpeg)
![](https://i.imgur.com/c6K2Kfp.jpeg)

**Setting up Bluetooth Module & Amplifier IC**

To setup the Bluetooth module (BC127), and the Amplifier IC (TDA7802) use the code below. Quick head-ups - these settings are not optimized for sound quaility, but rather as a quick way to see if the two chips would communicate at all.

Start by connecting the Bluetooth module (BC127) and the Amplifier IC (TDA7802) together in the same manner as they are shown in the schematics above. Then, setup the bluetooth module to send audio via the I2S bus. This assumes the module is set to completely default settings already. Start by setting the Serial communication baudrate at 9600, with carriage return only.

```c
// Blue Creation BC127 Bluetooth Module Setup

SET AUDIO=3
SET BPS=16
SET CODEC=0 48000 1
SET I2S=0406
WRITE
RESET
```

Next, we must tell the amplifier to startup, and how to transmit the audio. This can be done using the following code:

```c
// Audio Amplifier STM TDA7802 IC Setup 
//     Note: Assumes Arduino Pin #13 is connected to the Amplifiers "Enable Pin"

#include <Wire.h>

void setup()
{
    Wire.begin();

    pinMode(13, OUTPUT);        // Set the Arduino Pin #13 as 'OUTPUT'
    digitalWrite(13, HIGH);     // Set the Arduino Pin #13 as 'HIGH'
    delay(5000);

    Wire.beginTransmission(0x6C);
    Wire.write(0x80);
    Wire.write(0x00);
    Wire.write(0x00);
    Wire.write(0x18);
    Wire.write(0x00);
    Wire.write(0x00);
    Wire.write(0x01);
    Wire.endTransmission();
}

void loop()
{
    // N/A
}
```

Originally found on this [BimmerForums.com Post](https://www.bimmerforums.com/forum/showthread.php?2294076-Got-bored-so-I-am-building-a-non-fugly-headunit&p=29272058#post29272058).

# BMW E34 Datalogger on Arduino

The user @AlexBelikov posted a thread in 2016 on [Drive.ru - Datalogger on Arduino, Preparation, Speedometer](https://www.drive2.ru/l/9148555/) that contains details of the telemetry/data logger system based on Arduino. In short, he tried to take all the important readings from the vehicle and record them on the SD Card as often as possible. Each entry will also contain a corresponding GPS coordinates and exact time of the logged detail.

He first focused on getting the speedometer in action on the Instrument Cluster. To test, he decided to use the formula for converting *pulses* into speed tacho using a frequency generator on Arduino. The formula he used to convert speed to frequency is like this:

1. There are 4534 pulses in 1 (one) kilometer
2. Multiply the expected *km/h* with this number
3. Divide the converted value per hour to something smaller (ie. *millis*)
4. Since there are 9 blades in the gearbox, recalculate by the radius of the wheel assembly
5. The final figure is very close

On the Arduino side, everything is simple. One must turn ON or OFF the Digital Pin. A transistor is connected to this Arduino Output Pin via ~1 kOhm resistor, which supplies 12V from another source to the dashboard.

![](https://i.imgur.com/h56WgLP.jpeg)

# Displaying Speed/Tacho/Voltage/Temp

The user @Roxsamara posted a [Drive.RU](https://www.drive2.ru/l/639212080997610691/) tutorial how to various sensor stuff into the Instrument Cluster display.

![](https://i.imgur.com/NYoFuLG.jpeg)

---

### References

* [Communicating with the Instrument Cluster](https://hackaday.io/project/334-integrated-rpi-car-audio/log/1078-communicating-with-the-instrument-cluster) @ Hackaday
* [BMW E32/E34 Engine Data on Instrument Cluster OBC](https://forum.btcf.fi/forum/mallisarjakohtainen-keskustelu/-5-sarja-aa/-1988-1995-e34/112073-e34-e32-moottorin-dataa-ajotietokoneen-lcd-lle)
* [Displaying Oil Pressure & Temp in E32/E34 Instrument Cluster OBC](http://www.bimmerboard.com/forums/posts/865568)
* [Injecting UART Messages into the BMW E32 750iL Instrument Cluster LCD](https://web.archive.org/web/20200817092629/https://i-code.net/injecting-custom-uart-messages-into-the-bmw-750il-instrument-cluster-lcd/)
* [Bypass the 'Check Control' Error on E32/E34 Instrument Cluster w/ Arduino](https://github.com/spanDN/check_emulation/tree/master)
* [BMW E34 Display that will display data from Rx/Tx Line w/ Arduino](https://github.com/LOBACU/BMW_e34_display?tab=readme-ov-file)