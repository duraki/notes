---
title: Fault Injection
url: /hw/fault-injection
---

# Fault Injection

The **Fault Injection** technique is a theory introducing hardware glitching using the electro magnetic voltage injection or clock fault injection attack vectors, allowing the attacker to induce unexpected fault in the electronic system or subsystem components logic, leading to missuse or bypass of the specific selection on the targeted device (DUT). This type of attack was proven multiple times as effective, with notable examples being a [Trezor One](https://mkesenheimer.github.io/blog/trezor-wallet-hack-v161.html) hardware crypto wallet to gain access, similarly [dumping the firmware of the Apple AirTag](https://hackaday.com/2022/07/14/apple-airtags-hacked-and-cloned-with-voltage-glitching/), and even glitching the Nintendo Switch, which was hacked using voltage glitching. Note that you need a voltage glitching device to execute this attack vector on a real hardware device, either a commercial product such is *ChipWhisperer (Pro)*, [PicoGlitcher](https://fault-injection-library.readthedocs.io/en/latest/), or alternatively building your own DIY solution, for example this open-source [ESP8266-based Fault Injection](https://github.com/PythonHacker24/fault-injector) toolkit. A [Faultier](https://1bitsquared.com/products/faultier) commercial fault injection product is recommended due to price and ease of use.

This technique eventually provides the attacker to trigger **undefined behavior**, which results in different type of results, with some of them listed below:

**Undefined Behavior** due to Fault Injection attacks:

- Chip, MCU or SoC might crash
- A corrupt registers may occur
- Memory disallocation and malformation
- Skipping over logically handled instructions (ie. *unskippable* parts)
- Re-enable debugging features on locked chips
- Bypass secure-boot mechanisms
- [Gain code-execution](https://riverloopsecurity.com/blog/2020/10/hw-101-glitching/) by glitching `memcpy`

{{< notice >}}
Hardware Implementation (Example in Clang)
{{</ notice >}}
{{< callout emoji="💡" text="Lets take a look at a simple hardware implementation logic that might be abused in a real-life scenarios, where the part of the programmed electrical system checks for a valid password entry; with example code provided below." >}}

```c
bool passwd_valid = check_password();
if (passwd_valid) {
    printf("Password is correct, here is your secret code:");
    printf(secret);
}
```

Due to `bool-type` variable `passwd_valid` which returns either `1/0`, the results of the conditional `if` would factually equal to:

```c
bool passwd_valid = check_password();
if (passwd_valid) { // => equals to condition `if (passwd_valid != 0)`
    //
    // ...
    // printf(secret)
}
```

This means that for example if a `passwd_valid` equals to `0` (`false`), then the password is **invalid**, while if it returns `1` (`true`) then the password is **valid**. Thought, if a password is a valid hexadecimal address, ie. `passwd_valid = 0x86540BB2` this would result in the password being labeld as **valid** as well; since the `passwd_valid` does not equal to zero (`0x0`) in this case.

Therefore, a single bit-flip is enough to bypass this conditional check and we can cause this bit-flip using **voltage injection** attack vector. Esentally, what we will try to do is write the bit in the processor while the conditional check of a pool is at validation point; by dropping the supply and by that, hopefully corrupting a bit in `passwd_valid` bit.



<!--{{< imgcap title="Block Diagram - Example during BMW Analog GSM Telephone System RevEng" src="/posts/hw/blockdi-gsm.png" >}}-->

## Voltage Fault Injection

This is the most common attacking vector when it comes to voltage glitching and fault injection techniques, and while these terms (both `voltage injection`, & `voltage glitching` are the word terms) are used in the description and overview reference, different type of wording might be used to simplify the theory behind this attack. 

Simply put, a **voltage injection** is injecting a higher voltage against a particular chip on a `X, Y` graph, a supplied voltage referencing the `Y` axis, while the `X` axis indicating the *time* towards the chip for a very short amount of time at a very precise control time, results in an **undefined behaviour**.

```
Voltage
  |
  |___________________________      _____________________________
  |                           |    |
  |                           |    |
  |                            |  |
  |                             ||
  |                             ||
  |                             ||
  |
  +---------------------------------------------------------> Time
```

To find the correct proposition for the attack, the signal has to be referenced using the "Trigger", "Delay", and the "Pulse". Using these terminologies, the "Pulse" is the actual voltage drop that shall happen during the execution of the chip logic, and the indicator of the pulse has its own **Pulse Length** - a time reference for which the pulse takes the action. The "Delay" is the time frame reference of the signal until it reaches the "Pulse". The delay can be specified for example, while powering up the chip, known as a "Trigger". The "Trigger" is a reference point in the timeframe, indicating at which point does the signal is started (ie. _triggered_), therefore indicating a delay and a pulse frame for which it was taken on. Take a look at the following example of what each of the indicator means in using the same `X` and `Y` axis indicating the *Voltage* and *Time* (ie. timeframe) reference respectively.

```
                                         Pulse
                                         Length
                                         <---->
Voltage                                       
  |  ___________________________________       ________________
  | |         Delay                      |   |
  | |<-------------------------------------->|
  | |                                    |   |
  | |                                     | |
  |/                                       |
  | ^Trigger                               V
  |
  +---------------------------------------------------------> Time
```

The trigger point of the fault injection is the most important part of the attack vector since it indicates at which point of time do we want the voltage injection to happen, therefore finding one is the most precious and tedious task for a successful attack. For a more advanced fault injections, one might even use a further systematic approaches, for example variable "Pulse strength" which can be triggered at some point of time, right after the pulse, as shown in ASCII example below:

```
                                         Pulse
                                         Length
                                         <---->
Voltage
  |  ___________________________________       _________________
  | |         Delay                       |  |
  | |<-------------------------------------->|
  | |                                     |  | ^
  | |                                     |  | |  Pulse
  |/                                      | |  |  strength
  | ^Trigger                               |   |
  |                                        V   v
  |
  +---------------------------------------------------------> Time
```

## Clock Fault Injection

_TBA_

### Resources

* Hextree.io: [Fault Injection / Voltage Glitching Video Tutorial Series](https://app.hextree.io/courses/fault-injection-introduction/fault-injection-theory)
* [Blackhat 2015: Implementing Practical Electrical Glitching Attacks (`PDF`)](https://blackhat.com/docs/eu-15/materials/eu-15-Giller-Implementing-Electrical-Glitching-Attacks.pdf)
* [Voltage Glitching with the Pico Glitcher and Findus](https://blog.syss.com/posts/voltage-glitching-with-picoglitcher-and-findus/)
* [How to Voltage Fault Injection](https://www.synacktiv.com/publications/how-to-voltage-fault-injection)
* Hardware Side Channel Attack: [Fault Injection](https://swisskyrepo.github.io/HardwareAllTheThings/side-channel/fault-injection/)
