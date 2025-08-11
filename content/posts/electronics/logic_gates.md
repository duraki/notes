---
title: "Logic Gates"
url: "/hw/logic-gates"
---

This note present fundamental concepts about electrical logical gates (ie. *AND*, *OR*, *NAND*, *NOR*), and to help you become familiar with basic logic gates and logic functions.

### Binary Numbers in Digital Signal

**Binary Numbers**

The power of the digital logic used to construct digital systems like computers comes from the fundamental simplicity of the binary number systems. Binary digits (callled *Bits*) have only two values (`0` and `1`). Using binary numbers makes representation of a any data very long (called *Number of bits*) - for example: `hello` text data in binary would be `0110100001100101011011000110110001101111`, and if you were to count all these 0s and 1s, it would equal to decimal `40` (*of 0s & 1s*), therefore, we can say that textual data `hello` would have "*40 number of bits*". 

### Logic Gates

**Logic Gates - `AND` Gate**

The `AND` gate takes multiple inputs (lets say `A` and `B`). Using the `AND` gate would output a "*HIGH*" (`1`) if, and only if all inputs (`A`, `B`, ...) are also "*HIGH*" (`1`). If any of the inputs are "*LOW*" (`0`), the output of this gate will be a "*LOW*" (`0`) state. The two-input AND gate truth table is as shown below:

and-logic-gate.png

The `AND` Gate Truth Table is as following:

|A|B|Output|Explanation|
|-|-|------|-----------|
|0|0|0|Both inputs are LOW (`0`), the output is also (`0`)|
|1|0|0|One of the inputs is LOW (`0`), the output is also (`0`)|
|0|1|0|One of the inputs is LOW (`0`), the output is also (`0`)|
|1|1|0|Both inputs are HIGH (`1`), the output is also (`1`)|

---

**Logic Gates - `NAND` Gate**

A variation of the AND gate is called the `NAND` gate - or `NOT AND`. The word "NAND" is the contraction of *NOT* and *AND*. The `NAND` gate behaves the same as an `AND` gate with a NOT (inverted) gate connected to the output terminal/signal. To symbolize and make a difference of the `AND` gate, the NAND gate symbol has a bubble (small circle) on the output line. 

nand-logic-gate.png

The `NAND` Gate Truth Table is as following: (*as you've guessed, exactly that of inverted AND gate*)

|A|B|Output|Explanation|
|-|-|------|-----------|
|0|0|1|Both inputs are LOW (`0`), the output is therfore (`1`)|
|1|0|1|One of the inputs is HIGH (`0`), the other is LOW (`0`), the output is therfore (`1`)|
|0|1|0|One of the inputs is HIGH (`0`), the other is LOW (`0`), the output is therfore (`1`)|
|1|1|0|Both inputs are HIGH (`1`), the output is therfore (`0`)|

---

**Logic Gates - `OR` Gate**

The next gate to investigate is the `OR` gate. The output of this gate will be "*HIGH*" (`1`) if any of the inputs is "HIGH" (`1`). If all inputs are "LOW" (`0`), then the OR gate will also output the signal as "*LOW*" (`0`).

or-logic-gate.png

The `OR` Gate Truth Table is as following:

|A|B|Output|Explanation|
|-|-|------|-----------|
|0|0|0|Both inputs are LOW (`0`), the output is also (`0`)|
|1|0|1|One of the inputs is HIGH (`1`), the other is LOW (`0`), the output is therfore (`1`)|
|0|1|0|One of the inputs is HIGH (`1`), the other is LOW (`0`), the output is therfore (`1`)|
|1|1|1|Both inputs are HIGH (`1`), the output is therfore (`0`)|

**Logic Gates - `NOR` Gate**

The `NOR` gate is an OR gate with its output inverted, just like the `NAND` gate is for the `AND` gate described above. The output of the "*NOR*" gate will be "LOW" (`0`), only if any of the input is "HIGH" (`1`). Again, the "NO" gate symbol has a bubble (small circle) of the output line indicating the "NOR/NOT OR" gate. 

nor-logic-gate.png

The `NOR` Gate Truth Table is as following:

|A|B|Output|Explanation|
|-|-|------|-----------|
|0|0|1|Both inputs are LOW (`0`), the output is therefore (`1`)|
|1|0|0|One of the inputs is HIGH (`1`), the other is LOW (`0`), the output is therfore (`0`)|
|0|1|0|One of the inputs is HIGH (`1`), the other is LOW (`0`), the output is therfore (`0`)|
|1|1|1|Both inputs are HIGH (`1`), the output is therfore (`0`)|

**Logic Gates - The `Exclusive-OR` Gate**

TBA. See [1](https://wiki.analog.com/university/courses/alm1k/intro/basic-logic-gates-1).

**Logic Gates - The `Exclusive-NOR` Gate**

TBA. See [1](https://wiki.analog.com/university/courses/alm1k/intro/basic-logic-gates-1).

### Other Resources

- [Wikipedia: Logic Gates](https://en.wikipedia.org/wiki/Logic_gate)
- [Analog.com: Basic Logic Gates](https://wiki.analog.com/university/courses/alm1k/intro/basic-logic-gates-1)