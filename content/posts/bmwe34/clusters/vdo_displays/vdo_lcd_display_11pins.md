---
title: VDO LCD Display - 11 Pins
url: /bmw/e34/vdo-lcd-11pins
---

![](https://i.imgur.com/L75nTjF.png)

* OEM Part ID No.: 1 388 799
* Other Reference No.: [62-11-1-388-799](http://bmwfans.info/parts-catalog/62111388799), 5EE626, 62111388799
* Production MY: 1992 - 1996
* Screen Size: `N/A`
* Used on: [Instrument Clusters - High (Normal)](/bmw/clusters/high-normal), [Instrument Clusters - High (Redesign/240)](/bmw/clusters/high-redesign), [Instrument Clusters - High (Redesign 2)](/bmw/clusters/high-redesign-2)

---

This is a note describing an LCD Display Module, with flat ribbon cable, adaptable to VDO Instrument Cluster dashboards of a BMW 5 Series E34 (post-facelift models, for E34 525i and up, and also E32 735i and up).

{{< details "Expand Actual Photos" >}}
![](https://i.imgur.com/J85JaTO.png)
![](https://i.imgur.com/zXHSD9k.jpeg)
![](https://i.imgur.com/DskC967.jpeg)
{{< /details >}}

### Pinouts

![](https://i.imgur.com/VWssd7M.png)

![](https://i.imgur.com/H8gQkas.png)

The blue marking on top of the wireframe indicates a pinout coming out of the LCD Display Module that gets inserted into Instrument Cluster. For a full pinout diagram, alongside other information, please take a look at the repository hosted on [duraki/bmw_e34_cluster_test_bench-pinout](https://github.com/duraki/bmw_e34_cluster_test_bench-pinout) inside the `*.numbers` file.

{{< imgcap title="VDO LCD Display - 11 Pins - Pinout Diagram" src="/posts/bmwe34/clusters/vdo_displays/vdo_disp_11pins-pinout-image.png" >}}

| **Pin No**  | **Type** | **Description**         | **Signal Type**    |
|----------|----------|-------------------------|--------------------|
| Pin 1    | M        | Ground                  | GND                |
| Pin 2    | E        | VCC +5V                 | 4.98V              |
| Pin 3    | E        | Contrast Voltage (VO)   | 0.03V - 0.07V      |
| Pin 4    | E        | Register Select (RS)    | 4.86V - 5.02V      |
| Pin 5    | E        | Read/Write (RW)         | 4.86V - 5.02V      |
| Pin 6    | E        | DB4                     | 0.01V - 0.02V      |
| Pin 7    | E        | DB5                     | 0.01V - 0.08V      |
| Pin 8    | E        | DB6                     | 0.03V              |
| Pin 9    | E        | DB7                     | 0.03V              |
| Pin 10   | E        | Power Supply +5V        | 4.98V              |
| Pin 11   | E        | Enable Signal (E)       | 1.03V              |
