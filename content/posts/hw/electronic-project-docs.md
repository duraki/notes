---
title: "Documenting Electronic Projects"
url: /hw/docs
---

## WireWiz (*Cable Documentation*)

WireViz is a tool for easily documenting cables, wiring harnesses and connector pinouts. It takes plain text, YAML-formatted files as input and produces beautiful graphical output (ie. *SVG, PNG, ...*). It can also handle automatic BOM (*Bill of Materials*) creation and has a lot of extra features.

* [GitHub](https://github.com/wireviz/WireViz)

**Install instructions:**

```bash
$ cd utils/clone
$ git clone git@github.com:wireviz/WireViz.git
# $ git checkout <tag>/<branch>
$ cd WireWiz
$ python3 -m venv path/to/venv
$ source path/to/venv/bin/activate
$ python3 -m pip install -e .
##  => $ path/to/venv/bin/wireviz --help
```

To use it, simply provide `*.yaml` definition file following Wirewiz format and the Python script will output the graphical representation using GraphViz:

```bash
# Depending on the options specified, this will output selected/all graphic files (svg,png,...)
$ wireviz ~/path/to/file/mywire.yml

# Wildcards in the file path (*.yaml) are also supported to process multiple files at once
$ wireviz ~/path/to/files/*.yml

# To see how to specify the output formats, as well as additional options, run:
$ wireviz --help
```

**WireWiz Definition Files**

Example Demo: `#1`:

```yaml
connectors:
  X1:
    type: D-Sub
    subtype: female
    pinlabels: [DCD, RX, TX, DTR, GND, DSR, RTS, CTS, RI]
  X2:
    type: Molex KK 254
    subtype: female
    pinlabels: [GND, RX, TX]

cables:
  W1:
    gauge: 0.25 mm2
    length: 0.2
    color_code: DIN
    wirecount: 3
    shield: true

connections:
  -
    - X1: [5,2,3]
    - W1: [1,2,3]
    - X2: [1,3,2]
  -
    - X1: 5
    - W1: s
```

Will produce the following image:

{{< imgcap title="WireWiz - YAML Producing Output for Example #1" src="/posts/images/wirewiz_demo01.png" >}}

Check more examples in official [GitHub - Examples README](https://github.com/wireviz/WireViz/blob/master/examples/readme.md) file and samples. There is also a [tutorial](https://github.com/wireviz/WireViz/blob/master/tutorial/readme.md) explaining from bare minimal YAML definition to a more complex wiring systems implemented and case shown.

The [WireWiz syntax](https://github.com/wireviz/WireViz/blob/master/docs/syntax.md) is heavily documented, while also offering additional options [when using images](https://github.com/wireviz/WireViz/blob/master/docs/advanced_image_usage.md) in YAML defs.

There is also a simple [GUI wrapper for WireWiz](https://github.com/slightlynybbled/wireviz-gui) developed for WindowsNT.

## Pinout (*Hardware Pinout Documentation*)

The [Pinout](https://pinout.readthedocs.io/) is an open-source Python package that generates hardware pinout diagrams to SVG format.

* [GitHub](https://github.com/j0ono0/pinout)

{{< imgcap title="Pinout - Producing Output from README" src="/posts/images/demo_pinout_diagram.png" >}}

## InteractiveHtmlBom (*BOM Documentation*)

Interactive HTML BOM generation plugin for KiCad, EasyEDA, Eagle, Fusion360 and Allegro PCB designer. This plugin generates a convenient Bill of Materials (BOM) listing with the ability to visually correlate and easily search for components and their placements on the PCB.

* [GitHub](https://github.com/openscopeproject/InteractiveHtmlBom)

## Electric Symbols (*Symbols Documentation*)

- GitHub: [Electric Symbols Library (Inkscape)](https://github.com/upb-lea/Inkscape_electric_Symbols)

## WaveDrom (*Digital Timing Diagram Documentation*)

[WaveDrom](https://wavedrom.com/) is a Digital Timing Diagram generation system. WaveDrom draws your Timing Diagram or Waveform from simple textual description. It comes with description language, rendering engine and the editor. WaveDrom editor works in the browser or can be installed on your system.
Rendering engine can be embeded into any webpage.

- [WaveDrom Tutorial](https://wavedrom.com/tutorial.html)

## Circuits (*Electrical PCB and Circuits Documentation*)

[tscircuit](https://docs.tscircuit.com/) is an open-source React/Typescript electronics toolchain and ecosystem for creating, previewing, simulating and manufacturing Printed Circuit Boards (PCBs).

- Quickstart for [web](https://docs.tscircuit.com/intro/quickstart-web), for [CLI](https://docs.tscircuit.com/intro/quickstart-cli), and for [ChatGPT/AI](https://docs.tscircuit.com/intro/quickstart-ChatGPT)

[Gerber Viewers](https://github.com/kitspace/awesome-electronics?tab=readme-ov-file#gerber-viewers) are used to view "*gerber*" files. Some of the software solutions for geber file viewing is shown on the linked GitHub repository.

[EDA](https://github.com/kitspace/awesome-electronics?tab=readme-ov-file#free-eda-packages) are embedded development applications that are used to design schematics and embedded device systems.
