---
title: "Medusa Framework"
url: "medusa"
---

[Medusa](https://github.com/Ch0pin/medusa) is an extensible and modularized framework that automates processes and techniques practiced during the dynamic analysis of Android and iOS Applications. This tool requires both Frida, and a POSIX-based operating system running as HostOS (ie. Linux or MacOS). Medusa is usually used in combination with [stheno](https://github.com/Ch0pin/stheno) when analyzing Android applications, which provides a way to manipulate application intents.

You can use Medusa [on Android](/using-medusa-android) and [on iOS](/using-medusa-ios) systems, but `frida-server` must be available as a pre-requisit.

### Installation

Clone `medusa` repository:

```
$ git clone git@github.com:Ch0pin/medusa.git --depth=1
$ cd medusa
$ python3 -m venv path/to/venv
$ source path/to/venv/bin/activate
$ python3 -m pip install -r requirements.txt
# ...
```

Alternatively, you can use `medusa` as a [Docker](#docker) container.

### Docker

You can find `Dockerfile` in the `medusa/` directory after cloning it, as described in [Installation](#installation). Once cloned, you may build the Docker image using the commands below:

```
$ docker build -t medusa:local ./
# ....
```

Then run this newly built Docker image using:

```
$ docker run --name medusa --net=host --rm -it medusa:local
```

On your HostOS (ie. MacOS), run `adb` in TCP/IP mode on the physical device or emulator:

```
$ adb tcpip 5555
```

Connect to your device from within the Docker shell:

```
$ root@docker# adb connect <device_ip>:5555
```

### Usage

Check out [wiki page](https://github.com/Ch0pin/medusa/wiki) for usage details. Separate notes for `medusa` are visible in using [Medusa on Android](/using-medusa-android) and [Medusa on iOS](/using-medusa-ios).

