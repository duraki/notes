---
title: "Scrcpy for Android"
---

Install [`scrcpy`](https://github.com/Genymobile/scrcpy) on your HostOS using `apt` for GNU/Linux, or `brew` for macOS as shown below:

```
# On Debian/Ubuntu or similar Linux distribution
$ sudo apt install scrcpy
```

```
# On Apple macOS
$ brew install scrcpy
```

Choose a connected devices for which you want to use `scrcpy`:

```
$ adb devices
# List of devices attached
# ...
```

Use `scrcpy` by either specifying the connected devices, or leave blank if only one device is connected since `scrcpy` will default to that one:

```
$ scrcpy -s [device_id]
```

Record a video of the screen of the device by running `scrcpy` command with `--record` argument:

```
$ scrcpy -s [device_id] --record /tmp/screen.mp4
```
