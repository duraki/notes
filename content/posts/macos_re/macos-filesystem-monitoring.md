---
title: "MacOS Filesystem Monitoring"
---

The file(s) and filesystem change monitoring software is used to receives notifications when the contents of the specified files or directories are modified.

Available options:

- (**PAID**) [FSMonitor](http://fsmonitor.com/)
- (**FREE**) [fswatch](https://github.com/emcrisostomo/fswatch)
- **Developing MacOS FS Monitoring** [#ref](#Developing-MacOS-FS-Monitoring)

## FSMonitor

The [xnucrack](https://github.com/xnucrack/) contains license for [FSMonitor](http://fsmonitor.com/). It's pretty simple to use and, unlike `fswatch`, it is paid to use and it provides native MacOS GUI.

## fswatch

[This is](https://emcrisostomo.github.io/fswatch/) a cross-platform file change monitor with multiple backends: **Apple OS X File System Events API**, **BSD kqueue**, **Solaris/Illumos**, **Linux**, and **Microsoft Windows**. 

Install `fswatch`  via:

```
$ brew install fswatch
```

### Developing MacOS FS Monitoring

Using Apple's introduction course, you can utilise [Endpoint Security](https://developer.apple.com/documentation/endpointsecurity/monitoring_system_events_with_endpoint_security) to receive notifications about filesystem and file-related events that occur on the Host OS. Refer to XCode [Endpoint Security](https://developer.apple.com/documentation/endpointsecurity) documentation to learn more.