---
title: "macOS Filesystem Monitoring"
---

* Also See: [MacOS App. Preferences](/macos-application-preferences), and [Hooking MacOS Preferences changes](/hook-macos-preferences).

The file(s) and filesystem change monitoring software is used to receives notifications when the contents of the specified files or directories are modified.

Available options:

- **Paid**: [FSMonitor](http://fsmonitor.com/)
- **Free**: [fswatch](https://github.com/emcrisostomo/fswatch)
- **Developing MacOS FS Monitoring**: [#ref](#developing-macos-fs-monitoring)

With **SIP** is disabled, one can use `opensnoop`:

```
$ sudo opensnoop
$ sudo opensnoop -n Preview
```

The `opensnoop` tracks file opens. As a process issues a file open, details such as UID, PID and pathname are printed out.

## FSMonitor

The [xnucrack](https://github.com/xnucrack/) contains license for [FSMonitor](http://fsmonitor.com/). It's pretty simple to use and, unlike `fswatch`, it is paid to use and it provides native MacOS GUI.

## fsmon

*(Preferred Option)* - Developed by [nowsecure/frida](frida.re), [fsmon](https://github.com/nowsecure/fsmon/) is a great little multi-platform utility that acts as a file change monitor with multiple backends included. Supported on iOS/macOS as well as Linux and Windows! Backends can be any of: `osx=`:devfsev,kqueue,kdebug,fsevapi or `linux/android=`:inotify,fanotify,kdebug. Btw, typing `fsmon -L` will yield all supported backends.

Close `fsmon` to local host:

```bash
$ cd /tmp/
$ git clone https://github.com/nowsecure/fsmon/ && cd fsmon
$ make
$ sudo make install
$ which fsmon
# /usr/local/bin/fsmon
```

Usage is simple as is the case with other listed FS monitoring utils:

```bash
# via App/Process Name
$ sudo fsmon -B kdebug  -P MakePass / 		# will monitor from ROOT(/) dir. on changes made by process name 'MakePass'

$ sudo fsmon -B kdebug -J -P\
  MakePass ~/ | jq -r .filename # will monitor from HOME(~/) dir. on changes made by process name 'MakePass'
								# outputs to JSON via -J and parsed via 'jq'

$ sudo fsmon -B kdebug -P MakePass ~/ 		# will monitor from HOME(~/) dir. on changes made by process 'MakePass'


# or via PID
$ PIDOF=$(ps -A | grep Safari | grep -e grep | awk '{print $1}')
$ sudo fsmon -B fsevapi -p $PIDOF ~/ 	 	# will monitor from HOME(~/) dir. on changes made by PID of process 'Safari'
											# uses 'fsevapi' as the backend
```

## filemon

[filemon](http://newosxbook.com/tools/filemon.html) is a free, open-source, FS monitoring tool.

```
filemon -h
Usage: filemon [options]
Where [options] are optional, and may be any of:
	-p|--proc  pid/procname:  filter only this process or PID
	-f|--file  string[,string]:        filter only paths containing this string (/ will catch everything)
	-e|--event event[,event]: filter only these events
	-s|--stop:                auto-stop the process generating event
	-l|--link:                auto-create a hard link to file (prevents deletion by program :-)
	-c|--color (or set JCOLOR=1 first)
```

## fswatch

[This is](https://emcrisostomo.github.io/fswatch/) a cross-platform file change monitor with multiple backends: **Apple OS X File System Events API**, **BSD kqueue**, **Solaris/Illumos**, **Linux**, and **Microsoft Windows**.

Install `fswatch`  via:

```
$ brew install fswatch
```

Usage is simple as; to scan ROOT `/` for AppName target:

```
$ fswatch --access -xr / | grep -i "AppName"
```

### Developing MacOS FS Monitoring

Using Apple's introduction course, you can utilise [Endpoint Security](https://developer.apple.com/documentation/endpointsecurity/monitoring_system_events_with_endpoint_security) to receive notifications about filesystem and file-related events that occur on the Host OS. Refer to XCode [Endpoint Security](https://developer.apple.com/documentation/endpointsecurity) documentation to learn more.
