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

## iCloud Monitoring

There is a native MacOS Terminal command `brctl` which stands for "`brctl` – **Manage the CloudDocs daemon**". It allows end-user to diagnose and collect iCloud logs, execute a download/dump/monitor operations against the CloudDocs database and it's services.

There is really not a lot of information on the internet regarding this MacOS utility, but one can read this online [manpage](https://www.manpagez.com/man/1/brctl/osx-10.10.php) of the `brctl`, or read the latest available version by running `man` command on it:

```sh
$ man brctl
# ...
```

I also found this GitHub [MacHack](https://github.com/azenla/MacHack?tab=readme-ov-file#brctl) repository describing this utility but it's not providing a lot of information whatsoever. Additionally, the [hitchiker's guide](https://man.ilayk.com/man/brctl/) also contain entry about this utility which is dry as well.

Some commands I've discovered:

```sh
$ brctl log -w --shorten		# Dumps the CloudDocs daemon logs
# [dbg  2025-01-20 17:25:47.835+0100] brctl[90556]  ┏  BRCopyUbiquityContainerIdentifiersForCurrentProcess
# [dbg  2025-01-20 17:25:47.837+0100] brctl[90556]  ┃  current process containers: <private>
# [dbg  2025-01-20 17:25:47.837+0100] brctl[90556]  ┗  end
# [dbg  2025-01-20 17:25:47.837+0100] bird[86817]  ┏  received new XPC connection: <private>, for uid: 501
# [dbg  2025-01-20 17:25:47.838+0100] bird[86817]  ┃  welcome <private>!
# [dbg  2025-01-20 17:25:47.839+0100] bird[86817]  ┗  end
# ...

$ brctl status 					# Get iCloud Client status logs
# <com.apple.CloudDocs[1] foreground {client:idle server:full-sync|fetched-recents|fetched-favorites|ever-full-sync sync:has-synced-down last-sync:2025-01-20 17:16:49.232, requestID:8328, caught-up, token:unkown-token-size:34 (HwoECNfNFxgAIhUIhYil3v7s9PN8EI6fotm4k6DKiAEoAA==) rid:8329 appuninstalled:(null)}>
# ...

$ brctl monitor com.apple.CloudDocs	# Monitor iCloud DriveSync status
# ...
```

Use `brctl` without any arguments in Terminal to list all available command options and arguments. The truncated list of commands are shown below:

```sh
$ brctl

Usage: brctl <command> [command-options and arguments]

    -h,--help            show this help

COMMANDS

diagnose [options] [--doc|-d <document-path>] [<diagnosis-output-path>]
    diagnose and collect logs

log [options] [<command>]

dump [options] [<container>]
    dump the CloudDocs database

status [<containers>]
    Prints items which haven't been completely synced up / applied to disk

accounts [options]
    Displays iCloudDrive eligible accounts and their logged in/out status and directory name

quota
    Displays the available quota in the account

monitor [options] [<container> ...]
    monitor activity
```

{{< details "Show all command-options and arguments" >}}

```
Usage: brctl <command> [command-options and arguments]

    -h,--help            show this help

COMMANDS

diagnose [options] [--doc|-d <document-path>] [<diagnosis-output-path>]
    diagnose and collect logs

    -M,--collect-mobile-documents[=<container>]  (default: all containers)
    -s,--sysdiagnose     Do not collect what's already part of sysdiagnose
    -t,--uitest          Collect logs for UI tests
    -n,--name=<name>     Change the device name
    -f,--full            Do a full diagnose, including server checks
    -d,--doc=<document-path>
                         Collect additional information about the document at that path.
                         Helps when investigating an issue impacting a specific document.
    -e,--no-reveal       Do not reveal diagnose in the Finder when done
    [<diagnosis-output-path>]
                         Specifies the output path of the diagnosis; -n becomes useless.

log [options] [<command>]

    -a,--all                         Show all system logs
    -p,--predicate                   Additional predicate (see `log help predicates`)
    -x,--process <name>              Filter events from the specified process
    -d,--path=<logs-dir>             Use <logs-dir> instead of default
    --last num [m|h|d]               Limits the captured events to the period starting at the given interval ago from the current time
    -S,--start="YYYY-MM-DD HH:MM:SS" Start log dump from a specified date
    -E,--end="YYYY-MM-DD HH:MM:SS"   Stop log dump after a specified date
    -b                               Show CloudDocs logs
    -f                               Show FileProvider related logs
    -F                               Show FruitBasket related logs
    -N                               Show network related logs (should be used in conjonction with another flag)
    -g                               Show Genstore related logs
    -i                               Show SQL and CloudDocs logs
    -o                               Show local storage logs
    -D                               Show logs from the Denator subsystem
    -z,--local-timezone              Display timestamps within local timezone
    --dark-mode                      Adapt color scheme to dark mode terminal
    -q,--quick                       Print logs without heavy pre-processing

dump [options] [<container>]
    dump the CloudDocs database

    -o,--output=<file-path>
                         redirect output to <file-path>
    -d,--database-path=<db-path>
                         Use the database at <db-path>
    -e,--enterprise
                         Use the Data Separated database
    -i,--itemless
                         Don't dump items from the db
    -u,--upgrade
                         Upgrade the db if necessary before dumping
    -v,--verbose
                         Be verbose when dumping the database

    [<container>]        the container to be dumped

status [<containers>]
    Prints items which haven't been completely synced up / applied to disk

    [<container>]        the container to be dumped

accounts [options]
    Displays iCloudDrive eligible accounts and their logged in/out status and directory name
    -w,--wait            wait for logged in accounts to load

quota
    Displays the available quota in the account

monitor [options] [<container> ...]
    monitor activity
    -g                   dump global activity of the iCloud Drive
    -i                   dump changes incrementally
    -t                   amount of time in seconds to run the query, the query will stop after the specified time
    -p                   only static gathering
                         Example: brctl monitor -p com.apple.CloudDoocs
    -S,--scope=<scope>
                         restrict the NSMetadataQuery scope to docs, data, external or a combination
    -w,--wait-uploaded
                         wait for all items to be uploaded

    [<container> ...]    list of containers to monitor, ignored when -g is used
```

{{</ details >}}

{{< details "Expand for manpage" >}}

```
BRCTL(1)                    General Commands Manual                   BRCTL(1)

NAME
     brctl – Manage the CloudDocs daemon

SYNOPSIS
     brctl ⟨command⟩ [command-options and arguments]

DESCRIPTION
     brctl understands the following commands:

     diagnose [options] [⟨diagnosis-output-path⟩]
         diagnose and collect logs

         -M,--collect-mobile-documents[=<container>]  (default: all
     containers)
         -s,--sysdiagnose     Do not collect what's already part of
     sysdiagnose
         -n,--name=<name>     Change the device name
         [<diagnosis-output-path>]
                              Specifies the output path of the diagnosis; -n
     becomes useless.

     download ⟨path⟩
         download a local copy of the document at this path

     evict ⟨path⟩
         evict the local copy of the document at this path

     log [options] [⟨command⟩]

         -c,--color[={yes,no}]
                              turn on or off color use
         -d,--path=<logs-dir> use <logs-dir> instead of default
         -H,--home=<home-dir> use this as the ~ prefix, to look for ~/L/
         -f,--filter=<predicate>
                              only show lines matching predicate
         -m,--multiline[={yes,no}]
                              turn on or off multiple line logging
         -n=<number>          number of initial lines to display
         -p,--page            use paging
         -w,--wait            wait for new logs continuously (syslog -w)
         -t,--shorten         Shorten UUIDs, paths, etc
         -s,--digest          Only print digest logs

     dump [options] [⟨container⟩]
         dump the CloudDocs database

         -o,--output=<file-path>
                              redirect output to <file-path>
         -d,--database-path=<db-path>
                              Use the database at <db-path>
         [<container>]        the container to be dumped

     monitor [options] ⟨container⟩
         use NSMetadataQuery to monitor the container

         -S,--scope=<scope>
                              restrict the NSMDQ scope to DOCS, DATA, or BOTH

     versions [options] ⟨path⟩ [ALL|etags...]
         list the non-local versions of the document at this path.

         -a,--all             List all non-local versions including those that
                              are locally cached

SEE ALSO
     bird(8)

Mac OS X                           22/04/14                           Mac OS X
```

{{< /details >}}

To restart iCloud process, try to kill process named `bird`, like so:

```sh
$ sudo killall bird
# ...
```


### Developing MacOS FS Monitoring

Using Apple's introduction course, you can utilise [Endpoint Security](https://developer.apple.com/documentation/endpointsecurity/monitoring_system_events_with_endpoint_security) to receive notifications about filesystem and file-related events that occur on the Host OS. Refer to XCode [Endpoint Security](https://developer.apple.com/documentation/endpointsecurity) documentation to learn more.
