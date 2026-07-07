---
title: "r2frida"
---

[r2frida](https://github.com/nowsecure/r2frida) is a self-contained plugin for [radare2](/radare2) that allows to instrument remote processes using [frida](/frida).

The recommended way to install r2frida is via r2pm:

```
$ r2pm -ci r2frida
```

### Usage

For testing, use `r2 frida://0`, as attaching to the pid0 in frida is a special session that runs in local. Now you can run the `:?` command to get the list of commands available.

```
$ r2 'frida://?'
r2 frida://[action]/[link]/[device]/[target]
* action = list | apps | attach | spawn | launch
* link   = local | usb | remote host:port

# ...
```

### Examples

Connect to local session

```
$ r2 frida://0     # same as frida -p 0, connects to a local session
```

You can attach, spawn or launch to any program by name or pid, The following line will attach to the first process named rax2 (run rax2 - in another terminal to test this line)

```
$ r2 frida://rax2  # attach to the first process named `rax2`
$ r2 frida://1234  # attach to the given pid
```

Using the absolute path of a binary to spawn will spawn the process:

```
$ r2 frida:///bin/ls
[0x00000000]> :dc        # continue the execution of the target program
```

Also works with arguments:

```
$ r2 frida://"/bin/ls -al"
```

For USB debugging iOS/Android apps use these actions. Note that spawn can be replaced with launch or attach, and the process name can be the bundleid or the PID.

```
$ r2 frida://spawn/usb/         # enumerate devices
$ r2 frida://spawn/usb//        # enumerate apps in the first iOS device
$ r2 frida://spawn/usb//Weather # Run the weather app
```

### Commands

These are the most frequent commands, so you must learn them and suffix it with ? to get subcommands help.

```
:i        # get information of the target (pid, name, home, arch, bits, ..)
.:i*      # import the target process details into local r2
:?        # show all the available commands
:dm       # list maps. Use ':dm|head' and seek to the program base address
:iE       # list the exports of the current binary (seek)
:dt fread # trace the 'fread' function
:dt-*     # delete all traces

# more commands @ https://github.com/vadimszzz/iOS-Internals-and-Security-Testing#commands
```

### References

* [Troubleshooting](https://github.com/nowsecure/r2frida#troubleshooting)
* [r2frida-wiki](https://github.com/nowsecure/r2frida/wiki/random)