---
title: "Jailbreak Bypass"
---

## Bypass

**Common iOS Jailbreak Bypasses**

* [Libery Lite](https://www.ios-repo-updates.com/repository/ryley-s-repo/package/com.ryleyangus.libertylite.beta/) via Cydia, then go to iOS Settings, and select the application (Recommended)
* [Objection](/frida-objection-tutorial#ios-tutorial) use `ios jailbreak disable` or `--startup-command`
* [Frida](/frida-objection-tutorial#ios-tutorial) as a standalone instrumentation
* [Cycript](/cycript) via REPL-based Dynamic Instrumentation 
* Manual Patching, the old school way

## Detection

**Sandbox Integrity Check**:

On iOS devices, user apps installed in `/var/mobile/Application` are restricted by the sandbox, while System Apps installed in `/Application` are not restricted by the sandbox. The below snippet would try to call `fork()`, `opendir()`, and `system()`, and therefore fail if any of the calls succeeded.

```
void SandboxIntegrityCheck() {
    int result = fork(); 		// also vfork(), popen()
    if(!result)
        exit(0);
    if(result >= 0) 			// jailbreak detected, app. shouldn't be allowed to `fork()`
        {sandbox_is_compromised = 1};
        opendir(“/dev”);  		// also system(), getgid() // confirmation-bias to jailbreak
}
```

**FileSystem Detection**

Detect the existence of common jailbreak tools, directories and files. Typical Jailbreak detection method, and quite easy to bypass.

```
void FileSystemCydiaCheck() {
    struct stat s;
    int is_jailbroken = stat(“/Applications/Cydia.app”, &s) == 0;

    if (is_jailbroken != 0) { 
        // jailbreak detected, app. can 'stat' on the Cydia bundle
    	{jailbreak_detected = 1};
    }
}

# besides, many other paths are checked
//  /Library/MobileSubstrate/MobileSubstrate.dylib
//  /private/var/stash
//  /private/var/lib/apt
//  /private/var/lib/cydia
//  /usr/libexec/cydia
//  ...
```

**Detect Mount Point**

Using `/etc/fstab` file and making it smaller, as the original `fstab` is fixed, depending on the iPhone device. In this case, the use of `fstab` would be integrity check to detect jailbreak detection.

```
void fsStabJailed() {
    struct stat s;
    stat("/etc/fstab", &s);
    return s.st_size;			// Depending on the retval of 's', the device is jailed
}
```

**Detect Soft Links**

Detect `/Applications` soft link. If the device is jailbroken, the softlink will be replaced to `/var/stash/<PATH>` directory, which usually is not case on jailed devices.

```
void checkSoftLinks() {
    struct stat s;
    if (lstat("/Applications", &s) != 0) {
    	if (s.st_mode & S_IFLNK) {
    		exit(-1); 		// Detected jailbroken device
    	}
    }
}

# besides, many other paths are checked
//  /Library/Ringtones
//  /Library/WallPaper
//  /usr/arm-apple-darwin9
//  /usr/include
//  /usr/libexec
//  /usr/share
```

**Detect Cydia URL Scheme**

Cydia will create a `cydia://` URL scheme on the jailbroken device. If an iOS app. can call `NSURL` handler with this scheme, the device is jailbroken.

```
# Objective-C sample 
NSURL *url [NSURL URLWithString @”cydia://package/com.example.package”];
```

**Detection of KernelEnv Variables**

When a device is jailbroken, two kernel environment variables will be added to bypass iOS Code Signing mechanism. These variables are `proc_enforce`, and `vnode_enforce`. Using the `sysctlbyname()` function, an app can check this system information and validate the device.

```
/** on a jailed device, the following values should be '1' */
sysctlbyname(security.mac.proc_enforce)
sysctlbyname(security.mac.vnode_enforce)
```

**Detect `DYLD_INSERT_LIBRARIES` in running process**

On a jailbroken device, a `MobileSubstrate.dylib` will be injected via `DYLD_INSERT_LIBRARIES` in the environment variable. In fact, `getenv('DYLD_INSERT_LIBRARIES')` will return `NULL` -- on a jailed device, or `\0` on a jailbroken device.

```
$ getenv("DYLD_INSERT_LIBRARIES")
```

## Jailbreaking Techniques

* [Legacy-iOS-Kit](https://github.com/LukeZGD/Legacy-iOS-Kit)