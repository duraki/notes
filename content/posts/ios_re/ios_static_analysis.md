---
title: "iOS Static Analysis"
---

**Watch iPhone device System Logs**

```
$ idevicesyslog
[connected]
Nov 18 17:58:52 kernel[0] <Notice>: EXC_RESOURCE -> duetexpertd[37309] exceeded mem limit: InactiveHard 14 MB (fatal)
Nov 18 17:58:52 kernel[0] <Notice>: duetexpertd[37309] Corpse allowed 1 of 5
Nov 18 17:58:52 backboardd(IOKit)[21224] <Notice>: Connection removed: IOHIDEventSystemConnection uuid:XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX pid:37309 process:duetexpertd type:Monitor entitlements:0x2 caller:AppPredictionInternal: <redacted> + 44 attributes:(null) state:0x1 events:14456 mask:0x1000 dropped:0 dropStatus:0 droppedMask:0x0 lastDroppedTime:NONE
...
```

**Inspect App. Bundle** (Persisted Data)

```
// Compiled code, statically linked files, compressed NIBs, et al.
$ cd /private/var/containers/Bundle/Application/<guid>/AppName.app
```

**Inspect Sandboxed Data** (Persisted Data)

```
// Contains sandbox dirs (Documents, Library, etc.) for an App
$ cd /private/var/mobile/Containers/Data/Application/
$ ls -lrt 				// List all apps., the one at the bottom are freshly installed
$ cd ./[appname-_guid]/Documents/
$ cd ./[appname-_guid]/Library/
```

**Inspect device databases**

```
$ cd /private/var/Keychains
# TrustStore.sqlite3
# keychain-x.db
# pinningrules.sqlite3
```

**Inspect binarycookies for an App.** (Persisted Data)

```
$ cat /private/var/mobile/Containers/Data/Application/[appname-_guid]/Library/Cookies/Cookies.binarycookies

// Pull from Device to Host OS tmp dir.
$ scp -P 2222 root@localhost:/private/var/mobile/Containers/Data/Application/[appname-_guid]/Library/Cookies/Cookies.binarycookies /tmp/cookies.bin

// Extract Cookie data
$ python BinaryCookieReader.py /tmp/cookies.bin
# Cookie : xxxxx=xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx; domain=.example.com; path=/; expires=Thu, 14 Dec 2030;
# ............
```

**Spoofing iOS Build Version**

```
// Note: only change minimum iOS version of a specific app's plist, not for the entire device.
$ ssh root@127.0.0.1 -p2222
root# cd /System/Library/CoreServices/
root# cat SystemVersion.plist
root# vi SystemVersion.plist
```

**Other possible analysis**

- Find all JSON and Plist files in app bundle and see if there are any disclosures
- `NSAllowsArbitraryLoads` - Disables App Transport Security (ATS), allowing weak TLS configs
- `CFBundleURLTypes` - Custom Scheme URLs that can be exploited further (see [this](https://github.com/ivRodriguezCA/RE-iOS-Apps/tree/master/Module-4#url-scheme-injection))
- `AFNetworking 2.5.1` - Version and below are vulnerable to MITM if there was no SSL pinning applied

