---
title: "Scan APK for Secrets"
url: "/apk-secrets"
---

**Using `apkleaks` to scan APK for secrets**

The [apkleaks](https://github.com/dwisiswant0/apkleaks) utility can be used to scan APK for URIs/Endpoints/Secrets that are hardcoded or bundled with the APK.

To install it, clone the repository and prepare Python virtual environment:

```
$ git clone git@github.com:dwisiswant0/apkleaks.git --depth=1
$ cd apkleaks
$ python3 -m venv path/to/venv
$ source path/to/venv/bin/activate
$ python3 -m pip install -r requirements.txt
# ...
```

To scan an APK with `apkleaks`, provide the path to APK file:

```
$ python3 apkleaks.py -f TestedApp.apk
     _    ____  _  ___               _
    / \  |  _ \| |/ / |    ___  __ _| | _____
   / _ \ | |_) | ' /| |   / _ \/ _` | |/ / __|
  / ___ \|  __/| . \| |__|  __/ (_| |   <\__ \
 /_/   \_\_|   |_|\_\_____\___|\__,_|_|\_\___/
 v2.6.3
 --
 Scanning APK file for URIs, endpoints & secrets
 (c) 2020-2024, dwisiswant0

** Decompiling APK...
INFO  - loading ...
INFO  - processing ...
ERROR - finished with errors, count: 12

** Scanning against 'com.example.AppName'

[Google_API_Key]
# ...

[IP_Address]
# ...

[JSON_Web_Token]
# ...

[LinkFinder]
# ...
```

**Using `apkhunt` for static code analysis on Android apps**

The [apkhunt](https://github.com/Cyber-Buddy/APKHunt) utility is a comprehensive static code analysis tool for Android apps, based on [OWASP MASVS](https://mobile-security.gitbook.io/masvs/). This tool requires you to have Linux as the HostOS - systems like Microsoft Windows and MacOS are not supported. The `apkhunt` can be installed and used in a virtualized Linux environment.

Clone the repository and use it via `go run` command:

```
$ git clone https://github.com/Cyber-Buddy/APKHunt.git
$ cd APKHunt
$ go run apkhunt.go --help
```

