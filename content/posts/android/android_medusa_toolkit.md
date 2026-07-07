---
title: "Using Medusa on Android"
url: "using-medusa-android"
---

Check [Medusa](/medusa) note for general information about this framework and how to install it for your system. This note provides detail usage for [Android Reverse Engineering](/android-reverse-engineering) alongside relevant details. [Stheno](/stheno) is a subproject of Medusa, specifically designed for intent monitoring within this framework.

Reference to [Stheno](/stheno) quick guide, on how to set up and use [Stheno](https://github.com/Ch0pin/stheno) effectively.

**Unpacking Android App. with Medusa**

Install the APK to [emulated Android device](/running-android-apps-on-macos) using `adb`:

```
$ adb install AppName.apk
# Performing Streamed Install
# Success
```

Start [medusa](/medusa) REPL via Terminal:

```
(medusa-venv) $ python3 medusa.py
[2025-02-04 04:22:43,102 - INFO] -  Loading modules...
[2025-02-04 04:22:43,107 - INFO] -  Total modules available 120
[2025-02-04 04:22:43,107 - INFO] -  All one....

    ███╗   ███╗███████╗██████╗ ██╗   ██╗███████╗ █████╗
    ████╗ ████║██╔════╝██╔══██╗██║   ██║██╔════╝██╔══██╗
    ██╔████╔██║█████╗  ██║  ██║██║   ██║███████╗███████║
    ██║╚██╔╝██║██╔══╝  ██║  ██║██║   ██║╚════██║██╔══██║
    ██║ ╚═╝ ██║███████╗██████╔╝╚██████╔╝███████║██║  ██║
    ╚═╝     ╚═╝╚══════╝╚═════╝  ╚═════╝ ╚══════╝╚═╝  ╚═╝ (Android) Version: dev

[2025-02-04 04:22:43,107 - INFO] -  Available devices:

x) ...
3) Device(id="127.0.0.1:26624", name="GKWS6", type='usb')

Enter the index of the device to use: 3

Device properties:

# [...]
# [ro.<flags>.details]

- 3rd party installed applications:

[2] com.example.appname
[x] ...

(127.0.0.1:26624) medusa➤search http
# ...
# http_communications/uri_logger
# http_communications/okhttp3_retrofit
# http_communications/...

(127.0.0.1:26624) medusa➤use http_communications/uri_logger
# 
# Current Mods:
#   0) http_communications/uri_logger

(127.0.0.1:26624) medusa➤search dump
# ...
# memory_dump/dump_dyndex

(127.0.0.1:26624) medusa➤use memory_dump/dump_dyndex
# 
# Current Mods:
#   0) http_communications/uri_logger
#   1) memory_dump/dump_dyndex

(127.0.0.1:26624) medusa➤search encryp
# ...
# encryption/cipher_1

(127.0.0.1:26624) medusa➤use encryption/cipher_1
# 
# Current Mods:
#   0) http_communications/uri_logger
#   1) memory_dump/dump_dyndex
#   3) encryption/cipher_1

(127.0.0.1:26624) medusa➤compile
# Script is compiled

(127.0.0.1:26624) medusa➤list
# Installed packages:
#   [2] com.example.appname

(127.0.0.1:26624) medusa➤run -n 2
# Spawned package: com.example.appname on pid XXXX
# ...
```

See this [Youtube Video](https://www.youtube.com/watch?v=ffM5R2Wfl0A) for detailed instructions.

**Using Mango REPL - a Medusa companion**

The [medusa](/medusa) contains a `mango` which is a companion utility used to extract and anlyze components of Android Application. The results are stored to SQLite database, which can be reloaded and updated with new samples. Additionally, [mango](https://github.com/Ch0pin/medusa/wiki#mango-quick-start) automates various other tasks, like changing proxy settings on the device, forcing start/stop of the services, (re)installing of the application, taking screenshot and more. Mango can be started via Terminal:

```
(medusa-venv) $ python3 mango.py

  Welcome to

    888b     d888
    8888b   d8888
    88888b.d88888
    888Y88888P888  8888b.  88888b.   .d88b.   .d88b.
    888 Y888P 888     "88b 888 "88b d88P"88b d88""88b
    888  Y8P  888 .d888888 888  888 888  888 888  888
    888   "   888 888  888 888  888 Y88b 888 Y88..88P
    888       888 "Y888888 888  888  "Y88888  "Y88P"
                                        888
                                    Y8b d88P
                                    "Y88P"
--------------------------------------------------
[?] What do you want to do?
--------------------------------------------------
1. Start a new session
2. Continue an existing session
3. Exit
```

Lets start by creating a new session file without any arguments by entering "1" in the REPL:

```
#   ...
[?] Enter your selection: 1
[?] Enter a session name: ExmplSession1

# [2025-02-04 04:46:37,444 - INFO] -  Available devices:
# ...
3) Device(id="127.0.0.1:26624", name="GKWS6", type='usb')

Enter the index of the device you want to use: 3

# Device properties:
# [ro.xxxxx.xxxx]: [xxxxxx]
# [...]: [....]

(127.0.0.1:26624) mango➤
```

Now that we have initiated a Mango session, we can use its' REPL:

```
(127.0.0.1:26624) mango➤pull com.example.appname # pull an apk from device 
# [2025-02-04 05:10:23,195 - INFO] -  /data/app/~~gTA5KqsXh_r0N6dPChjSvQ==/com.example.appname-ubCP5TlZDeHLQau7hWmaJA==/base.apk retrieved successfully !
# Do you want to import the application? (Y/n) [Enter] (n)

(127.0.0.1:26624) mango➤import base.apk          # load and analyze apk
#   OR mango>(...):
#       # import /full/path/to/app.apk           # load and analyze apk from HostOS
#       # load <package_name>                    # reload an APK that has been analyzed
#
# [2025-02-04 05:10:37,266 - INFO] -  [+] Analyzing apk with SHA256:d160fc310608b31738478b48743033575cd53bc8909a73ebb9029a15bf06ab71
# [2025-02-04 05:10:37,306 - INFO] -  [+] Analysis finished.
# [2025-02-04 05:10:37,306 - INFO] -  [+] Filling up the database....
# [2025-02-04 05:10:37,368 - INFO] -  Extracting secrets in the background: base.apk (sha256: d160fc310608b31738478b48743033575cd53bc8909a73ebb9029a15bf06ab71)
# [2025-02-04 05:10:37,384 - INFO] -  [+] Database Ready !
# 
# [------------------------------------Package Details---------------------------------------]:
# |    Original Filename :base.apk
# |    Application Name  :App Name
# |    Package Name      :com.example.appname
# |    ....
# |    Dev. Framework    :React Native
# [------------------------------------------------------------------------------------------]

(127.0.0.1:26624) mango➤show activities            # show all activities
# com.example.appname.MainActivity | exported = true (intent filter)
# com.proyecto26.inappbrowser.ChromeTabsManagerActivity | exported = false
# net.openid.appauth.AuthorizationManagementActivity | exported = false
# net.openid.appauth.RedirectUriReceiverActivity | exported = true (intent filter)
# com.google.android.gms.common.api.GoogleApiActivity | exported = false

(127.0.0.1:26624) mango➤show deeplinks             # show registered deeplinks
----------------------------------------------
# Deeplinks that start:net.openid.appauth.RedirectUriReceiverActivity
# com.example.appname.auth://

(127.0.0.1:26624) mango➤show activities -e         # show exported activities
# com.example.appname.MainActivity | exported = true (intent filter)
# net.openid.appauth.RedirectUriReceiverActivity | exported = true (intent filter)
```

**Working with Application Components:** You can view an application's components (activities, services etc.) by using the `show` command followed by the component type, for example:

```
mango> show <type>
mango> show [activities|activityAlias|services|receivers|providers|permissions|deeplinks|intentFilters]
mango> show activities
```

Using the `-e` argument, the output will contain only the exported components (when applicable), for example:

```
mango> show activities -e   # show only exported activities
```

Further, the `show` command supports the following additional options:

* `exposure`: Prints the application 'attack surface', including deeplinks, exported activities, activity aliases, services, receivers and providers
* `info`: Prints handy information about the loaded application
* `strings`: Prints the application's string resources
* `database`: Prints the structure of the database file. The output can be used to construct raw SQL queries (*see: `query` command*)
* `applications`: This option can be used to load a different application or manage the existing applications

**Interacting with Application:** You can force the currently loaded application to start an activity by typing `start` followed by `[TAB]` or the full name of an activity:

```
(127.0.0.1:26656) mango➤start
# com.google.android.gms.common.api.GoogleApiActivity      com.example.appname.MainActivity
# com.proyecto26.inappbrowser.ChromeTabsManagerActivity

(127.0.0.1:26656) mango➤com.example.appname.MainActivity
```

Similarly, you can force the application to start a service by typing `startsrv` followed by `[TAB]` or the full name of a service:

```
(127.0.0.1:26656) mango➤startsrv com.example.appname.serviceExample
(127.0.0.1:26656) mango➤stopsrv com.example.appname.serviceExample
```

To trigger a deeplink, type `deeplink` followed by `[TAB]` or the full URI of the deeplink:

```
(127.0.0.1:26656) mango➤deeplink example://mywebview
```

Additionally, you can kill or start an application by typing `kill` or `spawn` respectively followed by the application's name:

```
(127.0.0.1:26656) mango➤spawn com.example.appname
```

**Interacting with the Device:** You can interact with the device using the commands explained below.

To (un)install an application use `install` command followed by the path of the APK:

```
(127.0.0.1:26656) mango➤install /full/path/to/app.apk      # install
(127.0.0.1:26656) mango➤uninstall com.example.appname      # uninstall [package name]
```

To install a Burp Suite certificate, type `installBurpCert` and follow the steps provided by `mango` REPL:

```
(127.0.0.1:26656) mango➤installBurpCert
# ...
```

To modify device's proxy settings, use the `proxy` command followed by one of its' options:

```
(127.0.0.1:26656) mango➤proxy get                # print current proxy config
(127.0.0.1:26656) mango➤proxy set [ip:port]      # set a fixed proxy config
(127.0.0.1:26656) mango➤proxy set -t [ip:port]   # set a transparent proxy config
(127.0.0.1:26656) mango➤proxy reset              # clear device's proxy
```

To start an interactive `adb` session, use `adb` command:

```
(127.0.0.1:26656) mango➤adb
# ...
```

To get a package-*specific* logcat, type `logcat [package name]`. Alternatively, use `nlog` for device's native logs and `jlog` for Java crash logs:

```
(127.0.0.1:26656) mango➤logcat com.example.appname     # get app/pkgs logs
(127.0.0.1:26656) mango➤nlog                           # get devices native logs
(127.0.0.1:26656) mango➤jlog                           # get Java crash logs
```

To get a screenshot of the device, use `screencap` command:

```
(127.0.0.1:26656) mango➤screencap -o /tmp/screenshot.png
# screenshot will be saved in /tmp/screenshot.png
```

To run a shell command on the connected device, use `cc`:

```
(127.0.0.1:26656) mango➤cc whoami
# root
```

To send a notification on connected device, use `notify` command. This command requires installation of medusa agent on the device:

```
(127.0.0.1:26656) mango➤installagent
# ... medus agent installed
# ...
(127.0.0.1:26656) mango➤notify [notification_title] [notification_body]
```

**Patching an APK:** You can use `mongo` utility to patch an APK and set desired flags.

Set debuggable flag to TRUE of a given APK file (requires `zipalign` and `apksigner` on HostOS):

```
(127.0.0.1:26656) mango➤patch /full/path/to/app.apk
```

Dynamically debug an app. using the `jdwp` command:

```
(127.0.0.1:26656) mango➤jdwp [package name]
```

Start a `frida-trace` session using the `trace` command and one of corresponding options:

```
(127.0.0.1:26656) mango➤trace -j com.example.appname       # trace all functions of the 'com.example.appname.*' class
(127.0.0.1:26656) mango➤trace -n name*                     # trace of a native function matching 'name*'
(127.0.0.1:26656) mango➤trace -a libexample.so             # trace all the functions of a native library 'libexample.so'
```
