---
title: Schemes.app
---

The application [Schemes](https://github.com/oliverepper/Schemes) (*requires manual compilation*) is a small MacOS UI app. that lists all the schemes and their handlers that are registered via Launch Services.

{{< imgcap title="Searching and showing Scheme in the app." src="https://oliver-epper.de/images/Schemes-dark.png" >}}

The application, after compiling in XCode creates `Schemes.app` app. bundle and additional XPC service `UnregisterSchemeHandler.xpc` that basically calls:

```
# => Show available help and commands for the 'lsregister'
$ /System/Library/Frameworks/CoreServices.framework/Versions/A/Frameworks/LaunchServices.framework/Versions/A/Support/lsregister -h
lsregister: [OPTIONS] [ <path>... ]
                      [ -apps <domain>[,domain]... ]
                      [ -libs <domain>[,domain]... ]
                      [ -all  <domain>[,domain]... ]

Paths are searched for applications to register with the Launch Service database.
# ...

  -delete       Delete the Launch Services database file. You must then reboot!
  - ...

# => Unregister Entry for the App.
$ /System/Library/Frameworks/CoreServices.framework/Versions/A/Frameworks/LaunchServices.framework/Versions/A/Support/lsregister -u /APplications/Example.app
```
