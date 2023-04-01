---
title: MacOS Application Preferences
---

* Also See: [Hooking MacOS Preferences changes](/hook-macos-preferences).

The macOS `.plist` or Property List is a Apple's propriatery binary format that contains application's information, build version, additional resources and assets as well as all other metadata that may be useable for app. lifecycle or usage.

**To print `*plist` files**, use `plutil` with `FILE`:

```
$ plutil /path/to/file.plist            # This will output data from FILE
```

**To convert `*plist` files**, use `plistuitl` from CLI:

```
$ plistutil -i /path/to/file.plist -o /tmp/converted.xml -f [FORMAT]
        # where FORMAT:
        #       [bin|xml|json|openstep]
```

CLI utility `plutil` is a tool used to read `plist` – or *property list format*. Property lists organize data into named values and lists of values using several Core Foundation types: CFString, CFNumber, CFBoolean, CFDate, CFData, CFArray, and CFDictionary.

See: `man plutil`, `man plist` & `man plistuitl`.
