---
title: WindowsNT Reverse Engineering
---

**Analyze APIs in binary and extract Function calls**

Read, build and install the [pharos/callanalyzer](https://github.com/cmu-sei/pharos/blob/master/tools/callanalyzer/callanalyzer.pod) utility. This CLI application analyzes function call points in binaries, attempting to determine their argument values.

```
$ ./bin/callanalyzer --help
# => Show manpage for the Call Analyzer

$ ./bin/callanalyzer --show-symbolic --allow-unknown /examples/binary.exe
OPTI[INFO ]: Call: WaitForSingleObject (0x00401047)
OPTI[INFO ]:   Param: hHandle Value: {(HANDLE)0xffffffff -> {(void)<unknown>}}
OPTI[INFO ]:   Param: dwMilliseconds Value: {(DWORD)4294967295}
# ...
```

**Search for patterns of API in binary**

The [pharos/apianalyzer](https://github.com/cmu-sei/pharos/blob/master/tools/apianalyzer/apianalyzer.pod) utility can be used to search and extract Microsoft Windows API function calls within targeted binary.

Usage:

```
$ ./bin/apianalyzer --help
# => Display API Analyzer's Manpage

$ ./bin/apianalyzer /examples/binary.exe
OPTI[INFO ]: Analyzing executable: ../examples/binary.exe
# Category: INFORMATIONAL
# Found: TerminateSelf starting at address 0x00401C0C
# Category: MALWARE
# ...
# Category: PROCESS_MANIPULATION
# Found: SpawnProcess starting at address 0x004010EC
```

**Reference to Windows API Documentation**

Quickly reference to Microsoft Windows API using [pharos/apilookup](https://github.com/cmu-sei/pharos/blob/master/tools/apilookup/apilookup.pod) utility that is bundled with the main framework.

```
$ ./bin/apilookup --help
# => Display API database Manpage

$ ./bin/apilookup kernel32:ReadFile
Lookup: kernel32:ReadFile
  Definition found
    Name: ReadFile
# ...
```
