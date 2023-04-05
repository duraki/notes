---
title: "MacOS RE Companion App"
---

Create a MacOS Reverse Engineering Platform/Framework that will quickly do a static and dynamic analysis of the targeted MachO.

---

Explore Apple Docs: `NSUserDefaults`, `NSCoding`, `Codable`,

---

What it should do:
- Detect security issues, information disclosure, analyse binary
    - Use: [extrude](https://github.com/liamg/extrude)
- Detect all Binary and Property list resources of the $TARGET
    - Use: [BinaryCodeable](https://github.com/jverkoey/BinaryCodable), [BinaryCookies](https://github.com/interstateone/BinaryCookies), [BinaryKit](https://github.com/Cosmo/BinaryKit), [EasyMapping](https://github.com/lucasmedeirosleite/EasyMapping)
- Detect all $TARGET metadata, such is *App. Bundle Preferences*, *Imported DYLIB*, *Extract Binary Functions*
    - Use: [MSFoundation](https://github.com/mattstevens/MSFoundation), [CXFoundation](https://github.com/cx-org/CombineX/tree/master/Sources/CXFoundation), NSBundle/NSData, [NNKit](https://github.com/numist/NNKit), [JSONExport](https://github.com/Ahmed-Ali/JSONExport) ...
- Detect all FileSystem events from in and out of the $TARGET thread
    - Use: [fswatch](/macOS-filesystem-monitoring), [FileMonitor](https://github.com/objective-see/FileMonitor) [Pathos](https://github.com/dduan/Pathos), [filewatcher](https://github.com/santoru/filewatcher), [frangipanni](https://github.com/birchb1024/frangipanni)
- Describe and Rebuild MachO Binary Details
    - Use: [quill](https://github.com/anchore/quill), [ProcInfo](https://github.com/objective-see/ProcInfo)
- Trace Application, XPC, System, and MachO calls dynamically
    - Use: [SwiftInMemoryLoading](https://github.com/slyd0g/SwiftInMemoryLoading), [XPCSniffer](https://github.com/evilpenguin/XPCSniffer)
- Trace HTTP/S, TCP/UDP and alternative network comm. calls
    - Use: [harlogger](https://github.com/doronz88/harlogger), [NetworkSniffer](https://github.com/evilpenguin/NetworkSniffer)
