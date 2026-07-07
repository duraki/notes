---
title: "iOS Vulnerability Checklist"
---

**iOS Vulnerability Checklist**

- [ ] Hardcoded Sec-WebSocket-Key Header Value
- [ ] Crash from Previews of Malformed PDFs
- [ ] Potential Format String Vulnerabilities
- [ ] Message Nonce Used to Index Asset Cache
- [ ] Sensitive Data Disclosure in Property List
- [ ] Sensitive Data Disclosure in Application Bundle
- [ ] Sensitive Data Disclosure in Runtime Memory
- [ ] Missing Jailbreak Detection
- [ ] Sensitive Data in Logged [1](https://github.com/futurice/ios-good-practices?tab=readme-ov-file#logging)
- [ ] Insecure Cryptographic Interface Implementation [1](https://github.com/felixgr/secure-ios-app-dev?tab=readme-ov-file#api-generate-cryptographically-strong-random-numbers)
- [ ] Leaking of Sensitive Data while application is in background [1](https://github.com/felixgr/secure-ios-app-dev?tab=readme-ov-file#api-prevent-leaking-sensitive-data-during-app-backgrounding)
- [ ] Insecure Handling of Device Pasteboard [1](https://github.com/felixgr/secure-ios-app-dev?tab=readme-ov-file#api-handle-the-pasteboard-securely), [2](https://github.com/futurice/ios-good-practices?tab=readme-ov-file#user-interface)
- [ ] Keyboard Auto-correction on Sensitive Input Fields [1](https://github.com/felixgr/secure-ios-app-dev?tab=readme-ov-file#api-disable-auto-correction-for-sensitive-input-fields)
- [ ] Insecure Data Deserialization Handling [1](https://github.com/felixgr/secure-ios-app-dev?tab=readme-ov-file#handling-data-deserialize-data-securely)
- [ ] SQL Injection via Application-level SQLite implementation [1](https://github.com/felixgr/secure-ios-app-dev?tab=readme-ov-file#handling-data-avoid-sql-injection)
- [ ] Missing Exploit Mitigation Compile-flags [1](https://github.com/felixgr/secure-ios-app-dev?tab=readme-ov-file#hardening-enable-exploit-mitigation-compile-time-options), [2](https://github.com/nowsecure/secure-mobile-development/blob/master/en/ios/implement-protections-against-buffer-overflow-attacks.md)
  - [ ] Missing Objective-C Automatic Reference Counting (ARC) - `-fobjc-arc`
  - [ ] Missing Stack Smashing Protection (Stack Buffer Overflow) - `-fstack-protector-all`
  - [ ] Missing Full-ASLR Protection Implemented -  `-pie`
- [ ] Application support third-party keyboards [1](https://github.com/felixgr/secure-ios-app-dev?tab=readme-ov-file#hardening-check-that-support-for-third-party-keyboards-is-disabled)
- [ ] Missing SSL/TLS App Transport Security (ATS) Protection [1](https://github.com/felixgr/secure-ios-app-dev?tab=readme-ov-file#networking-configure-app-transport-security-ats), [2](https://github.com/felixgr/secure-ios-app-dev?tab=readme-ov-file#networking-use-native-tlsssl-securely), [3](https://github.com/futurice/ios-good-practices?tab=readme-ov-file#networking), [4](https://github.com/nowsecure/secure-mobile-development/blob/master/en/ios/implement-app-transport-security.md)
- [ ] Insecure incoming URI/URL Handler Calls [1](https://github.com/felixgr/secure-ios-app-dev?tab=readme-ov-file#io-validate-incoming-url-handler-calls)
- [ ] Incorrect handling of `UIWebView` URL Handlers [1](https://github.com/felixgr/secure-ios-app-dev?tab=readme-ov-file#io-validate-outgoing-requests-and-url-handlers), [2](https://github.com/felixgr/secure-ios-app-dev?tab=readme-ov-file#io-prevent-webview-ui-redressing)
- [ ] Cross-site Scripting (XSS) via insecure `UIWebView`/`WKWebView` [1](https://github.com/felixgr/secure-ios-app-dev?tab=readme-ov-file#io-avoid-xss-in-webviews)
- [ ] Cross-site Scripting (XSS) via Local HTML Preview in `UIWebView` [1](https://github.com/felixgr/secure-ios-app-dev?tab=readme-ov-file#io-avoid-local-html-preview-with-uiwebview)
- [ ] Null-byte Injection in `CF/NS` Strings [1](https://github.com/felixgr/secure-ios-app-dev?tab=readme-ov-file#memory-prevent-null-byte-injection)
- [ ] Format-string Injection Attacks [1](https://github.com/felixgr/secure-ios-app-dev?tab=readme-ov-file#memory-prevent-format-string-attacks)
- [ ] Identified Cached Snapshots of Application [1](https://github.com/nowsecure/secure-mobile-development/blob/master/en/ios/avoid-cached-application-snapshots.md)
- [ ] App. HTTPS Traffic is Inadvertly Cached [1](https://github.com/nowsecure/secure-mobile-development/blob/master/en/ios/avoid-caching-https-requests-responses.md)
- [ ] Biometric Bypass or Insecure TouchID Implementation [1](https://github.com/nowsecure/secure-mobile-development/blob/master/en/ios/implement-touch-id-properly.md)
- [ ] Missing Intended Use of App. Protected Data [1](https://github.com/nowsecure/secure-mobile-development/blob/master/en/ios/declare-protected-data.md)

**Storing Data on iOS:**

* [Keychain Services](https://developer.apple.com/library/ios/documentation/Security/Reference/keychainservices/)
  * Encrypted Key/Value Store
  * Design to store and holde:
    * Generic Passwords
    * Internet Passwords (*Password + Protocol + Server*)
    * Certificates
    * Private Keys
    * Identities (*Certificate + Private Key*)
  * Max raw value size is ~16MB
  * Keychain Items may be shared or set as app-specific (ie. *Private*)
    * Keychain Items can only be shared by apps from the same vendor
    * Enterprise Apps have a different Vendor ID
* [File System](https://developer.apple.com/library/ios/documentation/FileManagement/Conceptual/FileSystemProgrammingGuide/FileSystemOverview/FileSystemOverview.html#//apple_ref/doc/uid/TP40010672-CH2-SW12)
  * The app itself has access to its own app-specific filesystem sandbox, see Apple's [File System Programming Guide](https://developer.apple.com/library/ios/documentation/FileManagement/Conceptual/FileSystemProgrammingGuide/FileSystemOverview/FileSystemOverview.html#//apple_ref/doc/uid/TP40010672-CH2-SW12)
  * Sandbox Directory: `Documents/`
    * User-created Data taht should be visible to the user
    * Optionally visible to the user via iTunes
      * Subdirectories generally aren't visible, special tools are needed to open them
    * Backup of this sandbox directory is allowed
      * User can disable backup for specific apps
      * App can disable backup paths by setting [`NSURLIsExcludedFromBackupKey`](https://developer.apple.com/library/ios/documentation/FileManagement/Conceptual/FileSystemProgrammingGuide/FileSystemOverview/FileSystemOverview.html#//apple_ref/doc/uid/TP40010672-CH2-SW28)
  * Sandbox Directory: `Library/Caches/`
    * Semi-persistent Cached Files
    * Not visible to the user
    * Backup of this sandbox directory is not possible
    * Can be deleted by the OS at any time if the app is not running
      * The cleanup/deletion is managed automatically in response to storage pressure
  * Sandbox Directory: `Library/Application Support`
    * Persistent files necessary to run the app
    * Not visible to the user
    * Backup of this sandbox directory is allowed
      * User can disable backup for specific apps
      * App can disable backup paths by setting [`NSURLIsExcludedFromBackupKey`](https://developer.apple.com/library/ios/documentation/FileManagement/Conceptual/FileSystemProgrammingGuide/FileSystemOverview/FileSystemOverview.html#//apple_ref/doc/uid/TP40010672-CH2-SW28)
  * Sandbox Directory: `Library/Preferences/`
    * ie. *same as* `Library/Application Support`
    * By convention, only for files created with `NSUserDefaults`
  * Sandbox Directory: `Library/*`
    * ie. *same as* `Library/Application Support`
  * Sandbox Directory: `tmp/`
    * Non-persistent Cached files
    * Not visible to the user
    * Backup of this sandbox directory is not possible
    * Periodically deleted by the OS when the app is not running

{{< details "🗂️ Native OS Protection of App FS" >}}
The OS nativelly provides four levels of protection. Note that backups to iCloud are **always encrypted** and that backups in iTunes are **optionally encrypted**; unencrypted backups do not backup the data marked in any of the protected classes below. The device’s filesystem is encrypted on modern iOS on the DMA path; these options add extra layers of security.
{{</ details >}}
* `NSFileProtectionComplete` (ie. *the most secure option*)
  * Only readable if device is unlocked
  * File is closed when the device is locked
  * Suitable for most apps and data
* `NSFileProtectionCompleteUnlessOpen`
  * File can only be opened when the device is unlocked
  * File is not closed when the device is locked
  * File is encrypted when the last open handle is closed
  * Suitable for data that is uploaded in the background, etc
* `NSFileProtectionCompleteUntilFirstUserAuthentication` (ie. *default*)
  * File is inaccessible until the device is unlocked once after boot
  * Suitable for background processes that should start ASAP after boot
  * Geofence data
  * Bluetooth accessories (e.g. Android Wear)
  * In general, all user data should be handled *at least* on this level
* `NSFileProtectionNone` (ie. *least secure*)
* No native protection
* Suitable for certain applications that must access data immediately on boot without any user interaction
* The encryption/decryption is handled by the OS and the Keychain transparently 
* The relevant decryption key is created from the keychain when appropriate
* The relevant keychain key is erased from memory when appropriate (see [this](https://developer.apple.com/library/ios/documentation/iPhone/Conceptual/iPhoneOSProgrammingGuide/StrategiesforImplementingYourApp/StrategiesforImplementingYourApp.html#//apple_ref/doc/uid/TP40007072-CH5-SW21))

---

{{< details "🗂️ Best practices for App Storage: **Store Files Securely**" >}}
A stolen or lost iOS device can be potentially jailbroken or disassembled and the contents of the local file system can be read. Therefore iOS app developers need to make sure to encrypt sensitive information like credentials or other private information.
{{</ details >}}

Keychain already allows you to prevent items from ever leaving the device or be included in backups. In addition to that:

- Items can be made to require user consent when accessed;
- That consent can be set to Touch ID with the device password as fallback;
- Items can be made inaccessible if passcode is removed.

The safest scenario would require *flagging items* as device-only, requiring Touch ID for access, and invalidated if passcode is ever removed.

**Remember:** It possible to store any piece of text in Keychain, not just username and password credentials. Apple uses this to synchronize Wifi credentials between devices so that when you connect your laptop to a network, your phone will be able to as well a few seconds later when synchronization finishes, saving you from entering those long passwords on your phone. For more information on the details check out the Apple iOS Security white paper.

Check for stored data which is not using `kSecAttrAccessibleWhenUnlocked` or `kSecAttrAccessibleAfterFirstUnlock`. For example, if it is using `kSecAttrAccessibleAlways`, then the data is not sufficiently protected. Check for files created with `NSFileProtectionNone` - they have no protection. Note that files created without explicit protection do not necessarily use `NSFileProtectionNone`. Make sure one of the following is used:

* `NSFileProtectionComplete`
* `NSFileProtectionCompleteUnlessOpen` *(key stays in memory while locked and file opened)*
* `NSFileProtectionCompleteUntilFirstUserAuthentication` *(key stays in memory when locked)*

{{< details "🗂️ Best practices for App Storage: **Use Secure Temporary Files**" >}}
Check that secure temporary files and directories are used - for example: `URLForDirectory`, `NSTemporaryDirectory`, `FSFindFolder(kTemporaryFolderType)`. See also [Create Temporary Files Correctly](https://developer.apple.com/library/mac/documentation/Security/Conceptual/SecureCodingGuide/Articles/RaceConditions.html#//apple_ref/doc/uid/TP40002585-SW10) in the Apple Secure Coding Guide.
{{</ details >}}

{{< details "🗂️ Best practices for App Storage: **Avoid Insecure Destination/API**" >}}
Check for Private Information (PII) in `NSLog`/`Alog`, `plist` or local `sqlite` databases. It may not be encrypted. Logging is encrypted as of `iOS>10`. Check that only appropriate *user-specific* non-sensitive information is written to iCloud storage. Use` NSURLIsExcludedFromBackupKey` to prevent backup of specific files to iCloud and iTunes. For the Keychain, check that `kSecAttrSynchronizable` is `false` if the item is not intended for iCloud Keychain Backup (it is `false` by default). Make sure that [`NSUserDefaults`](https://developer.apple.com/library/mac/documentation/Cocoa/Reference/Foundation/Classes/NSUserDefaults_Class/) only contains Settings and **no** personal information.
{{</ details >}}

**Where should app store Data**: [1](https://github.com/felixgr/secure-ios-app-dev?tab=readme-ov-file#where-should-i-store-my-data), [2](https://github.com/futurice/ios-good-practices?tab=readme-ov-file#data-storage)

* **Sensitive and Persistent Data** (ie. *credentials*, *tokens*, ...)
  * Keychain
* **Large sensitive and persistent files**
  * Usually in the `Library/*` directory
  * Should be flagged as "*excluded*" from the backups
  * Keychain backups have a higher level of security than Filesystem backups
  * Set appropriate encryption options, ie. *as secure as possible*
* **Sensitive Cache Data**
  * Usually in the `Library/Caches/*` directory
  * Set appropriate encryption options, ie. *as secure as possible*
* **Application Settings/Configuration**
  * For `NSUserDefaults` use `Library/Preferences/[Name].plist`
  * For other/custom formats use `Library/Application Support/*`
  * Set appropriate encryption options, ie. *as secure as possible*
* **Persistent Content With Backup**
  * For data that should be visible to the user
    * Usually in the `Documents/*` directory (iTunes will ignore subdirectories)
    * Usually with the `NSFileProtectionCompleteUntilFirstUserAuthentication` flag for encryption (if required)
  * For data that should't be visible to the user
    * Usually in the `Library/Application Support/*` directory
    * Usually with the appropriate encryption flag

---

The above checklists are collected from various sources including (but not limited to):

* [X41 D-Sec "Wire Security Review - iOS Client for Wire Swiss GmbH"](https://www.x41-dsec.de/static/reports/X41-Kudelski-Wire-Security-Review-iOS.pdf)
* [Felix's "Secure iOS App. Development"](https://github.com/felixgr/secure-ios-app-dev)
* [Futureice's iOS App. Development Best Practices](https://github.com/futurice/ios-good-practices)
* [Apple's iOS Security Guide](https://www.apple.com/business/docs/iOS_Security_Guide.pdf)
* [Mobile App Pentesting Cheatsheet](https://github.com/tanprathan/MobileApp-Pentest-Cheatsheet)
* [NowSecure Secure Mobile Development](https://github.com/nowsecure/secure-mobile-development/blob/master/en/ios/README.md)
* [OWASP's Mobile Security Testing Guide](https://github.com/OWASP/owasp-mastg)