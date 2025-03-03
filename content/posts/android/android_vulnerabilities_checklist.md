---
title: "Android Vulnerability Checklist"
---

Official Google Android-related Security Checklist are present on [`developer.android.com`](https://developer.android.com/privacy-and-security/risks) website, click on "Guides" tab in the sidebar, and then click " Understand common security risks" menu.

**Android Vulnerability Checklist**

- [ ] Runtime Use of Logging APIs ([MASTG-TEST-0203](https://mas.owasp.org/MASTG/tests-beta/android/MASVS-STORAGE/MASTG-TEST-0203/))
- [ ] Data Stored in the App Sandbox at Runtime ([MASTG-TEST-0207](https://mas.owasp.org/MASTG/tests-beta/android/MASVS-STORAGE/MASTG-TEST-0207/))
- [ ] Files Written to External Storage ([MASTG-TEST-0200](https://mas.owasp.org/MASTG/tests-beta/android/MASVS-STORAGE/MASTG-TEST-0200/))
- [ ] Sensitive Data Not Excluded From Backup ([MASTG-TEST-0216](https://mas.owasp.org/MASTG/tests-beta/android/MASVS-STORAGE/MASTG-TEST-0216/))
- [ ] References to APIs and Permissions for Accessing External Storage ([MASTG-TEST-0202](https://mas.owasp.org/MASTG/tests-beta/android/MASVS-STORAGE/MASTG-TEST-0202/))
- [ ] Runtime Use of APIs to Access External Storage ([MASTG-TEST-0201](https://mas.owasp.org/MASTG/tests-beta/android/MASVS-STORAGE/MASTG-TEST-0201/))
- [ ] References to Logging APIs ([MASTG-TEST-0231](https://mas.owasp.org/MASTG/tests-beta/android/MASVS-STORAGE/MASTG-TEST-0231/))
- [ ] Usage of Insecure Signature Version ([MASTG-TEST-0224](https://mas.owasp.org/MASTG/tests-beta/android/MASVS-RESILIENCE/MASTG-TEST-0224/))
- [ ] Debugging Enabled for WebViews ([MASTG-TEST-0227](https://mas.owasp.org/MASTG/tests-beta/android/MASVS-RESILIENCE/MASTG-TEST-0227/))
- [ ] Debuggable Flag Enabled in the AndroidManifest ([MASTG-TEST-0226](https://mas.owasp.org/MASTG/tests-beta/android/MASVS-RESILIENCE/MASTG-TEST-0226/))
- [ ] Usage of Insecure Signature Key Size ([MASTG-TEST-0225](https://mas.owasp.org/MASTG/tests-beta/android/MASVS-RESILIENCE/MASTG-TEST-0225/))
- [ ] Non-random Sources Usage ([MASTG-TEST-0205](https://mas.owasp.org/MASTG/tests-beta/android/MASVS-CRYPTO/MASTG-TEST-0205/))
- [ ] Use of Hardcoded Cryptographic Keys in Code ([MASTG-TEST-0212](https://mas.owasp.org/MASTG/tests-beta/android/MASVS-CRYPTO/MASTG-TEST-0212/))
- [ ] Insecure Random API Usage ([MASTG-TEST-0204](https://mas.owasp.org/MASTG/tests-beta/android/MASVS-CRYPTO/MASTG-TEST-0204/))
- [ ] Weak Symmetric Encryption Modes ([MASTG-TEST-0232](https://mas.owasp.org/MASTG/tests-beta/android/MASVS-CRYPTO/MASTG-TEST-0232/))
- [ ] Inappropriate Key Sizes ([MASTG-TEST-0208](https://mas.owasp.org/MASTG/tests-beta/android/MASVS-CRYPTO/MASTG-TEST-0208/))
- [ ] Weak Symmetric Encryption Algorithms ([MASTG-TEST-0221](https://mas.owasp.org/MASTG/tests-beta/android/MASVS-CRYPTO/MASTG-TEST-0221/))
- [ ] Cross-Platform Framework Configurations Allowing Cleartext Traffic ([MASTG-TEST-0237](https://mas.owasp.org/MASTG/tests-beta/android/MASVS-NETWORK/MASTG-TEST-0237/))
- [ ] Using low-level APIs (e.g. Socket) to set up a custom HTTP connection ([MASTG-TEST-0239](https://mas.owasp.org/MASTG/tests-beta/android/MASVS-NETWORK/MASTG-TEST-0239/))
- [ ] Android App Configurations Allowing Cleartext Traffic ([MASTG-TEST-0235](https://mas.owasp.org/MASTG/tests-beta/android/MASVS-NETWORK/MASTG-TEST-0235/))
- [ ] Insecure TLS Protocols Explicitly Allowed in Code ([MASTG-TEST-0217](https://mas.owasp.org/MASTG/tests-beta/android/MASVS-NETWORK/MASTG-TEST-0217/))
- [ ] SSLSockets not Properly Verifying Hostnames ([MASTG-TEST-0234](https://mas.owasp.org/MASTG/tests-beta/android/MASVS-NETWORK/MASTG-TEST-0234/))
- [ ] Hardcoded HTTP URLs ([MASTG-TEST-0233](https://mas.owasp.org/MASTG/tests-beta/android/MASVS-NETWORK/MASTG-TEST-0233/))
- [ ] Runtime Use of Network APIs Transmitting Cleartext Traffic ([MASTG-TEST-0238](https://mas.owasp.org/MASTG/tests-beta/android/MASVS-NETWORK/MASTG-TEST-0238/))
- [ ] Sensitive Data in Network Traffic Capture ([MASTG-TEST-0206](https://mas.owasp.org/MASTG/tests-beta/android/MASVS-PRIVACY/MASTG-TEST-0206/))
- [ ] Stack Canaries Not Enabled ([MASTG-TEST-0223](https://mas.owasp.org/MASTG/tests-beta/android/MASVS-CODE/MASTG-TEST-0223/))
- [ ] Testing Logs for Sensitive Data ([MASTG-TEST-0003](https://mas.owasp.org/MASTG/tests/android/MASVS-STORAGE/MASTG-TEST-0003/))
- [ ] Testing Backups for Sensitive Data ([MASTG-TEST-0009](https://mas.owasp.org/MASTG/tests/android/MASVS-STORAGE/MASTG-TEST-0009/))
- [ ] Determining Whether Sensitive Data Is Shared with Third Parties via Notifications ([MASTG-TEST-0005](https://mas.owasp.org/MASTG/tests/android/MASVS-STORAGE/MASTG-TEST-0005/))
- [ ] Testing Memory for Sensitive Data ([MASTG-TEST-0011](https://mas.owasp.org/MASTG/tests/android/MASVS-STORAGE/MASTG-TEST-0011/))
- [ ] Testing the Device-Access-Security Policy ([MASTG-TEST-0012](https://mas.owasp.org/MASTG/tests/android/MASVS-STORAGE/MASTG-TEST-0012/))
- [ ] Determining Whether Sensitive Data Is Shared with Third Parties via Embedded Services ([MASTG-TEST-0004](https://mas.owasp.org/MASTG/tests/android/MASVS-STORAGE/MASTG-TEST-0004/))
- [ ] Testing Local Storage for Sensitive Data ([MASTG-TEST-0001](https://mas.owasp.org/MASTG/tests/android/MASVS-STORAGE/MASTG-TEST-0001/))
- [ ] Determining Whether the Keyboard Cache Is Disabled for Text Input Fields ([MASTG-TEST-0006](https://mas.owasp.org/MASTG/tests/android/MASVS-STORAGE/MASTG-TEST-0006/))
- [ ] Testing Emulator Detection ([MASTG-TEST-0049](https://mas.owasp.org/MASTG/tests/android/MASVS-RESILIENCE/MASTG-TEST-0049/))
- [ ] Testing File Integrity Checks ([MASTG-TEST-0047](https://mas.owasp.org/MASTG/tests/android/MASVS-RESILIENCE/MASTG-TEST-0047/))
- [ ] Testing Anti-Debugging Detection ([MASTG-TEST-0222](https://mas.owasp.org/MASTG/tests/android/MASVS-RESILIENCE/MASTG-TEST-0046/))
- [ ] Testing Root Detection ([MASTG-TEST-0045](https://mas.owasp.org/MASTG/tests/android/MASVS-RESILIENCE/MASTG-TEST-0045/))
- [ ] Testing Reverse Engineering Tools Detection ([MASTG-TEST-0048](https://mas.owasp.org/MASTG/tests/android/MASVS-RESILIENCE/MASTG-TEST-0048/))
- [ ] Testing for Debugging Symbols ([MASTG-TEST-0040](https://mas.owasp.org/MASTG/tests/android/MASVS-RESILIENCE/MASTG-TEST-0040/))
- [ ] Testing whether the App is Debuggable ([MASTG-TEST-0039](https://mas.owasp.org/MASTG/tests/android/MASVS-RESILIENCE/MASTG-TEST-0039/))
- [ ] Testing Runtime Integrity Checks ([MASTG-TEST-0050](https://mas.owasp.org/MASTG/tests/android/MASVS-RESILIENCE/MASTG-TEST-0050/))
- [ ] Making Sure that the App is Properly Signed ([MASTG-TEST-0038](https://mas.owasp.org/MASTG/tests/android/MASVS-RESILIENCE/MASTG-TEST-0038/))
- [ ] Testing Obfuscation ([MASTG-TEST-0051](https://mas.owasp.org/MASTG/tests/android/MASVS-RESILIENCE/MASTG-TEST-0051/))
- [ ] Testing for Debugging Code and Verbose Error Logging ([MASTG-TEST-0041](https://mas.owasp.org/MASTG/tests/android/MASVS-RESILIENCE/MASTG-TEST-0041/))
- [ ] Testing for Java Objects Exposed Through WebViews ([MASTG-TEST-0033](https://mas.owasp.org/MASTG/tests/android/MASVS-PLATFORM/MASTG-TEST-0033/))
- [ ] Determining Whether Sensitive Stored Data Has Been Exposed via IPC Mechanisms ([MASTG-TEST-0007](https://mas.owasp.org/MASTG/tests/android/MASVS-PLATFORM/MASTG-TEST-0007/))
- [ ] Checking for Sensitive Data Disclosure Through the User Interface ([MASTG-TEST-0008](https://mas.owasp.org/MASTG/tests/android/MASVS-PLATFORM/MASTG-TEST-0008/))
- [ ] Finding Sensitive Information in Auto-Generated Screenshots ([MASTG-TEST-0010](https://mas.owasp.org/MASTG/tests/android/MASVS-PLATFORM/MASTG-TEST-0010/))
- [ ] Testing WebView Protocol Handlers ([MASTG-TEST-0032](https://mas.owasp.org/MASTG/tests/android/MASVS-PLATFORM/MASTG-TEST-0032/))
- [ ] Testing for Overlay Attacks ([MASTG-TEST-0035](https://mas.owasp.org/MASTG/tests/android/MASVS-PLATFORM/MASTG-TEST-0035/))
- [ ] Testing for Vulnerable Implementation of PendingIntent ([MASTG-TEST-0030](https://mas.owasp.org/MASTG/tests/android/MASVS-PLATFORM/MASTG-TEST-0030/))
- [ ] Testing for Sensitive Functionality Exposure Through IPC ([MASTG-TEST-0029](https://mas.owasp.org/MASTG/tests/android/MASVS-PLATFORM/MASTG-TEST-0029/))
- [ ] Testing for App Permissions ([MASTG-TEST-0024](https://mas.owasp.org/MASTG/tests/android/MASVS-PLATFORM/MASTG-TEST-0024/))
- [ ] Testing WebViews Cleanup ([MASTG-TEST-0037](https://mas.owasp.org/MASTG/tests/android/MASVS-PLATFORM/MASTG-TEST-0037/))
- [ ] Testing Deep Links ([MASTG-TEST-0028](https://mas.owasp.org/MASTG/tests/android/MASVS-PLATFORM/MASTG-TEST-0028/))
- [ ] Testing JavaScript Execution in WebViews ([MASTG-TEST-0031](https://mas.owasp.org/MASTG/tests/android/MASVS-PLATFORM/MASTG-TEST-0031/))
- [ ] Testing Biometric Authentication ([MASTG-TEST-0018](https://mas.owasp.org/MASTG/tests/android/MASVS-AUTH/MASTG-TEST-0018/))
- [ ] Testing Confirm Credentials ([MASTG-TEST-0017](https://mas.owasp.org/MASTG/tests/android/MASVS-AUTH/MASTG-TEST-0017/))
- [ ] Testing the Purposes of Keys ([MASTG-TEST-0015](https://mas.owasp.org/MASTG/tests/android/MASVS-CRYPTO/MASTG-TEST-0015/))
- [ ] Testing the Configuration of Cryptographic Standard Algorithms ([MASTG-TEST-0014](https://mas.owasp.org/MASTG/tests/android/MASVS-CRYPTO/MASTG-TEST-0014/))
- [ ] Testing Random Number Generation ([MASTG-TEST-0016](https://mas.owasp.org/MASTG/tests/android/MASVS-CRYPTO/MASTG-TEST-0016/))
- [ ] Testing Symmetric Cryptography ([MASTG-TEST-0013](https://mas.owasp.org/MASTG/tests/android/MASVS-CRYPTO/MASTG-TEST-0013/))
- [ ] Testing Custom Certificate Stores and Certificate Pinning ([MASTG-TEST-0022](https://mas.owasp.org/MASTG/tests/android/MASVS-NETWORK/MASTG-TEST-0022/))
- [ ] Testing the TLS Settings ([MASTG-TEST-0020](https://mas.owasp.org/MASTG/tests/android/MASVS-NETWORK/MASTG-TEST-0020/))
- [ ] Testing the Security Provider ([MASTG-TEST-0023](https://mas.owasp.org/MASTG/tests/android/MASVS-NETWORK/MASTG-TEST-0023/))
- [ ] Testing Endpoint Identify Verification ([MASTG-TEST-0021](https://mas.owasp.org/MASTG/tests/android/MASVS-NETWORK/MASTG-TEST-0021/))
- [ ] Testing Data Encryption on the Network ([MASTG-TEST-0019](https://mas.owasp.org/MASTG/tests/android/MASVS-NETWORK/MASTG-TEST-0019/))
- [ ] Testing Object Persistence ([MASTG-TEST-0034](https://mas.owasp.org/MASTG/tests/android/MASVS-CODE/MASTG-TEST-0034/))
- [ ] Memory Corruption Bugs ([MASTG-TEST-0043](https://mas.owasp.org/MASTG/tests/android/MASVS-CODE/MASTG-TEST-0043/))
- [ ] Testing Local Storage for Input Validation ([MASTG-TEST-0002](https://mas.owasp.org/MASTG/tests/android/MASVS-CODE/MASTG-TEST-0002/))
- [ ] Make Sure That Free Security Features Are Activated ([MASTG-TEST-0044](https://mas.owasp.org/MASTG/tests/android/MASVS-CODE/MASTG-TEST-0044/))
- [ ] Testing Implicit Intents ([MASTG-TEST-0026](https://mas.owasp.org/MASTG/tests/android/MASVS-CODE/MASTG-TEST-0026/))
- [ ] Checking for Weaknesses in Third Party Libraries ([MASTG-TEST-0042](https://mas.owasp.org/MASTG/tests/android/MASVS-CODE/MASTG-TEST-0042/))
- [ ] Testing Enforced Updating ([MASTG-TEST-0036](https://mas.owasp.org/MASTG/tests/android/MASVS-CODE/MASTG-TEST-0036/))
- [ ] Testing for URL Loading in WebViews ([MASTG-TEST-0027](https://mas.owasp.org/MASTG/tests/android/MASVS-CODE/MASTG-TEST-0027/))
- [ ] Testing for Injection Flaws ([MASTG-TEST-0025](https://mas.owasp.org/MASTG/tests/android/MASVS-CODE/MASTG-TEST-0025/))

**Manifest Exploration & Static Analysis**

- Check if `AndroidManifest.xml` contains: `<interesting_info>`, basically a blueprint of the application
- Check if `AndroidManifest.xml` contains: `android:allowBackup = TRUE`
- Check if `AndroidManifest.xml` contains: `android:debuggable = TRUE`
- Check if `AndroidManifest.xml` contains: `android:exported = TRUE` (or not set), allowing external apps to access data
- Check if `AndroidManifest.xml` contains: `android:permission.READ|WRITE_EXTERNAL_STORAGE`, only if sensitive data was stored/read externally, resulting in:
  - The app, opens website in external browser (not `inApp`), however requires "`android.permission.INTERNET`" indicating incorrect usage of permissions (ie. *over-privileged*)
  - The app's `android:protectionLevel` was not set properly (ie. `<permission android:name="my_custom_permission_name" android:protectionLevel="signature"/>`)
  - The app is missing `android:permission` (permission tags limiting exposure to other apps)
- Cleartext Credentials (ie. Base64-encoded, Hardcoded, or Weak Encrypted)
  - Hard-coded User Authentication Information (Credentials, PINs, etc.)
  - Hard-coded Cryptographi Keys
  - Hard-coded Keys used for Encrypted Databases
  - Hard-coded API Keys
  - Hard-coded Keys that might've been encoded (Base64/XOR/etc.)
  - Hard-coded Server IPv4 Addresses
- File Permissions uses `MODE_WORLD_READABLE` / `MODE_WORLD_WRITEABLE` (other apps/users are able to read/write the file)
- Debug Information, Information Disclosure, or anything that shouldn't be in the APK
- Find exported components, API keys, DeepLink Schemas, Endpoints in file `resources.arsc/strings.xml`
- Explore all file save paths in file `res/xml/file_paths.xml`
- Search source code recursively, especially `BuildConfig` files
- Search for Firebase related value leaks using `firebase.io`/`https://*.firebase.io/.json`
- Extract API Keys by:
  - Looking up string reference in Android Classes (`getString(R.string.<stringResourceLabel>)`)
  - Finding these string references in corresponding `strings.xml` file
  - Joining together the domains and required parameters as per decompiled code
- Android Exported Components:
  - Activities: Entrypoints for application interactions of components specified in `AndroidManifest.xml`
    - Has several states managed by callbacks such as `onCreate()`
    - Access to protected intents via exported activites
    - One exported activity that accepts a user provided intent can expose protected intents
    - Access to sensitive data via exported activity
    - Often combined with deep links to steal data via unvalidated parameters, write session tokens to an external file
    - Access to sensitive files, stealing files, replacing imported files via exported activities, external-files-path, external-path, public app. directories
    - Look for `content://` in decompiled source code
  - Service: Supplies additional functionality in the background
    - Custom file upload service for example, that is vulnerable due to `android:exported="TRUE"` flag
    - When exported, third-party applications can send data to the service
    - When exported, third-party applications can steal sensitive data from application depending on the service function
    - Check if parameters and intent data can be set with PoC application
  - Broadcast Receivers: Receives broadcasts from events of interest
    - Usually specified broadcasted intents in the broadcast receiver activity
    - Vulnerable when receiver is exported and accepts user provided broadcasts
    - Any application, including malicious ones, can send an intent to the broadcast receiver causing it to be triggered without any restrictions
  - Content Providers: Helps application to manage access to stored data and ways to share data with other Android apps
    - Content providers that connect to SQLite can be exploited via SQL Injection by a third-party apps
- Deep Links:
  - A deep link is a link that takes user directly to a specific destination with-in an app
  - Usally mirros web application except with different schemas that navigate directory to specific Android activity
  - Verified deep links can only use `http` and `https` schemas, but custom schemas can be implemented by developers
  - Type of vulnerabilities are based on how thre `scheme://`, `host://` and parameters are validated
    - CSRF: Test when `autoVerify="true"` is not present in `AndroidManifest.xml`
    - Open Redirect: Test when custom schemes do not verify endpoint parameters or hosts
    - XSS: Test when endpoint parameters or hosts are not validated, use of `addJavaScriptInterface(...)`/`setJavascriptEnabled(true)`
    - LFI: Test when deep link parameters aren't validated, ie. `appschema://app/goto?file=[...]`
- Database Encryption:
  - Check if database is encrypted under `/data/data/<package_name>/`
  - Check if decompiled code contains database credentials
- Allowed Backup:
  - Check if any backup results in Sensitive Information Disclosure
  - Use the `adb backup com.example.app` to backup the allowed app. data
- Verbose Logging Enabled
  - Check logs using `logcat` when user tries to Log-in
  - Check logs using `logcat` on other actions performed
- External Storage
  - Check data stored on External Storage, ie. `/sdcard/android/data/<com.example.app>/` directory
- Weak Hashing Algorithm
  - Use of `MD5` or equivalent hashing algorithm that may be vulnerable to collisions
  - Predictable PRNG due to use of `java.util.Random` function
- Check for "Debug Mode" enabled flag
  - Start a shell on Android using: `adb shell`
  - Gain an interactive shell with `run-as` command: `run-as <com.example.app>` in adb
  - Execute app. via forced debug mode: `adb exec-out run-as com.example.app cat databases/AppName > AppNameDB-COPY`
- Built-in WebView Testing
  - If application is using built-in WebView, try to access it
  - Deeplink WebView Open URL: `appscheme://webview?url=https://google.com`
  - Deeplink WebView Javascript: `appscheme://webview?url=javascript:document.write(document.domain)`

**Public Disclosures**

* [H1: Hardcoded API Secret in Android App](https://hackerone.com/reports/351555)
* [H1: Account Takeover via Intercepted Magic Link](https://hackerone.com/reports/855618)
* [H1: Insecure deeplink leads to Sensitive Information Disclosure](https://hackerone.com/reports/401793)
* [H1: SQL Injection via Android App Content Provider](https://hackerone.com/reports/291764)
* [H1: Theft of User Session via vulnerable Deep Link](https://hackerone.com/reports/328486)
* [H1: Android Intent missing validation leads to multiple vulnerabilities](https://hackerone.com/reports/499348)
* [H1: Theft of Arbitrary Files leading to Token Leakage](https://hackerone.com/reports/288955)
* [H1: Stealing Arbitrary Files from Android device](https://hackerone.com/reports/258460)
* [H1: Insecure Data Storage in Android App via Webview](https://hackerone.com/reports/44727)
* [H1: Insecure Local Data Storage using a binary SQLite Database](https://hackerone.com/reports/57918)
* [H1: HTML Injection in Application WebView](https://hackerone.com/reports/176065)
* [H1: XSS via start ContentActivity on Android app](https://hackerone.com/reports/189793)
* [H1: Access of Android Protected Components via Embedded Intent](https://hackerone.com/reports/200427)
* [H1: Fragment Injection in Twitter Android App](https://hackerone.com/reports/43988)
* [H1: App is vulnerable to XSS/WSX injected into Activity](https://hackerone.com/reports/54631)
* [H1: App deeplink leads to CSRF](https://hackerone.com/reports/583987)
* [H1: Android app. leaks all API requests due to insufficient broadcast permissions](https://hackerone.com/reports/56002)
* [Security Checklist: Abusing Android WebViews](https://blog.oversecured.com/Android-security-checklist-webview/)
* [Security Checklist: Content Providers & their weak spots](https://blog.oversecured.com/Content-Providers-and-the-potential-weak-spots-they-can-have/)
* [Security Checklist: Gaining Access to arbitrary Content Providers](https://blog.oversecured.com/Gaining-access-to-arbitrary-Content-Providers/)
* [Security Checklist: Theft of Arbitrary Files](https://blog.oversecured.com/Android-security-checklist-theft-of-arbitrary-files/)
* [Security Checklist: Common mistakes when using Android Permissions](https://blog.oversecured.com/Common-mistakes-when-using-permissions-in-Android/)
* [Security Checklist: Vulnerabilities in WebResourceResponse](https://blog.oversecured.com/Android-Exploring-vulnerabilities-in-WebResourceResponse/)
* [Security Checklist: Interception of Android Implicit Intents](https://blog.oversecured.com/Interception-of-Android-implicit-intents/)
* [Security Checklist: Arbitrary Code Execution via Third-party Package Contexts](https://blog.oversecured.com/Android-arbitrary-code-execution-via-third-party-package-contexts/)
* [Security Checklist: Universal XSS and theft of all cookies on Evernote app.](https://blog.oversecured.com/Evernote-Universal-XSS-theft-of-all-cookies-from-all-sites-and-more/)
* [PentestLab Blog: Android WebView Vulnerabilities](https://pentestlab.blog/2017/02/12/android-webview-vulnerabilities/)
