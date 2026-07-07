---
title: "Android MITM for HTTP/S protocols"
url: "android-mitm-for-https-protocols"
---

**Android MITM for Emulated Devices**

This note provide details on how to enable and execute MITM against the [emulated devices](/running-android-apps-on-macos) on macOS using Burp Suite Professional. The setup for which we are enabling MITM is something like this:

* Emulated [Google Pixel 8 Pro](/running-android-apps-on-macos) Android Device (Model: `GKWS6`)
* Operating System is `AndroidOS 12`
* The Host is running macOS
* Android Platform Tools installed on Host

1. Export Burp Suite Certificate

Open Burp Suite Professional, start a new temporary project, and click on `Proxy => Proxy Settings` tab. Under the "Proxy Listeners" panel click on the `Import / export CA Certificate`, and choose "Certificate in DER format" in the popup window. Click "Next", and choose the location and filename to save the DER file, for example: `~/burpcert/cert.der`.

2. Convert Burp Suite DER to PEM Certificate

Once you have DER (Distinguished Encoding Rules) digital certificate file exported (`cert.der`), we need to convert it to PEM (Privacy Enhanced Mail) file. We can do it using the `openssl` command below:

```
$ openssl x509 -inform der -in ~/burpcert/cert.der -out ~/burpcert/cert.pem
```

4. Convert Burp Suite PEM Certificate to Subject Hash

Now that we have certificate in PEM format, we can use `openssl` command again to generate a subject hash out of the provided PEM file. This is required due to newer AndroidOS versions not allowing the typical installation of the certificates from the device Settings app. Once you run the following command, the Terminal output should display the subject hash, alongside the certificate in cleartext:

```
$ openssl x509 -subject_hash_old -in ~/burpcert/cert.pem
# 9a5ba575                                 # Certificate Subject Hash
#
# -----BEGIN CERTIFICATE-----              # Certificate Cleartext
# MIIDqDCCApCgAwIBAgIFAJ2J/DcwDQYJKoZIhvcNAQELBQAwgYoxFDASBgNVBAYT
#                           [REDACTED]
# H0vfflysfnp6fKLQAkHoOGN1qg37PgqsdQH0Sg==
# -----END CERTIFICATE-----
```

Once you have Subject Hash of Burp Suite certificate, we need to rename our PEM certificate to that of Subject Hash, followed by `.0`, meaning the name of our certificate would be `9a5ba575.0`, as shown below:

```
$ cp ~/burpcert/cert.pem ~/burpcert/9a5ba575.0
```

5. Push the certificate into the system directory using `adb`

Now using the `adb` command, we can push our certificate with subject hash as a filename, to Android System CA certs directory, as shown below:

```
$ adb devices
# List of devices attached
# 127.0.0.1:26624	device

$ adb push ~/burpcert/9a5ba575.0 /system/etc/security/cacerts/
$ adb shell "chmod 664 /system/etc/security/cacerts/9a5ba575.0"
```

6. Test if SSL Proxy is working in Android

Configure your Burp Suite to capture packets from all interfaces by clicking on the `Prox` tab, and then click `Proxy Settings`, and in the "Proxy Listeners" panel click "Add" button, select option "Bind to address: All Interfaces" and set the port to `8080`. Click "OK" and the Burp Suite should now listen to traffic on all interfaces.

Configure your Android Device to proxy through the Burp Suite by going into "Settings" app in Android, then click `Network & Internet -> Internet -> wlan0` and use the settings icon in the top right corner, select "Manual" under "Proxy", and enter the "Proxy Hostname" to "0.0.0.0" and "Proxy Port" to "8080". Finally, click "Save" and open any webpage (ie. `https://google.com`) from Web Browser app in Android and see if the Burp Suite recorded the HTTP Request/Response in `Proxy -> History` tab.

Sometimes the proxy won't work until the port forwarding is configured, which can be done using the following command on your Host:

```
$ adb reverse tcp:8080 tcp:8080
```

References:

* [MuMuPlayer Install Certificate & Packet Capture](https://www.mumuplayer.com/mac/tutorials/certificates-and-packet-capture.html)
* [How to setup Burp Suite on Android](https://dev.to/whatminjacodes/how-to-setup-burp-suite-on-android-581a)
* [Setting up Burp Suite to work with Android Emulator](https://b4y.dev/posts/android-emulator-burp-suite/)

**Android MITM for Real Devices**

_To be added._
