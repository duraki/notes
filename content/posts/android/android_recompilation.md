---
title: "Android Recompilation"
---

## APKLab Workbench

A more in-depth instructions are provided in separate note titled ["Using APKLab for Recompilation"](/reactnative-patch-devmode-old) which is both easier and stable method of recompilation.

## Manual Recompilation

Decompile Android APK file using `apktool`:

```
# => decompile
$ apktool -r d AppName.apk -o AppName

# => recompile
$ apktool b AppName
```

Resign the APK package and install the Android application:

```
# => sign the apk package
$ keytool -genkey -keystore example.keystore -validity 10000 -alias example
$ jarsigner -keystore example.keystore -verbose AppName.apk example

# => installation
$ apk install AppName.apk
```
