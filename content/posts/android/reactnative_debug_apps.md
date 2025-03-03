---
title: "Enabling DevMode in React Native Apps"
url: "reactnative-patch-devmode"
---

The idea of this note is to describe technique and process which might allow reverse engineers to enable *debugging* capabilities in third-party apps. and force this "development" context without any limitations, eventually allowing us to debug applications straight out of the Google PlayStore or the APK distributions.

For a quick start, it's recommended to go through [Developing simple app in React Native](/reactnative-simple-app) and [Exploring React Native Apps on Android](/reactnative-on-android) notes to get a feel of React Native and its' ecosystem. Additonally, base notes were described in [Using APKLab to Enable DevMode in React Apps](/reactnative-patch-devmode-old) which provides setup instruction for APKLab Workbench, and patch modifications on React apps. Java native level.

### Demo App

We will use our [Demo App](/reactnative-simple-app) and build the release-variant APK to study and anlyze this topic.

Build the release variant of the Android demo application using:

```sh
$ npm run build
# > rnprojectdemo@0.0.1 build
# > react-native run-android --mode=release
#
# info A dev server is already running for this project on port 8081.
# info Installing the app...
#
# > Task :app:createBundleReleaseJsAndAssets
# Writing bundle output to: 
#           rnprojectdemo/android/app/build/generated/assets/createBundleReleaseJsAndAssets/index.android.bundle
# Writing sourcemap output to: 
#           rnprojectdemo/android/app/build/intermediates/sourcemaps/react/release/index.android.bundle.packager.map
# 
# > Task :app:installRelease
# Installing APK 'app-release.apk, app-release.dm' on 'Nexus 10 - 13' for :app:release
# Installed on 1 device.
#
# Starting: Intent { act=android.intent.action.MAIN cat=[android.intent.category.LAUNCHER] cmp=com.rnprojectdemo/.MainActivity }
```

The APK distribution files should be generated in: `android/app/build/outputs/apk/` in `(debug)` and `(release)` subdirectories:

```sh
$ ls -la [project]/android/app/build/outputs/apk/
# drwxr-xr-x  4 xxxxxxx  staff   128 Feb  9 19:37 debug       # -> app-debug.apk
# drwxr-xr-x  5 xxxxxxx  staff   160 Feb  9 22:11 release     # -> app-release.apk
```

If you install the release version of the APK and try to get into "Developer Menu" using `CMD+Shift+M` keyboard shortcut, or by sending the keycode `82` over `adb`, nothing will happen since App. Devmode is disabled on "release" distributions.

**Decompile the Releases-version APK**
Follow the notes in [Exploring React Native Apps on Android](/reactnative-on-android) to decompile and explore the built "Releases" APK distribution.

**DEV Components in APK**
We can try forcing the `DEV` flag in the Javascript Bundle (`assets/index.android.bundle`) file and repack (recompile) app again with single modification; that is, replacing the `__DEV__=false` instruction early in the bundle to `__DEV__=true`. Once the app is recompiled and installed on the device, nothing happens. There were no requests observed to port `8081`, Dev Menu can't be triggered, however, manually opening the Dev Settings presented the "JS Dev Mode" checkbox enabled:

```
$ adb shell "am start com.rnprojectdemo/...DevSettingsActivity"
# ...
```

Other than that, no other way was found via above method to open apps' dev-tools, nor a way to debug the app.

### Research Debug Flags

Searching around, I've found [Leo's](https://laripping.com/blog-posts/2020/04/17/debugging-react-native-apps.html) and [EdgeApp's](https://github.com/EdgeApp/edge-react-gui/wiki/Debugging-React-Native-in-Production-Mode) notes very valuable. They indicate that there are 2x components that should have `DEV` state:
    - The **JavaScript** code
    - The **Native (Java)** code

The above process only switched the JavaScript counterpart to "DEV", but was missing native Java context to allow DEV stuff. The native code responsible for all the DEV stuff is part of the `react-native` core module, and lies in thhe `com.facebook.react.devsupport` package.

Esentially, the critical bits to investigate are under demo apps' directory `node_modules/react-native/ReactAndroid/src/main/java/com/facebook/react/devsupport/*`

In detail, the decision to include this package's functionality or not, is located in the `DevSupportManagerFactory` class:

```java
// node_modules/react-native/ReactAndroid/src/main/java/com/facebook/react/devsupport/DevSupportManagerFactory.java

package com.facebook.react.devsupport;
// ...

public interface DevSupportManagerFactory {
  /**
   * Factory used by the Old Architecture flow to create a {@link DevSupportManager} and a {@link
   * com.facebook.react.runtime.BridgeDevSupportManager}
   */
  DevSupportManager create(..., boolean enableOnCreate) {

  }
```

The factory class responsible for deciding whether to enable Developer Menu in the app is in Kotlin's `DefaultDevSupportManagerFactory` class:

```kotlin
// node_modules/react-native/ReactAndroid/src/main/java/com/facebook/react/devsupport/DefaultDevSupportManagerFactory.kt

package com.facebook.react.devsupport
// ...

public class DefaultDevSupportManagerFactory : DevSupportManagerFactory {
    // ...

    public override fun create(/* ... */, enableOnCreate: Boolean, /* ... */): DevSupportManager {

        return if (!enableOnCreate) {
            ReleaseDevSupportManager()
        } else
            try {
                // Developer support is enabled, we now must choose whether to return a DevSupportManager,
                // ...
```

The `enableOnCreate` argument is traced back to `abstract class ReactNativeHost`, which by the way React Native works, is instantiated by demo app. own's Kotlin class `MainApplication.kt`:

```kotlin
// android/app/src/main/java/com/rnprojectdemo/MainApplication.kt
package com.rnprojectdemo

// ...

class MainApplication : Application(), ReactApplication {

  override val reactNativeHost: ReactNativeHost =
      object : DefaultReactNativeHost(this) {
        // ...
        //

        // This function returns whatever is in 'BuildConfig.DEBUG' flag
        override fun getUseDeveloperSupport(): Boolean = BuildConfig.DEBUG
      }

    // ...
}
```

In the excerpt above it's visible that the inclusion of Developer/Debugging support code boils down to the `BuildConfig.DEBUG`, replaced by Gradle task on buildtime, therefore, after decompiling, will look like this *pseudocode* for the above class:

```kotlin
package com.rnprojectdemo

class MainApplication : Application(), ReactApplication {
    // ...
    fun getUseDeveloperSupport() {
        return false;
    }
}
```

### Patching Debug Flags

To locate the overriden `getUseDeveloperSupport()` function we must keep in mind that smali-bytecode displays nested classes with the nesting class's name, appended with a dollar sign (`$`). Therefore, the class we need to modify is:

```
smali/com/rnprojectdemo/MainApplication$reactNativeHost$1.smali
```

The `smali` bytecode for the aftermentioned method looks similar to this:

```smali
# /smali/com/rnprojectdemo/MainApplication$reactNativeHost$1.smali

...

# virtual methods
.method public getUseDeveloperSupport()Z
    .locals 1
    const/4 v0, 0x0             # replace with 0x1
    return v0
.end method
```

Change the value `0x0` to `0x1` in `v0` to patch `BuildConfig.DEBUG` value to `Bool(True)`, and rebuild the APK, sign it and install it on the device. Once the patched APK is installed, type the following in Terminal, in the `rnprojectdemo` repository/directory:

```
$ npm run react-native start
```

