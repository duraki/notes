---
title: "Using APKLab to Enable DevMode in React Apps"
url: "reactnative-patch-devmode-old"
---

**Enable ReactNative Android Debug Utilities in Production APKs**

During this process, we will enable the React's Native Dev Menu (*Bridge*) allowing us to explore the JSIExecutor runtime, alongside the Hermes runtime (if applicable).

Using the previously extracted and analyzed APK, similarly, we will start decompiling it via VSCode & [APKLab]() extension, so we could edit the Java and Smali code more natively and recompile the final build of patched/signed APK.

1. Download & Install [Visual Studio Code](https://code.visualstudio.com/download)

Either download the corresponding Visual Studio Code installation file for your HostOS, or if you are on macOS you can use `homebrew`:

```
$ brew install --cask visual-studio-code
# ...
```

2. Open Visual Studio Code & Install APKLab Extension

The [APKLab](https://github.com/APKLab/APKLab) extension aids reverse engineering process directly in VS Code as a sort of Workbench. It is publicly available and installable via [VSCode Marketplace](https://marketplace.visualstudio.com/items?itemName=Surendrajat.apklab).

HostOS requirements are as following:

* **JDK 8+**: Run `java --version` in Terminal to check your JDK Version
* **quark-engine >=21.01.6**: Run `quark` in Terminal to check the version, check [official docs](https://github.com/quark-engine/quark-engine)
* **adb**: Run `adb devices` in Terminal, if not found [check this guide](https://www.xda-developers.com/install-adb-windows-macos-linux/)

Click **Install** in VSCode's `Extension: APKLab` Tab or in the VSCode Marketplace to install the extension.

3. Open the APK using VSCode's APKLab

Open a new VSCode Window ({{<kbd>}}⌘{{</kbd>}}+{{<kbd>}}⇧{{</kbd>}}+{{<kbd>}}N{{</kbd>}}) and then trigger *Command Palette* in the new window using {{<kbd>}}⌘{{</kbd>}}+{{<kbd>}}⇧{{</kbd>}}+{{<kbd>}}P{{</kbd>}} keyboard shortcut.

In the *Command Palette* enter "APKLab: Open an APK" as shown below:

{{< imgcap title="Visual Studio Code - APKLab - Open APK" src="/posts/android/apklab_open_apk.png" >}}

Select your APK file and when asked for decompilation details, use check the following features:

- [x] Check `decompile_java` [jadx]
- [x] Check `--only-main-classes` [apktool]
- [x] Check `--deobf` [jadx]
- [ ] Leave all other flags **unchecked**:
  * `quark_analysis`, `--no-src`, `--no-res`, `--force-manifest`, `--no-assets`, `--no-debug-info`, `--show-bad-code`

Start APKLab analysis once ready and wait for the process to finish fully - watch the *Output* pane in VSCode for progress details. Once completed, the *Explorer* pane in VSCode should contain decompiled Java code of the selected APK, the `smali` directory containing decompiled native JVM smalicode of all `*.dex` classes (ie. custom app. codebase), and `apktool.yml` file describing all *[re/de]*compilation flags.

Besides, the APKLab Workbench add-on will initiate a `.git` repository, which is handy since it tracks any changes/breaks you may trigger during the patching process.

4. Patching the APK to enable ReactNative Debugging

Start by expanding `smali_classes[...]` directoris, which due to flag we used earlier (ie. `--only-main-classes`) provides mostly custom codebase of the targeted Android application. In my example, I have (4x) `smali_classes` directories indicated by their numbers `[1|2|3]` and one without number indicator. If you remember earlier while using *Jadx-GUI*, the Summary tab showed the `classes.dex`, `classes2.dex`, which are those decompiled smali decompilation bytecodes:

```bash
$ cd /path/where/vscode/apklab/decompiled/the/code
$ ls -la | grep "smali*"
drwxr-xr-x    6 xxxxxxx  staff    192 Feb  5 01:17 smali            # classes.dex
drwxr-xr-x    3 xxxxxxx  staff     96 Feb  5 01:17 smali_classes2   # classes2.dex
drwxr-xr-x    6 xxxxxxx  staff    192 Feb  5 01:17 smali_classes3   # classes3.dex
drwxr-xr-x   14 xxxxxxx  staff    448 Feb  5 01:17 smali_classes4   # classes4.dex
```

Traverse through each of the `smali*` directory and its relevant classes and try to identify where the patch should be placed.

Inside the `smali/` I haven't found any interesting classes, methods or values to patch therefore I will skip it. In other examples, it might be possible that only one `classes.dex` exists in APK therefore it will be the only application's custom codebase you may find (that is, in `smali/` directory).

Inside `smali_classes2/com/swmansion/getuserhandler/` directory, in my APK there is a `BuildConfig.smali` file containing the following Smali Bytecode:

```smali
.class public final Lcom/swmansion/gesturehandler/BuildConfig;
.super Ljava/lang/Object;
.source "BuildConfig.java"

# static fields
.field public static final BUILD_TYPE:Ljava/lang/String; = "release"
.field public static final DEBUG:Z = false
.field public static final IS_NEW_ARCHITECTURE_ENABLED:Z = false
.field public static final LIBRARY_PACKAGE_NAME:Ljava/lang/String; = "com.swmansion.gesturehandler"
.field public static final REACT_NATIVE_MINOR_VERSION:I = 0x4c

# direct methods
.method public constructor <init>()V
    # ... [REDACTED] ...
.end method
```

Although this component (*class*) is not part of the application's custom Android codebase, we can still see a declared static const `DEBUG` set to `false`. While still in VSCode, change this `DEBUG` value to `true`, like so:

```smali
# ...

# static fields
.field public static final DEBUG:Z = true

# ...
```

Once the line has been changed, VSCode will insert an indicator on the changed line since APKLab is awesome and it track changes via initialized `*git` repository. Check below screenshot for descriptive representation of this simple patch:

{{< imgcap title="Visual Studio Code - APKLab - Patching Smali Bytecode" src="/posts/android/apklab_vscode_debugtrue.png" >}}

---

Similarly, we will look for other `*.smali` decompiled bytecode that will help us enable **ReactNative Debugging**. In my APK example, inside the `smali_classes4/` directory, I have very interesting subdirectory, located in `smali_classes4/com/example/appname`. Since I know my targeted app. package is `com.example.appname` I'm sure this is relevant codebase of the targeted package/application. 

Below is the directory/file content of it:

```bash
$ cd /path/where/vscode/apklab/decompiled/the/code
$ ls -la smali_classes4/com/example/ | grep ".smali"
-rw-r--r--   1 xxxxxxx  staff   728 Feb  5 01:21 BuildConfig.smali
-rw-r--r--   1 xxxxxxx  staff  2863 Feb  5 01:17 MainActivity.smali
-rw-r--r--   1 xxxxxxx  staff  3850 Feb  5 01:24 MainApplication$reactNativeHost$1.smali
-rw-r--r--   1 xxxxxxx  staff  3731 Feb  5 01:17 MainApplication.smali
-rw-r--r--   1 xxxxxxx  staff  3629 Feb  5 01:17 R$drawable.smali
-rw-r--r--   1 xxxxxxx  staff   586 Feb  5 01:32 R$integer.smali
-rw-r--r--   1 xxxxxxx  staff   963 Feb  5 01:17 R$mipmap.smali
-rw-r--r--   1 xxxxxxx  staff   527 Feb  5 01:17 R$string.smali
-rw-r--r--   1 xxxxxxx  staff   580 Feb  5 01:17 R$style.smali
-rw-r--r--   1 xxxxxxx  staff   531 Feb  5 01:17 R.smali
```

Visiting each of the identified `*.smali` files inside this directory will provide you further information about the targeted application, and may help you enlarge attack surface. For now, the most interesting to us are the `BuildConfig.smali` and `MainApplication$reactNativeHost$1.smali`.

The filenames on other APK targets may be different but they should usually correspond to that of [react-native]() framework and its' compiled builds. Lets start anylizing `BuildConfig.smali` file first.

**BuildConfig:** *Analysis of `BuildConfig.smali` Smali Bytecode File*

The default and decompiled `BuildConfig.smali` file contains the following code inside it:

```smali
.class public final Lcom/example/app/BuildConfig;
.super Ljava/lang/Object;
.source "BuildConfig.java"

# static fields
.field public static final APPLICATION_ID:Ljava/lang/String; = "com.example.name"
.field public static final BUILD_TYPE:Ljava/lang/String; = "release"
.field public static final DEBUG:Z = false
.field public static final IS_HERMES_ENABLED:Z = true
.field public static final IS_NEW_ARCHITECTURE_ENABLED:Z = false
.field public static final VERSION_CODE:I = 0x1f
.field public static final VERSION_NAME:Ljava/lang/String; = "1.1"

# direct methods
.method public constructor <init>()V
    .locals 0

    .line 6
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method
```

As shown above, there are some interesting `DEBUG` & `HERMES` flags defined in this files. Maybe we could change these to our values which can be beneficial to enable the ReactNative DevTools. Lets do that while we are at it, change the following constants and their values:

```smali
# ...

# static fields
.field public static final DEBUG:Z = true
.field public static final IS_HERMES_ENABLED:Z = false
```

**MainApplication/NativeHost:** *Analysis of `MainApplication$reactNativeHost$1.smali` Smali Bytecode File*

The file contents of the `MainApplication$reactNativeHost$1.smali` contains large number of decompiled code from my APK, therefore, the code below is used just to provide an overview and summary of the decompiled data:

```smali
.class public final Lcom/example/app/MainApplication$reactNativeHost$1;
.super Lcom/facebook/react/defaults/DefaultReactNativeHost;
.source "MainApplication.kt"

# annotations
# .annotation system Ldalvik/annotation/EnclosingMethod; ...

# direct methods
# .method constructor <init>(Lcom/example/app/MainApplication;)V ...

# virtual methods
# .method protected getJSMainModuleName()Ljava/lang/String; ...
# .method protected isNewArchEnabled()Z ...

# instance fields
.field private final isHermesEnabled:Z
.field private final isNewArchEnabled:Z

.method public getUseDeveloperSupport()Z
    # ...
    const/4 v0, 0x0
    return v0
.end method

.method protected isHermesEnabled()Ljava/lang/Boolean;
    # ...
    iget-boolean v0, p0, Lcom/example/app/MainApplication$reactNativeHost$1;->isHermesEnabled:Z
    invoke-static {v0}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;
    move-result-object
    return-object v0
.end method

```

Lets try to make sense of this Smali Bytecode; 

* The `.class public final MainApplication$<...>.smali` line indicates that this is a final `MainApplication` class, extending the base class described in `MainApplication.smali` with additional *ReactNativeHost* interfaces and conformings
* Then we have some `annotations`, alongside some `direct`/`virtual` methods we are not interested in
* Then, again, similarly to previous changes, we have `instance fields`, and while these are not static fields (ie. *const*), they are instead class fields (ie. *variables*)
* Finally, we have these two interesting functions defined: `getUseDeveloperSupport()` and `isHermesEnabled()`
  * The `getUseDeveloperSupport()` Method: Sets `v0` register to `0x0 (FALSE)` and returns it
  * The `isHermesEnabled()` Method: Retrieves the static field value of the parent class (ie. `instance fields IS_HERMES_ENABLED`) and place the `BOOL(IS_HERMES_ENABLED)` inside `v0` register, finally returning it

Therefore, we need to patch `getUseDeveloperSupport()` method to always have `0x1` (ie. *TRUE*) as retval. The method after patching should look like this:

```smali
.method public getUseDeveloperSupport()Z
    .locals 1
    const/4 v0, 0x1         # patched to 0x1
    return v0
.end method
```

**R/Integer:** *Analysis of `R$integer.smali` Smali Bytecode File*

Looking further into other `.smali` files inside the package directory, there is a file `R$integer.smali` which besides other code, containined the following line:

```smali
.class public final Lcom/example/app/R$integer;
.super Ljava/lang/Object;

# ...

# static fields
.field public static react_native_dev_server_port:I = 0x7f0b0037
```

This static constant value declared at compile-time presumably allows developer to set ReactNative DevServer Port, since the `:I` suffix indicates an Integer value. Further research on the Interwebz confirmed this and therefore it's of our interest to have ReactNative DevTools enabled. We need to find where this value is provided, and we might do that by *searching in all files* from VSCode using either:

* `0x7f0b0037` (Hexadecimal Representation)
* `react_native_dev_server_port` (Name Representation)

Searching for the value using `0x7f0b0037` did not provide the expected *Int*-val anywhere in the results, but it confirmed that this React Native DevServer Port is used alongside React Native library (ie. in `smali_classes3/com/facebook/react/R$integer.smali`).

Searching for the value using `react_native_dev_server_port` shown a match which defines this constant value, specifically it has been found in `res/values/integers.xml` file, as shown below:

```
$ cat res/values/integers.xml | grep react_native_dev_server
# <integer name="react_native_dev_server_port">8081</integer>
```

Therefore, we can conclude that the app. expects React Native DevServer to listen on `PORT:8081`. We can add this comment in our original `R$integer.smali` file for further reference:

```smali
.field public static react_native_dev_server_port:I = 0x7f0b0037    # reactnative dev-server port (8081)
```

5. Recompile APK with New Patches

Finally, we can recompile our patches into a new APK that. This can all be done from within the VSCode using APKLab Workbench add-on, which automatically adds correct keystore signature and sign all the bundled files in the APK, allowing the final APK to be installed on any Android device.

To compile new APK, right-click on the `apktool.yml` file in VSCode "Explorer" panel, and selecting "APKLab: Rebuild the APK".

{{< imgcap title="Visual Studio Code - APKLab - Rebuild the APK" src="/posts/android/apklab_rebuild_apk.png" >}}

Wait for the APKLab to finish recompilation process and then use `adb install` command to install the patched APK. The patched and signed APK ready for distribution should be found in the `./dist/[filename].apk` alongside your APKLab decompilation folder:

```
$ adb install [...]/dist/base.apk
# Success
```

Another option is to use `APKLab: Rebuild and Install the APK` from the contextual menu but it might now always work if multiple `adb` devices are present.

**Interacting with patched ReactNative Debug Server**

Once we followed all the steps described in **Enable ReactNative Android Debug Utilities in Production APKs**, we can try and see if our patching works and the ReactNative Dev/Debug is enabled and usable. Having the patched APK installed, open the targeted app. from the running emulator or the physical device.

Once the application is started and the `MainActivity` is running, use the `input keyevent 82` AndroidOS tty-command to trigger the ReactNative Dev Tools, as described in [official documentation](https://reactnative.dev/docs/debugging):

```
$ adb shell input keyevent 82
```

Once this keyevent code is sent, a pop-up should show overlaying the targeted application, looking like this:

{{< imgcap title="Android Device - ReactNative - DevMenu Bridge Popup" src="/posts/android/android_trigger_reactnativedev.png" >}}