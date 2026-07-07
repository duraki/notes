---
title: Running WinNT Apps on MacOS
---

There are multiple ways a Microsoft WinNT applications can be executed on MacOS. Some of tested methods are outlined below.

## Running WinNT apps via Wineskin Winery

Wineskin Winery is a user-friendly tool used to make Wine-wrapped ports of Windows apps/software for latest Apple macOS systems. The official GitHub repository is located at [Gcenx/WineskinServer](https://github.com/Gcenx/WineskinServer).

* Install Wineskin Winery using Homebrew

```
brew install --cask --no-quarantine gcenx/wine/wineskin
```

* Open Wineskin Winery app. on your MacOS using Spotlight
* Once Wineskin Winery is opened, you should see a list of Installed Engines
* Click on the `+ New Engine(s) available!` plus icon and download the latest engine version
  - Ie. engine file `WS12WineCX64Bit23.7.1` to select CX = CrossOver version
* Select one of the installed and available engines in Wineskin Winery

{{< imgcap title="Wineskin Winery - Selecting the Engines" src="/posts/winnt/winery_1.png" >}}

* Click on the **Create New Blank Wrapper** button to create a new wrapper
  - Name the wrapper to whatever name you want, ie. `Example_MyAppWrapper * (.app)`
* Click on the "OK" button and wait until the newly wrapper is created. **Note** *It may take some long time*!

{{< imgcap title="Wineskin Winery - Creating the Wrapper" src="/posts/winnt/winery_2.png" >}}

All new created wrappers are located in the following directory:

```
$ ls -la $HOME/Applications/Wineskin/
# ...
drwxrwxrwx  3 hxxxx  wheel    96 Apr 26 00:20 Example_MyAppWrapper.app
drwxrwxrwx  3 hxxxx  wheel    96 Apr 26 00:20 MyCoolWrapper.app
```

{{< imgcap title="Wineskin Winery - Wrapper Created" src="/posts/winnt/winery_3.png" >}}

* Open the newly created wrapper app. using Finder or Spotlight
* You should be presented with Wineskin Popup, that allows you to install WinNT apps or configure Wine

{{< imgcap title="Wineskin Winery - Wrapper Popup" src="/posts/winnt/winery_4.png" >}}

* If using Wineskin Winery for **WindowsNT Games**, click on **Winetricks** in the popup and search for:
  - `d3dcompiler_47`, `dxvk` (DirectX) DLLs or any version above
* If using Wineskin Winery for **WindowsNT Apps**, click on **Winetricks** in the popup and search for:
  - `vcrun2022` or other required DLL for Visual C++ libraries
  - `dotnet48` or other required DLL for MS .NET libraries
* Otherwise, use [FanderWasTaken/wine-dependency-hell-solver](https://github.com/FanderWasTaken/wine-dependency-hell-solver) to solve required complex dependencies
* Click on **Run** to install selected Winetricks/DLLs and wait for process to finish
* You can also use Winetricks to download common WinNT apps such is 7Zip et al.


{{< imgcap title="Wineskin Winery - Using Winetricks to install requirements" src="/posts/winnt/winery_5.png" >}}

{{< imgcap title="Wineskin Winery - Using Winetricks (Installation)" src="/posts/winnt/winery_6.png" >}}

* Back in the Wrapper Popup window, click on the "Install Software" button
* Select either of the options in the "Wineskin Installer" window
  - Choose Setup Executable: to install WinNT apps/games via `setup.exe` or other installer
  - Copy a Folder Inside: to install portable programs by copying a folder inside the wrapper
  - Move a Folder Inside: same as copy, except it moves the folder instead of copying it

{{< imgcap title="Wineskin Winery - Installer" src="/posts/winnt/winery_7.png" >}}

* Most likely, you will use the first option (*Choose Setup Executable*)
* Click the *Choose Setup Executable* button in Installer to select `setup.exe` file or equivalent
* Complete the installation using the shown windows/popups

{{< imgcap title="Wineskin Winery - Selecting Telegram Desktop Setup" src="/posts/winnt/winery_8.png" >}}

{{< imgcap title="Wineskin Winery - Installing Telegram Desktop" src="/posts/winnt/winery_9.png" >}}

* Once the Game/App is installed in Wineskin Winery, click on the "Advanced" button in "Wineskin Popup"
* In Wineskin Advanced window, configure:
  - `Windows app:` to path location of the App executable inside the Windows (use `Browse` button)
  - In *Tools* tab, you may:
    - Use *Config Utility* via `winecfg`
    - Use *Registry Editor* via `regedit`
    - Use *Task Manager* or *Command Line* via `taskmgr/cli`
    - Open *Control Panel* via `control` and much more

{{< imgcap title="Wineskin Winery - Wineskin Advanced - Configuration" src="/posts/winnt/winery_9_advanced.png" >}}

{{< imgcap title="Wineskin Winery - Wineskin Advanced - Tools" src="/posts/winnt/winery_9_tools.png" >}}

If the Wineskin Wrapper is crashing, ie. app can't be opened, you may reconfigure the Wrapper by going to:

* Wineskin Wrapper dir: `/Users/$USER/Applications/Wineskin/`
* Right-click on crashing wrapper, and click **Show Package Contents**
* Double-click on the `Wineskin.app` file inside the enclosed wrapper package folder
* Re-configure Wineskin and fix crashing via Reinstall/Advanced/DLLs/etc.

### References

* [Wineskin as Crossover alternative on M1](https://malwarewerewolf.com/posts/wineskin-server-a-free-alternative-to-crossover-on-m1/)
* [Play DOOM 3 natively on Apple M1](https://malwarewerewolf.com/posts/play-doom-3-natively-on-apple-m1/)
* [Play SIMS on Mac](https://github.com/Gcenx/PlaySimsOnMac)
* [Debugging game on MacOS via wine](https://an-pro.org/posts/13-wine-debug-success-story.html)
* [/r/FitGirlRepack](https://www.reddit.com/r/PiratedGames/), [/r/PiratedGames](https://www.reddit.com/r/PiratedGames/)

## Running WinNT apps via Whisky

Whisky is a modern Wine wrapper for macOS built with SwiftUI. The official GitHub repository is located at [Whisky-App/Whisky](https://github.com/Whisky-App/Whisky).

* Install Whisky using Homebrew

```
brew install --cask whisky
```

* [Whisky Official Documentation](https://docs.getwhisky.app/)
* [Whisky Game Support](https://docs.getwhisky.app/game-support/index.html)
