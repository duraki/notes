---
title: "MacOS Tweaks"
---

If you end up checking my [Works for Me](https://deviltux.thedev.id/notes/works-for-me/) page, you might notice the amount of tweaks I have utilised in my environment. Based on the Apple's macOS that I use day to day in my workflow, I adhere this note to describe toolkit and system configurations, alongside other tweaks that helps me create my productive and creative environment.

**Table of Contents**
- [Application Icons](#application-icons)
- [Menubar Tweaks](#menubar-tweaks)
- [Windows Management (WM)](#windows-management-wm)
- [User Interface](#user-interface)
- [Wallpapers, Screensavers \& Desktops](#wallpapers-screensavers--desktops)

### Application Icons

I sometimes tweak my installed *application's* icon to a prefered choice, instead of using the defaults one that the application integrates. All the assets and design `*.ico`s are kept in my `~/.config/resources/design/` folder that I sync across multiple environments using [dotdrop](https://github.com/deadc0de6/dotdrop), which is based/cloned from my [private GitHub repository](http://github.com/duraki/dots) that tracks the change of my dotfiles, assets or binaries that I'd like to have installed by default, on new or formattted system environments. Some of the binaries I have installed and tracked are in my `~/.config/bin/*` directory, these are self-compiled binaries used daily during the day, but their typical download locations are either too obscure, unverified, or require self-compilation and notarization.

If it's important to keep track of my newly added directories or folders that I want across my environments, `dotdrop` can be used via the following Terminal command:

```
$ cd ~/dev/dots                                 # cd into my git-tracked dots dir
$ dotdrop import ~/.config/resources/design     # import the directory to track using dotdrop
#   
#   ...
#   1 File(s) imported.   
```

To change an application icon to a custom icon and keep it that way even after the application is *self-updated*, I use [Pictogram](https://pictogramapp.com) - a macOS utility that is totally free and which allows you to change any application icon installed on your Mac to some other icon. This utility also changes the selected application dock icon, and keeps the configured icon even after the application has been updated. The macOS App Icons alternative designs can be downloaded from [macOSicons.com](https://macosicons.com)/[macOSicongallery.com](https://www.macosicongallery.com) or finding them on [GitHub](https://github.com/dhanishgajjar/vscode-icons) or similar open-source hosting sites.

Sometimes an **Icon Generator** for a specific application may exists as a free online-hosted tool, for example a [VSCode custom icon generator](http://bouveronmaxi.me/vscode-icon-generator/), provided by [Bo-Duke/vscode-icon-generator](https://github.com/Bo-Duke/vscode-icon-generator) that allows making and creating a VSCode icon color scheme easier.

The tweaks presented here are shown-off on my [Works for Me](https://deviltux.thedev.id/notes/works-for-me/) page and are based on my [`~/dotfiles`](http://github.com/duraki/dots) but the GitHub repository is unfortunately private.

{{< details "**Icons:** Other Resources" >}}
I'm using [deadc0de6/dotdrop](https://github.com/deadc0de6/dotdrop) for managing my dotfiles. The utility supports multiplatform and is hosted on GitHub and is quite easy to use.

Besides, take a look at [lgarron/folderify](https://github.com/lgarron/folderify) CLI utility if you want to generate pixel-perfect macOS folder icons natively. To change Apps icon, use [Pictogram](https://pictogramapp.com) - a free software for macOS [by Neil](https://neilsardesai.com/pictogram) allowing you to use custom icons which can't be overwritten by the application during self-updates.

You may find alternative Apps icon designs on [macOSicons.com](https://macosicons.com), but there are some other sources which are application-specific, such is [VSCode Custom Icon Generator](http://bouveronmaxi.me/vscode-icon-generator/) - allowing you to create a VSCode custom icon based on your color scheme. Other [Folder Icons](https://github.com/VigoKrumins/folder-icons) for macOS/Windows are also to be found, which might provide you a visual-indicators to better organize development workspaces.

I also found [OS Folder Icons](https://github.com/shariati/OS-Folder-Icons/blob/gh-pages/.nojekyll) which contains various icons for WinNT/Linux/MacOS folders. This utility uses a custom generation [Python script](https://github.com/shariati/OS-Folder-Icons?tab=readme-ov-file#repository-folder-structure) allowing you to generate platform-independent folder icons if you are running multiple operating systems.
{{</ details >}}

### Menubar Tweaks

**SketchyBar:** This is an [open-source](https://github.com/FelixKratz/SketchyBar) highly [customizable](https://felixkratz.github.io/SketchyBar/config/bar) macOS status bar replacement. The default `sketchybarrc` file located in `~/.config/sketchybar` directory contains the main configuration and the plugin scripts. Refer to [Tips & Tricks](https://felixkratz.github.io/SketchyBar/config/tricks) page for additional config options. The color picker [hosted online](https://felixkratz.github.io/SketchyBar/config/tricks#color-picker) can be used to find ARGB encoded hex colors that are supported by SketchyBar. If you are looking for stylised app icons you might want to checkout the excellent community maintained [sketchybar-app-font](https://github.com/kvndrsslr/sketchybar-app-font) for SketchyBar.

Similar Apps: [BringOldMenuBar](https://www.publicspace.net/BoringOldMenuBar/) (Paid), [Menu Bar Tint](https://manytricks.com/menubartint/), and also oldy but goldy [spacebar](https://github.com/cmacrae/spacebar) (Un-maintained).

### Windows Management (WM)

Although **I don't use third-party WM(s)**, I will point out few that I've tried in the past here. There is an enterprise WM called [Moom](https://manytricks.com/moom/) (Paid), alongside [Menuwhere](https://manytricks.com/menuwhere/) (Paid, albeit very cheap). On other hand, there is [Yabai](https://github.com/koekeishiya/yabai) which is open-source and commonly used when ricing MacOS. The [AeroSpace](https://github.com/nikitabobko/AeroSpace) for macOS inspired by `i3` is also widely popular and still maintained. The latest kid on the block is [EnhancedSpoon](https://github.com/franzbu/EnhancedSpaces.spoon), but it requires [Hammerspoon](https://www.hammerspoon.org/).

{{< notice >}}
Note
{{</ notice >}}
{{< callout emoji="💡" text="Using the alternative WM requires a lot of custom configuration and settings to be set to play nicely, unlike the native WM shipped with MacOS (ie. [OSX's __Aqua__](https://en.wikipedia.org/wiki/Aqua_(user_interface))). I decided to not use WM in my environment but this paragraph sits for further reference if I ever change my mind." >}}

### User Interface

**JankyBorders:** This lightweight tool is designed to add colored borders to user windows on macOS 14.0+. It enhances the user experience by visually highlighting the currently focused window or other windows visible on the MacOS desktop(s). The tweak app. is [fully open-source](https://github.com/FelixKratz/JankyBorders) and should be easy to customize. Once installed via `brew`, you can bootstrap it from Terminal using the CLI or configure the corresponding `~/.config/borders/bordersrc` configuration file as explained in [official docs](https://github.com/FelixKratz/JankyBorders?tab=readme-ov-file#using-a-configuration-file-optional).

The colors are defined using `ARGB` (Alpha RGB) hexadecimal notation in this form: `0xAARRGGBB`. Here are some good color consts: `0xffc6a0f6` (Purple-*ish*), `0xff24273a` (Dark Purple), `0xff000000` (Transparent), `0xffe2e2e3` (Dirty White), `0xff494d64` (Semi-transparent Black), `0xff8839ef` (Party Purple), `0xff88c0d0` (Teal), `0xffe91e63` (Pink Reddish), `0xffe2e2e3` (Beige).

Alternatively, you may try these gradients: `active_color="gradient(top_left=0xffFF1493,bottom_right=0xff39FF14)"` (Pink → Green Combination), or apply glowing effect using `active_color="glow(0xffFF1493)"` which will add pink glowing effect as the borders.

{{< details "**Abstract Rainbows MacOS Wallpaper**" >}}
It's recommended to tweak JunkyBorder colors based on the wallpaper. Lets take a look at the following wallpaper that I use daily:
![](https://i.imgur.com/Qjo8fSL.jpeg)

We could configure JunkyBorder to have bright pink borders for focused window, and pink/blue gradient border for all inactive windows:
```
$ borders inactive_color="gradient(top_left=0xffFF1493,bottom_right=0xff2ab2dc)" active_color="glow(0xffFF1493)" width=8.0 hidpi=on
```

Alternatively, we could use this configuration settings within `~/config/borders/bordersrc` dotfile:
```
# ~/config/borders/bordersrc

#!/bin/bash
options=(
    width=8.0
    hidpi=on
    inactive_color="gradient(top_left=0xffFF1493,bottom_right=0xff2ab2dc)"
    active_color="glow(0xffFF1493)"
)

borders "${options[@]}"
```

Then start JunkyBorders via `brew services start borders`, or use `restart` if the service is already running. The resulting look is shown in image below (*click the image to open in full resolution*):

<a target="_blank" href="/posts/misc/screens/jankyborders_abstract-rainbow-results.png" style="text-decoration: none;" >{{< imgcap title="JunkyBorders - Crafting borders based on current wallpaper" src="/posts/misc/screens/jankyborders_abstract-rainbow-results.png" >}}</a>
{{</ details >}}

*JunkyBorder Config. & Running*

```
# start JunkyBorders and draw border highlighting the active window with RGBA(0xffe1e3e4), and inactive with RGBA(0xff494d64)
$ borders active_color=0xffe1e3e4 inactive_color=0xff494d64 width=5.0 style=round

# start JunkyBorders with 'hidpi' enabled (uses retina for rendering)
$ borders background_color=0xffc2c2c2 active_color=0xffe1e3e4 inactive_color=0xff494d64 width=5.0 style=round hidpi=on

# start JunkyBorders with gradient colored borders
$ borders style=round width=6.4 hidpi=on active_color="gradient(top_left=0xff8E83B8,bottom_right=0xffF8C8DC)" inactive_color=0xff494d64

$ start JunkyBorders with glowing colored borders
$ borders active_color="glow(0xffFF0000)" inactive_color=0x00000000 width=8.0

# @see: https://github.com/FelixKratz/JankyBorders/wiki/Man-Page
$ man borders
```

### Wallpapers, Screensavers & Desktops

- [WallpaperAccess.com](https://wallpaperaccess.com/)
- [wallhaven.cc](https://wallhaven.cc/)