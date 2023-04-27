---
title: "Safari Observations"
---

The newest Safari version running on MacOS Mojave (M1//Pro) does not allow unsigned extensions to be auto-loaded during Safari startup. Instead, you have to click `Develop => Allow Unsigned Extensions` which takes time, and after all, who'd remember to do this each startup. Bummers! I discovered this issue [when contributing this PR](https://github.com/go-shiori/shiori-web-ext/pull/43) to [go-shiori team](https://github.com/go-shiori/).

I tried simple things, such is rebuilding the extension (App) to use automatic signing for local development process. This [works partially](https://github.com/durakiconsulting/shiori-web-ext-safari/blob/build-_safari-ext/docs/safari.md), since you still have to enable the above noted option in Safari on launch. I also tried signing with a self-signed certificate created over Keychain Access, and similarly, I've tried to sign with my Developers Apple Certificate, but to no avail.

Part of my precious time was used to somehow enable Safari's `defaults` to include, or somehow bypass entitlements of the signed extension. I will post failures as well so I don't try same samples again.

```
$ xcrun security find-identity -v -p codesigning
# 1) ..... "Apple Development: <USER>"

$ xattr -cr Shiori.app
$ codesign --deep --force -s "<CERTIFICATE>" Shiori.app
```

This did nothing, basically, inside Safari it is still registered as *ad-hoc* signed binary app. And this is how I've tried to abuse `defaults` via sudo/tty Terminal shell:

```
$ defaults read com.apple.
com.apple.AMPDevicesAgent                                               com.apple.corespotlightui
com.apple.AMPLibraryAgent                                               com.apple.dataaccess.babysitter
# ...

$ defaults read com.apple.Safari
{
    AutoplayPolicyWhitelistConfigurationUpdateDate = "2023-04-19 16:16:44 +0000";
    AutoplayQuirksWhitelistConfigurationUpdateDate = "2023-04-19 16:16:44 +0000";
    CKPerBootTasks ...
# ... [large output] ...
```

Grepping the above output for `ext` resulted in this (stripped) output:

```
$ defaults read com.apple.Safari | grep -i ext
    ExtensionsEnabled = 1;
    LastExtensionSelectedInPreferences = "4D740136-593C-49B8-9B4E-A92AC8B5F000";
    LastSandboxFileExtensionMaintenanceDate = "2023-04-19 16:45:55 +0000";
    # ...
    "NSToolbar Configuration BrowserStandaloneTabBarToolbarIdentifier" =     {
        "TB Default Item Identifiers" =         (
            # ...
            "WebExtension-fr.frapps.SingleFile-Safari.Extension (FPM6D68GAR)",
            "WebExtension-4449XA862Y.com.giorgiocalderolla.Wipr-Mac.Wipr-Refresher.WiprBlockerMacExtra (4449XA862Y)",
            "WebExtension-com.one-tab.OneTab.Extension (444U6LQJ87)",
            "WebExtension-com.durakiconsulting.Shiori.Extension (UNSIGNED)",
            # ...
            
        "TB Item Identifiers" =         (
            # ...
            "WebExtension-4449XA862Y.com.giorgiocalderolla.Wipr-Mac.Wipr-Refresher.WiprBlockerMacExtra (4449XA862Y)",
            "WebExtension-com.one-tab.OneTab.Extension (444U6LQJ87)",
            "WebExtension-fr.frapps.SingleFile-Safari.Extension (FPM6D68GAR)",
            "WebExtension-com.durakiconsulting.Shiori.Extension (UNSIGNED)",
        # ...
    # ...
    OrderedToolbarItemIdentifiers =     (
        # ...
        "WebExtension-com.bonjourr.bonjourrStartpage.Extension (GZK4VLGQ5A)",
        "WebExtension-com.one-tab.OneTab.Extension (444U6LQJ87)",
        "WebExtension-fr.frapps.SingleFile-Safari.Extension (FPM6D68GAR)",
        "WebExtension-com.durakiconsulting.Shiori.Extension (UNSIGNED)",
        
    PreferencesModulesMinimumWidths =     {
        # ...
        MinimumWidths =         {
            # ...
            ExtensionsPreferences = 774;
            
    SkipLoadingEnabledAppExtensionsAtLaunch = 0;
    SkipLoadingEnabledWebExtensionsAtLaunch = 0;
```

There are few main components of Safari `defaults`:
* `com.apple.Safari`
* `SafariLaunchAgent`
* `com.apple.Safari.SafeBrowsing`
* `com.apple.Safari.PasswordBreachAgent`
* `com.apple.Safari.SandboxBroker`

... and a little less-known ones: `com.apple.SafariBookmarksSyncAgent`, and `com.apple.SafariCloudHistoryPushAgent`.

This is how I've tried to bypass Safari protection of unsigned extensions via `defaults`. First, take a backup of the current array container for the samples key:

```
$ defaults write com.apple.Safari OrderedToolbarItemIdentifiers
# ... save the output to a text file ...
```


```
        # Example for OrderedToolbarItemIdentifiers only

# This truncate/empty array container for key 'OrderedToolbarItemIdentifiers'
$ defaults write com.apple.Safari OrderedToolbarItemIdentifiers -array
$ defaults read com.apple.Safari OrderedToolbarItemIdentifiers    # => ()

# This rewrites array container for the specific key, and it tries to inject
# a valid signature into my own extension build.
$ defaults write com.apple.Safari OrderedToolbarItemIdentifiers "(
    CombinedSidebarTabGroupToolbarIdentifier,
    SidebarSeparatorToolbarItemIdentifier,
    BackForwardToolbarIdentifier,
    NSToolbarFlexibleSpaceItem,
    PrivacyReportToolbarIdentifier,
    'WebExtension-4449XA862Y.com.giorgiocalderolla.Wipr-Mac.Wipr-Refresher.WiprBlockerMacExtra (4449XA862Y)',
    'WebExtension-app.ajay.sponsor.SponsorBlock-for-YouTube.Extension (4449XA862Y)',
    'com.vitanov.Clean-Links-Extension (4BJWF2898T) Button',
    'WebExtension-com.sindresorhus.Refined-GitHub.Extension (YG56YK5RN5)',
    'WebExtension-com.bonjourr.bonjourrStartpage.Extension (GZK4VLGQ5A)',
    'WebExtension-com.one-tab.OneTab.Extension (444U6LQJ87)',
    'WebExtension-fr.frapps.SingleFile-Safari.Extension (FPM6D68GAR)',
    
        # Basically, I've tried to force-inject certificate signature of a notarized extension (FPM6D68GAR) 
        # into my own extension Bundler ID. I've set it to previous one since I knew this was clean signature.
    'WebExtension-com.durakiconsulting.Shiori.Extension (FPM6D68GAR)',
    
    InputFieldsToolbarIdentifier,
    NSToolbarFlexibleSpaceItem,
    ShareToolbarIdentifier,
    NewTabToolbarIdentifier,
    TabPickerToolbarIdentifier
)"

# We can confirm changes by reading the key again 
$ defaults read com.apple.Safari OrderedToolbarItemIdentifiers
```

Restarting Safari, clearing caches, destroying extension session from Safari preference did not help. I've turned out to last resort and a tad deeper analysis techniques. The below technique include personal notes during the Safari container analysis.

I've figured out that enabling "Allow Unsigned Extensions" from `Develop` menu in Safari must write this change somewhere (since the unsigned extension is automatically loaded). Below is how I've identified this flag writes/reads:

```
$ brew install fswatch         #% port install fswatch

# start fswatch command with -xr arg, indicating we want to see descriptive 
# changes, not internal syscall handlers. Sniffing file-change events in $HOME
# dir should be enough.

$ sudo fswatch -xr ~/
# ~/Library/Logs/TIDAL/player.log IsFile Updated
# ~/Library/Preferences/com.apple.xpc.activity2.plist IsFile Renamed
# ... leave it running ...
```

Once the file system monitor is running, from within Safari either disable/enable the "Allow Unsigned Extensions" from `Develop` menu. This should trigger an event related to Safari Extension internal flags, and it did:

```
    # [cont.]
# ~/Library/Containers/com.apple.Safari/Data/Library/Safari/WebExtensions/Extensions.plist OwnerModified IsFile Updated Renamed
# ~/Library/Containers/com.apple.Safari/Data/Library/Saved Application State/com.apple.Safari.savedState/windows.plist AttributeModified IsFile
```

We can repeat this process again to grab some more interesting file paths or identifiers that may aid us to progress further;

```
# ~/Library/IdentityServices/ids-pub-id.db AttributeModified IsFile Updated
# ~/Library/Containers/com.apple.Safari/Data/Library/Safari/WebExtensions/Extensions.plist IsFile Renamed
# ~/Library/Containers/com.apple.Safari
#     ./Data/Library/WebKit/WebsiteData/Default/<RAND_CONTAINER_STRCHAR>/<RAND_CONTAINER_STRCHAR>/
#     ./Data/Library/WebKit/WebsiteData
#     ...
# ...
```

The file `Extensions.plist` looks promising. Lets' see what is inside:

```
$ cd ~/Library/Containers/com.apple.Safari/Data/Library/Safari/AppExtensions
$ plutil -p Extensions.plist
# {
#  "com.charliemonroe.Downie-4-Downie-Extension (D43XN356JM)" => {
#    "AddedDate" => 2023-03-13 13:15:57 +0000
#  ...
# 
```

Well, I'll be damned 😤 This file contains only properly signed extensions that have been loaded in Safari. Here is a sample output for one of them:

```
# [cont.]
  # ...
  "com.ranchero.NetNewsWire-Evergreen.SubscribeToFeed (M8L2WTLA8W)" => {
    "AddedDate" => 2023-04-04 19:37:51 +0000
    "WebsiteAccess" => {
      "Allowed Domains" => [
      ]
      "Has Injected Content" => 1
      "Level" => "All"
    }
  },
  
  # ...
  "com.xxx.yyy" => {
      # ....
  },  
```

Luckly, I've identified exacto same file containing our unsigned extension, as shown below:

```
$ cd ~/Library/Containers/com.apple.Safari/Data/Library/Safari/WebExtensions
$ plutil -p Extensions.plist
# {
#  "4449XA862Y.com.giorgiocalderolla.Wipr-Mac.Wipr-Refresher.WiprBlockerMacExtra (4449XA862Y)" => {
#    "AccessibleOrigins" => [
#      0 => "<all_urls>"
#    ]
#    "AddedDate" => 2023-02-28 09:03:00 +0000
#    "Enabled" => 1
# ...
# 
#   
#
#           ... and here is our troublesome' extension ...
#
# "com.durakiconsulting.Shiori.Extension (UNSIGNED)" => {
#     "AccessibleOrigins" => [
#       0 => "<all_urls>"
#     ]
#     "AddedDate" => 2023-04-19 17:02:24 +0000
#     "Enabled" => 1
#     "EnabledByUserGesture" => 1
#     "EnabledModificationDate" => 2023-04-19 17:05:05 +0000
#     "GrantedPermissionOrigins" => {
#       "*://*/*" => 4001-01-01 00:00:00 +0000
#     }
#     "GrantedPermissions" => {
#     }
#     "HasAbilityToInjectContentIntoWebpages" => 1
#     "LastSeenBaseURI" => "safari-web-extension://D5198E77-0505-4990-845F-6320FCF2763D/"
#     "LastSeenUniqueIdentifier" => "CEB5FD95-202B-4F79-B235-CB8DD14E8DFE"
#     "LastSeenVersion" => "0.8.6"
#     "Permissions" => [
#       0 => "storage"
#       1 => "tabs"
#     ]
#     "RequestsTracking" => 0
#     "RevokedPermissionOrigins" => {
#     }
#     "RevokedPermissions" => {
#     }
#   }
```

But, looking further, I haven't really seen any difference between the signed extensions and a non-signed one, such is Shiori in this case. The only difference I'm seeing is related to folder naming convention difference, and otherwise, most of the keys are same. Intersting 🤔

Anyway, I've opened `WebExtensions/Extensions.plist` in Xcode Property List editor and added some more `Permissions` hoping it will fix the Safari.

```
#     "Permissions" => [
#       0 => "storage"
#       1 => "tabs"
#       2 => "contextMenus"
#       3 => "unlimitedStorage"
#       4 => "activeTab"
#     ]
```

Changes like those require you to duplicate original file (both for backup, and for haxoring):

```
$ cp WebExtensions/Extensions.plist /tmp/Extensions_Changes.plist
$ open /tmp/Extensions_Changes.plist
    
    "com.durakiconsulting.Shiori.Extension (FPM6D68GAR)" => {
        "Permissions" => [ ... ],

# File => Save or [CMD+S] and move it to REAL dir.
$ cp /tmp/Extensions_Changes.plist \
~/Library/Containers/com.apple.Safari/Data/Library/Safari/WebExtensions/Extensions.plist
```

Difference between enabled Shiori and disabled one, from the `Preferences => Extensions` tab:

```
    # Enable Shiori from Safari Extension List, then:
$ plutil -p ~/Library/Containers/com.apple.Safari/Data/Library/Preferences/com.apple.Safari.plist > /tmp/plist-enabled.txt

    # Disable Shiori from Safari Extension List, then:
$ plutil -p ~/Library/Containers/com.apple.Safari/Data/Library/Preferences/com.apple.Safari.plist > /tmp/plist-disabled.txt

# the diff. is rather minimal

$ md5sum /tmp/plist-*.txt
3d308e48c26008ce00d447756e672e14  /tmp/plist-enabled.txt
f7b5dd4985f3e7eb3f89b4a1239012fa  /tmp/plist-disabled.txt

$ git diff --no-index /tmp/plist-enabled.txt /tmp/plist-disabled.txt
-  "WBSDateOfLastSaveOfCurrentCloudExtensionDevice" => 2023-04-19 20:19:07 +0000
+  "WBSDateOfLastSaveOfCurrentCloudExtensionDevice" => 2023-04-19 20:15:07 +0000
```

Only 'update' flag has been dispatched. We will try same trick with Safari' defaults as well;

```
    # Disable Unsigned Extensions from Safari, then:
$ plutil -p /Users/hduraki/Library/Containers/com.apple.Safari/Data/Library/Preferences/com.apple.Safari.plist > /tmp/com.apple.Safari.plist.disabled

    # Enable Unsigned Extensions from Safari, then:
$ plutil -p /Users/hduraki/Library/Containers/com.apple.Safari/Data/Library/Preferences/com.apple.Safari.plist > /tmp/com.apple.Safari.plist.enabled

$ git diff --no-index /tmp/com.apple.Safari.plist.disabled /tmp/com.apple.Safari.plist.enabled
index ff50c92..551f282 100644
--- a/tmp/com.apple.Safari.plist.disabled
+++ b/tmp/com.apple.Safari.plist.enabled
@@ -146,12 +146,13 @@
       5 => "WebExtension-4449XA862Y.com.giorgiocalderolla.Wipr-Mac.Wipr-Refresher.WiprBlockerMacExtra (4449XA862Y)"
       6 => "WebExtension-com.one-tab.OneTab.Extension (444U6LQJ87)"
       7 => "WebExtension-fr.frapps.SingleFile-Safari.Extension (FPM6D68GAR)"
-      8 => "InputFieldsToolbarIdentifier"
-      9 => "NSToolbarFlexibleSpaceItem"
-      10 => "ShowDownloadsToolbarIdentifier"
-      11 => "ShareToolbarIdentifier"
-      12 => "NewTabToolbarIdentifier"
-      13 => "TabPickerToolbarIdentifier"
+      8 => "WebExtension-com.durakiconsulting.Shiori.Extension (UNSIGNED)"
+      9 => "InputFieldsToolbarIdentifier"
+      10 => "NSToolbarFlexibleSpaceItem"
+      11 => "ShowDownloadsToolbarIdentifier"
+      12 => "ShareToolbarIdentifier"
+      13 => "NewTabToolbarIdentifier"
+      14 => "TabPickerToolbarIdentifier"
     ]
     "TB Size Mode" => 1
```

Aha! Here is some `diff` that makes more sense. We can see that my unsigned extension is being loaded at one moment; basically, the above diff indicates that new extension is added (firstout-shfited to top). We can try searching for this entry in the `defaults` and hope that hardcoding it will bypass unsigned extension loader.

Comparing the key identifier against the known one (there are many `NSToolbarFlexibleSpaceItem` which I took as a reference in default plist), we can conclude the appending is executed in:

```
# .. diff resume ..

# BrowserStandaloneTabBarToolbarIdentifier contains the extension identifier by default. No Changes.
    "NSToolbar Configuration BrowserStandaloneTabBarToolbarIdentifier" => {
    "TB Default Item Identifiers" => [
      # ...
      7 => "WebExtension-com.durakiconsulting.Shiori.Extension (UNSIGNED)"
      8 => "PrivacyReportToolbarIdentifier"
      9 => "InputFieldsToolbarIdentifier"
      10 => "NSToolbarFlexibleSpaceItem"
      11 => "ShowDownloadsToolbarIdentifier"
      12 => "ShareToolbarIdentifier"
      13 => "NewTabToolbarIdentifier"
      14 => "TabPickerToolbarIdentifier"
    ]
    # ...
 
# (BrowserStandaloneTabBarToolbarIdentifier)TB Item Identifiers doest NOT contains the extension identifier by default.
# This array just extends from the top-level identifier (@see above), but it's in a separate key.
# 
# We will use this entrypoint to force this Toolbar Item directly in Safari. Refer to start of this notes to understand 
# how we will manage to do this via 'defaults write *' command. 
    "TB Item Identifiers" => [
      0 => "CombinedSidebarTabGroupToolbarIdentifier"
      1 => "SidebarSeparatorToolbarItemIdentifier"
      2 => "BackForwardToolbarIdentifier"
      3 => "NSToolbarFlexibleSpaceItem"
      4 => "PrivacyReportToolbarIdentifier"
      5 => "WebExtension-4449XA862Y.com.giorgiocalderolla.Wipr-Mac.Wipr-Refresher.WiprBlockerMacExtra (4449XA862Y)"
      6 => "WebExtension-com.one-tab.OneTab.Extension (444U6LQJ87)"
      7 => "WebExtension-fr.frapps.SingleFile-Safari.Extension (FPM6D68GAR)"
      8 => "WebExtension-com.durakiconsulting.Shiori.Extension (UNSIGNED)"
      9 => "InputFieldsToolbarIdentifier"
      10 => "NSToolbarFlexibleSpaceItem"
      11 => "ShowDownloadsToolbarIdentifier"
      12 => "ShareToolbarIdentifier"
      13 => "NewTabToolbarIdentifier"
      14 => "TabPickerToolbarIdentifier"
    ]
    # ...

# OrderedToolbarItemIdentifiers contains the extension identifier by default. No Changes.
    "OrderedToolbarItemIdentifiers" => [
      0 => "CombinedSidebarTabGroupToolbarIdentifier"
      1 => "SidebarSeparatorToolbarItemIdentifier"
      2 => "BackForwardToolbarIdentifier"
      3 => "NSToolbarFlexibleSpaceItem"
      4 => "PrivacyReportToolbarIdentifier"
      5 => "WebExtension-4449XA862Y.com.giorgiocalderolla.Wipr-Mac.Wipr-Refresher.WiprBlockerMacExtra (4449XA862Y)"
      6 => "WebExtension-app.ajay.sponsor.SponsorBlock-for-YouTube.Extension (4449XA862Y)"
      7 => "com.vitanov.Clean-Links-Extension (4BJWF2898T) Button"
      8 => "WebExtension-com.sindresorhus.Refined-GitHub.Extension (YG56YK5RN5)"
      9 => "WebExtension-com.bonjourr.bonjourrStartpage.Extension (GZK4VLGQ5A)"
      10 => "WebExtension-com.one-tab.OneTab.Extension (444U6LQJ87)"
      11 => "WebExtension-fr.frapps.SingleFile-Safari.Extension (FPM6D68GAR)"
      12 => "WebExtension-com.durakiconsulting.Shiori.Extension (FPM6D68GAR)"
      13 => "WebExtension-com.durakiconsulting.Shiori.Extension (UNSIGNED)"
      14 => "InputFieldsToolbarIdentifier"
      15 => "NSToolbarFlexibleSpaceItem"
      16 => "ShowDownloadsToolbarIdentifier"
      17 => "ShareToolbarIdentifier"
      18 => "NewTabToolbarIdentifier"
      19 => "TabPickerToolbarIdentifier"
    ]
    # ...
```

Force command-line default writes to Safari:

```
$ defaults read com.apple.Safari NSToolbar\ Configuration\ BrowserStandaloneTabBarToolbarIdentifier
{
    "TB Default Item Identifiers" =     ( }
    "TB Display Mode" = 2;
    "TB Icon Size Mode" = 1;
    "TB Is Shown" = 1;
    "TB Item Identifiers" =     (
        # ... we will insert here ...
    },
    
# ...

$ defaults write com.apple.Safari NSToolbar\ Configuration\ BrowserStandaloneTabBarToolbarIdentifier "{ "TB Default Item Identifiers" = {  } }"
```

```
$ defaults write com.apple.Safari OrderedToolbarItemIdentifiers "(
    CombinedSidebarTabGroupToolbarIdentifier,
    SidebarSeparatorToolbarItemIdentifier,
    BackForwardToolbarIdentifier,
    NSToolbarFlexibleSpaceItem,
    PrivacyReportToolbarIdentifier,
    'WebExtension-4449XA862Y.com.giorgiocalderolla.Wipr-Mac.Wipr-Refresher.WiprBlockerMacExtra (4449XA862Y)',
    'WebExtension-app.ajay.sponsor.SponsorBlock-for-YouTube.Extension (4449XA862Y)',
    'com.vitanov.Clean-Links-Extension (4BJWF2898T) Button',
    'WebExtension-com.sindresorhus.Refined-GitHub.Extension (YG56YK5RN5)',
    'WebExtension-com.bonjourr.bonjourrStartpage.Extension (GZK4VLGQ5A)',
    'WebExtension-com.one-tab.OneTab.Extension (444U6LQJ87)',
    'WebExtension-fr.frapps.SingleFile-Safari.Extension (FPM6D68GAR)',
    
        # Basically, I've tried to force-inject certificate signature of a notarized extension (FPM6D68GAR) 
        # into my own extension Bundler ID. I've set it to previous one since I knew this was clean signature.
    'WebExtension-com.durakiconsulting.Shiori.Extension (FPM6D68GAR)',
    
    InputFieldsToolbarIdentifier,
    NSToolbarFlexibleSpaceItem,
    ShareToolbarIdentifier,
    NewTabToolbarIdentifier,
    TabPickerToolbarIdentifier
)"
```
