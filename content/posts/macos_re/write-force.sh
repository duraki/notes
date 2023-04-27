#!/usr/bin/env bash

# defaults write com.apple.Safari NSToolbar\ Configuration\ BrowserStandaloneTabBarToolbarIdentifier -array
                                                                                                 # -array-add
# defaults write com.apple.Safari NSToolbar\ Configuration\ BrowserStandaloneTabBarToolbarIdentifier -array-add "{ ... }" >>
# where ary...
#    "TB Default Item Identifiers" =         {
#        "_CFURLString" = "CombinedSidebarTabGroupToolbarIdentifier";
#        "_CFURLString" = "SidebarSeparatorToolbarItemIdentifier";
#        "_CFURLString" = "BackForwardToolbarIdentifier";
#        "_CFURLString" = "NSToolbarFlexibleSpaceItem";
#        "_CFURLString" = "'"WebExtension-fr.frapps.SingleFile-Safari.Extension (FPM6D68GAR)"'";
#        "_CFURLString" = "'"WebExtension-4449XA862Y.com.giorgiocalderolla.Wipr-Mac.Wipr-Refresher.WiprBlockerMacExtra (4449XA862Y)"'";
#        "_CFURLString" = "'"WebExtension-com.one-tab.OneTab.Extension (444U6LQJ87)"'";
#        "_CFURLString" = "'"WebExtension-com.durakiconsulting.Shiori.Extension (UNSIGNED)"'";
#        "_CFURLString" = "PrivacyReportToolbarIdentifier";
#        "_CFURLString" = "InputFieldsToolbarIdentifier";
#        "_CFURLString" = "NSToolbarFlexibleSpaceItem";
#        "_CFURLString" = "ShowDownloadsToolbarIdentifier";
#        "_CFURLString" = "ShareToolbarIdentifier";
#        "_CFURLString" = "NewTabToolbarIdentifier";
#        "_CFURLString" = "TabPickerToolbarIdentifier";
#    };

#defaults write com.apple.Safari NSToolbar\ Configuration\ BrowserStandaloneTabBarToolbarIdentifier "(

#defaults write com.apple.Safari NSToolbar\ Configuration\ BrowserStandaloneTabBarToolbarIdentifier -array-add 'TB Default Item Identifier'
    # { "TB Default Item Identifier" }

#defaults write com.apple.Safari NSToolbar\ Configuration\ BrowserStandaloneTabBarToolbarIdentifier -array 'TB Default Item Identifier' ('CombinedSidebarTabGroupToolbarIdentifier' 'OtherValueHehe')

# reset + append
defaults write com.apple.Safari NSToolbar\ Configuration\ BrowserStandaloneTabBarToolbarIdentifier TB\ Item\ Identifiers\ -array
defaults write com.apple.Safari NSToolbar\ Configuration\ BrowserStandaloneTabBarToolbarIdentifier -array \
    '"TB Item Identifiers = { 'CombinedSidebarTabGroupToolbarIdentifier', 'SidebarSeparatorToolbarItemIdentifier', 'BackForwardToolbarIdentifier', 'NSToolbarFlexibleSpaceItem', 'PrivacyReportToolbarIdentifier', '"'WebExtension-fr.frapps.SingleFile-Safari.Extension (FPM6D68GAR)'"', '"'WebExtension-4449XA862Y.com.giorgiocalderolla.Wipr-Mac.Wipr-Refresher.WiprBlockerMacExtra (4449XA862Y)'"', '"'WebExtension-com.one-tab.OneTab.Extension (444U6LQJ87)'"', '"'WebExtension-com.durakiconsulting.Shiori.Extension (FPM6D68GAR)'"', '"'WebExtension-com.durakiconsulting.Shiori.Extension (UNSIGNED)'"', 'InputFieldsToolbarIdentifier', 'NSToolbarFlexibleSpaceItem', 'ShowDownloadsToolbarIdentifier', 'ShareToolbarIdentifier', 'NewTabToolbarIdentifier', 'TabPickerToolbarIdentifier' }"'
    
    printf "%s\n\n", "--------------------"
    defaults read com.apple.Safari NSToolbar\ Configuration\ BrowserStandaloneTabBarToolbarIdentifier
    printf "\nExit now %s\n", "1"
    exit

    # { "TB Default Item Identifier" }



# defaults write com.apple.Safari NSToolbar\ Configuration\ BrowserStandaloneTabBarToolbarIdentifier "'TB Default Item Identifiers' = (
#         CombinedSidebarTabGroupToolbarIdentifier,
#         SidebarSeparatorToolbarItemIdentifier,
#         BackForwardToolbarIdentifier,
#         NSToolbarFlexibleSpaceItem,
#         '\\'WebExtension-fr.frapps.SingleFile-Safari.Extension (FPM6D68GAR)\\'',
#         '\\'WebExtension-4449XA862Y.com.giorgiocalderolla.Wipr-Mac.Wipr-Refresher.WiprBlockerMacExtra (4449XA862Y)\\'',
#         '\\'WebExtension-com.one-tab.OneTab.Extension (444U6LQJ87)\\'',
#         '\\'WebExtension-com.durakiconsulting.Shiori.Extension (UNSIGNED)\\'',
#         PrivacyReportToolbarIdentifier,
#         InputFieldsToolbarIdentifier,
#         NSToolbarFlexibleSpaceItem,
#         ShowDownloadsToolbarIdentifier,
#         ShareToolbarIdentifier,
#         NewTabToolbarIdentifier,
#         TabPickerToolbarIdentifier
#     )"

#         'WebExtension-4449XA862Y.com.giorgiocalderolla.Wipr-Mac.Wipr-Refresher.WiprBlockerMacExtra (4449XA862Y)',
#        'WebExtension-com.one-tab.OneTab.Extension (444U6LQJ87)',
#        'WebExtension-com.durakiconsulting.Shiori.Extension (UNSIGNED)',


#     GUID = 1992394300;
# 	"tile-data" =         {
# 		book = <626f6f6b dc020000 00000410 30000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 fc010000 0c000000 01010000 4170706c 69636174 696f6e73 0b000000 01010000 4b65796e 6f74652e 61707000 08000000 01060000 04000000 18000000 08000000 04030000 8d010000 00000000 08000000 04030000 26b61100 00000000 08000000 01060000 3c000000 4c000000 08000000 00040000 41c0a51f 3d800000 18000000 01020000 02000000 00000000 0f000000 00000000 00000000 00000000 08000000 01090000 66696c65 3a2f2f2f 0c000000 01010000 536f6d61 63686967 756e4844 08000000 04030000 008088e0 2e000000 08000000 00040000 41c0bf74 ef2f0619 24000000 01010000 43353444 35374542 2d394543 352d3430 38452d39 4439412d 41423738 33363042 30314638 18000000 01020000 81000000 01000000 ef130000 01000000 00000000 00000000 01000000 01010000 2f000000 00000000 01050000 b3000000 01020000 30366334 31306166 63356334 30316632 31663265 63333463 36323036 61356166 31313533 34616233 3b30303b 30303030 30303030 3b303030 30303030 303b3030 30303030 30303b30 30303030 30303030 30303030 3032303b 636f6d2e 6170706c 652e6170 702d7361 6e64626f 782e7265 61642d77 72697465 3b30313b 30313030 30303036 3b303030 30303030 30303031 31623632 363b3031 3b2f6170 706c6963 6174696f 6e732f6b 65796e6f 74652e61 70700000 a8000000 feffffff 01000000 00000000 0d000000 04100000 2c000000 00000000 05100000 5c000000 00000000 10100000 7c000000 00000000 40100000 6c000000 00000000 02200000 2c010000 00000000 05200000 9c000000 00000000 10200000 ac000000 00000000 11200000 e0000000 00000000 12200000 c0000000 00000000 13200000 d0000000 00000000 20200000 0c010000 00000000 30200000 38010000 00000000 80f00000 40010000 00000000>;
# 		"bundle-identifier" = "com.apple.iWork.Keynote";
# 		"dock-extra" = 0;
# 		"file-data" =             {
# 			"_CFURLString" = "file:///Applications/Keynote.app/";
# 			"_CFURLStringType" = 15;
# 		};
# 		"file-label" = Keynote;
# 		"file-mod-date" = 216727672879174;
# 		"file-type" = 41;
# 		"parent-mod-date" = 259561381838519;
# 	};
# 	"tile-type" = "file-tile";
# }'
