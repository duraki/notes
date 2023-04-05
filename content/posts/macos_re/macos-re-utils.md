---
title: "macOS Metadata Extraction"
---

# Metadata Attributes

Metadata attributes can be used to investigate details about binary, blob or file within OSX/MacOS.

When you request the metadata for a specific file through the Spotlight API, information is gathered from a number of places, and passed to the program `mdls`, responding in a uniform format.

These sources are for example:

* The file system meta data
* The extended attributes stored in the file system
* Information from Application bundles and similar places
* Information gathered by the Spotlight importer plugin for the specific file type

### mdls

The OSX utility `mdls` can be used to list the metadata attributes for a specified file. The mdls command prints the values of all the metadata attributes associated with the files provided as an argument.

```
$ mdls [-s] [FILEPATH]
```

The output of the command is rather large. Here is an example using it on random app. on MacOS:

```
$ mdls /Applications/WhatsApp.app | head

_kMDItemDisplayNameWithExtensions       = "WhatsApp.app"
_kMDItemEngagementData                  = {length = 21, bytes = 0x0900000080f2e1c441000201030402050204060108}
kMDItemAlternateNames                   = (
    "WhatsApp.app"
)
kMDItemAppStoreAdamID                   = 1147396723
kMDItemAppStoreCategory                 = "Social Networking"
kMDItemAppStoreCategoryType             = "public.app-category.social-networking"
kMDItemAppStoreHasReceipt               = 1
kMDItemAppStoreInstallerVersionID       = "855549715"
# ...
```

Alterantively, pass the `-s` argument to enlarge verbosity of the output (albeit, not as pretty):

```
$ mdls -s /Applications/WhatsApp.app | head

_kMDItemSDBInfo = "kMDItemAppStoreReceiptIsVPPLicensed" = 0;
"kMDItemAppStorePurchaseDate" = 2023-03-17 12:28:50 +0000;
"kMDItemLogicalSize" = 304152538;
# ...
```

Metadata can be extracted for each of the `FILEPATH`, whichever file data it might be (ie. binary, images, blobs ...).-

```
$ mdls ~/Documents/XXX_SomePortableDocumentFormat.pdf
_kMDItemDisplayNameWithExtensions  = "XXX_SomePortableDocumentFormat.pdf"
kMDItemAlternateNames              = (
    "XXX_SomePortableDocumentFormat.pdf"
)
kMDItemContentCreationDate         = 2023-03-15 15:10:13 +0000
kMDItemContentCreationDate_Ranking = 2023-03-15 00:00:00 +0000
kMDItemContentModificationDate     = 2023-03-15 15:10:13 +0000
kMDItemContentType                 = "com.adobe.pdf"
...
```

### mdfind

This utility can be used to search and finds files matching a given query, based on Spotlight's metadata database.

```
# => find in all contents containing query "image"
$ mdfind image

# => find in DIR contents containing QUERY
$ mdfind -onlyin <DIR> <QUERY>
```

### mdutil & mdimport

Internal tool used to configure or work with Spotlight API directly, manage the metadata stores used by Spotlight and so on.

```
$ mdutil [ARGS]
```

Similarly, there is `mdimport` which imports file hierarchies into the metadata datastore. This offers importing metadata into attributes for specific Spotlight attributes.

```
$ mdimport [ARGS]
```
