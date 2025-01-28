---
title: "Download IPA on macOS"
url: "/download-ipa-on-macos"
---

# Via iOS (iPhone)

See [Decrypt IPA from AppStore](/decrypt-ipa-from-appstore) notes for details, or use `dumpdecrypt`.

# Via MacOS (Mac)

Downloading IPA from the AppStore is possible on macOS as well, thanks to the [majd/ipatool](https://github.com/majd/ipatool). The process of decrypting these binaries is explained under separate note - [decrypt IPA from AppStore (macOS)](/decrypt-ipa-from-appstore#macOS) but the results are not tested.

## Setting up & Using `ipatool` on macOS

The `ipatool` is an open-source utility developed by [majd](https://github.com/majd) which allows users to download IPA files directly from the AppStore.

{{< notice >}}
Important Errata
{{< /notice >}}
{{< callout emoji="⚠️" text="If you have XCode installed on your macOS - installing `ipatool` via `brew` won't work. There is another `ipatool` binary provided by XCode which might be confirmed using the command `which ipatool`. Instead, it's recommended to visit [Releases](https://github.com/majd/ipatool/releases) section of the GitHub repository, and downloading latest release builds for the `ipatool`." >}}

**Building `ipatool` from GitHub Repository**

This is a proven way to use latest updates of the `ipatool`, since the [Releases](https://github.com/majd/ipatool/releases) version have long been outdated, although the new updates and commmits exists.

To build `ipatool`, clone the repository first, build it, and then follow the next instructions. Ofcourse, make sure to have [GoLang](https://go.dev/doc/install) toolchain installed on your HostOS to be able to compile the codebase.

```sh
$ cd ~/utils/clone
$ git clone git@github.com:majd/ipatool.git
$ cd ipatool
$ go build -o ipatool-dl
# go: downloading github.com/juju/persistent-cookiejar v1.0.0
# go: downloading github.com/avast/retry-go v3.0.0+incompatible
# go: downloading github.com/99designs/keyring v1.2.1

$ file ipatool-dl
# ipatool-dl: Mach-O 64-bit executable arm64
```

**Installing the `ipatool` to `$PATH`-registered directory**

Lets move this `ipatool` binary to any directory, preferably to that which is inside your `$PATH` environment variable. On my macOS M1, I have `~/.config/bin/` directory configured and set in `$PATH` so I will move the newly built `ipatool-dl` to it:

```sh
$ cp ipatool-dl ~/.config/bin/ipatool-dl
$ chmod +x ~/.config/bin/ipatool-dl
```

Note that I've copied `ipatool-dl` binary in one of my `$PATH` directory - this is **important** since I already have XCode's `ipatool` in my executable paths. Using the `chmod +x` we've set the binary flag as executable, making sure it can be executed.

**Login to AppleID via `ipatool`**

The `ipatool` from [majd](https://github.com/majd) requires an AppleID account, and we must sign-in using the `ipatool auth login` command:

```sh
$ ipatool-dl auth login -e user@example.com
# 12:52PM INF enter password: <password>
# 12:52PM INF enter 2FA code: XXXXXX
# 12:52PM INF email= name=" " success=true
```

With that, we are logged in to AppStore and the `ipatool` appends the authentication item in the Keychain Access app. Use the `ipatool auth info` comamnd to show information about current account:

```sh
$ ipatool-dl auth info
# 3:01PM INF email=<user@example.com> name="<Full Name>" success=true
```

**Using the `ipatool` to Search in AppStore**

If we try to use `ipatool search` command which expects a search string argument, it should show list of apps that have been found in the AppStore for the given name:

```sh
$ ipatool-dl search "SMS Forwarder"
# 12:57PM INF apps=[{"bundleID":"tsubasa-technologies.Forward-OTP","id":6693285061,"name":"SMS Forwarder: Forward SMS","price":0,"version":"1.8.4"}] ... count=1
```

It's also possible to combine the `--format json` option with tools such is [`jq`](), showing the list of apps more clearly, like so:;

```sh
$ ipatool-dl search "SMS Forwarder" --format json | jq                      # format output to JSON and pipe to 'jq'
# {
#   "level": "info",
#   "count": 5,
#   "apps": [
#     {
#       "id": 6738728448,
#       "bundleID": "com.blw.DemoIntents1",
#       "name": "SMS Forwarder!",
#       "version": "1.1",
#       "price": 0
#     },
#     // ...
#   ],
#   "time": "2025-01-20T15:05:00+01:00"
# }

$ ipatool-dl search "SMS Forwarder" --format json | jq '.apps[].bundleID'       # output only bundleID from the array
# "studio.panikka.ForwardSMS"
# ...

$ ipatool-dl search "SMS Forwarder" --format json | jq -r '.apps[].bundleID'    # using '-r' to output without quotes
# studio.panikka.ForwardSMS
# ...
```

**Downloading *(encrypted)* IPA via `ipatool` from AppStore**

There is a bug when downloading `IPA` from the AppStore which doesn't properly *purchase* the application license first, resulting in an error, even if the application is free to download. This happens if the IPA you are trying to download did not 'purchase license' first, and due to the bug in `ipatool purchase` command, the flow is broken.

Lets take a look at the following example, which shows the Moonshot app. for iPhone in the AppStore.

{{< imgcap title="AppStore - iPhone 'Moonshot' app" src="/posts/images/appstore_iphoneapp.png" >}}

{{< notice >}}
Helpful Tip
{{< /notice >}}
{{< callout emoji="💡" text="You can search for iPhone apps on [fnd.io](https://www.fnd.io/#/us/charts/iphone/top-free/all) since the MacOS AppStore does not support searching for iPhone apps natively. The [fnd.io](https://www.fnd.io/) is an alternative to AppStore which allows filtering based on country, device, and much more." >}}

If we try to use `ipatool` to search and download this app. it will result in unexpected error, as shown below:

```sh
# First we need to search for the app. by it's name
$ ipatool-dl search "Moonshot" --format json | jq '.apps'
# [
#   {
#     "id": 6503993131,
#     "bundleID": "money.moonshot.app",
#     "name": "Moonshot",
#     "version": "1.4.5",
#     "price": 0
#   },
#   // ...
# ]

# Lets try to download the app.
$ ipatool-dl download -b "money.moonshot.app" --purchase
# downloading 0% |                                                    | ( 0/ 1 B) 
# 3:30PM ERR error="failed to purchase item with param 'STDQ': failed to purchase app" success=false
```

As you can see, the *purchase* of the application license failed due to the bug in `ipatool`. You may append `--verbose` argument to the `ipatool download` command which will spit more information on why it failed.

To workaround this bug, we must first initiate the *purchase* from the AppStore itself using the **Get** button, indicated by the **#1** in screenshot below.

{{< imgcap title="AppStore - Purchase License (1)" src="/posts/images/appstore_iphoneapp_numbering.png" >}}

Click the **Get** button only once, which will then change itself to **Install** button. 

{{< imgcap title="AppStore - Purchase License (2)" src="/posts/images/appstore_getlicense.gif" >}}

Now click the **Install** button once it's shown authenticate to AppStore via TouchID as requested, ie. *when you receive the following modal window popup*:

{{< imgcap title="AppStore - TouchID Required by AppStore" src="/posts/images/appstore_touchid.png" >}}

Once the application is installed on your macOS, move back to Terminal and execute the `ipatool download` command again as shown in previous example:

```sh
$ ipatool-dl download -b money.moonshot.app --purchase
# 3:44PM INF output=money.moonshot.app_6503993131_1.4.5.ipa success=true
```

The IPA should now be downloaded correctly in current working directory. It's also possible to pass an output directory argument using `-o` which indicates where the `*.ipa` should be downloaded to; and similarly, the `-i` (*AppStore - App ID*) argument can be used instead of `-b` (*AppStore - App Bundle Identifier*):

```sh
#       This would download *.ipa to /tmp/ directory, using the AppID instead of BundleID
#       Note that the downloaded IPA has filename "[ID].ipa" making it harder to identify.
$ ipatool-dl dowload -i 6503993131 -o /tmp/
# 4:43PM INF output=/tmp//6503993131.ipa success=true
```

Once the IPA has been downloaded, use a free tools such is [AppCleaner](https://freemacsoft.net/appcleaner/) to remove the installed application from the macOS. There is a CLI alternative to do the same called [unistall-cli.sh](https://gist.githubusercontent.com/duraki/9dd16becf7676b352ca68eb84dcedfaa/raw/bbd54927adf5f00ee0c6feec7816520dec75b193/uninstall-app.sh) which can be installed using:

```sh
$ wget -O$HOME/.config/bin/uninstall-app https://gist.githubusercontent.com/duraki/9dd16becf7676b352ca68eb84dcedfaa/raw/bbd54927adf5f00ee0c6feec7816520dec75b193/uninstall-app.sh
$ chmod +x ~/.config/bin/uninstall-app

# To use it, simply run
$ uninstall-app /Applications/AppName.app
```

### References

* [Apple AppStore Webpage](https://www.apple.com/app-store/)
* [Search in AppStore via `fnd.io`](https://www.fnd.io)
* IPA Online Hosted Libraries:
  * [iosvizor.com](https://iosvizor.com)
  * [ipauniverse.com](https://www.ipauniverse.com)
  * [ipaomtk.com](https://ipaomtk.com/)
  * archive.org: [`ios-ipa-collection`](https://archive.org/download/ios-ipa-collection), [ios-clutch-ipa-collection](https://archive.org/download/com.apple.mobilegarageband-ios5.1-clutch-2.0.4), [big-fat-ios-ipa-collection](https://archive.org/download/big-fat-ios-ipa-collection), [The IPA Software Archive](https://archive.org/details/ipaarchive)