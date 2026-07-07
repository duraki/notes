---
title: "Configure LLDB on M1/M2"
---

Table of Contents:
* Prepare MacOS to use Python 3
* Setup LLDB to use Python 3 by default
* Setup LLDB to use *snare's* [voltron](https://github.com/snare/voltron/) UI

**Prepare MacOS to prefer Python 3**

```
$ brew unlink python
$ brew install python@3.11          # or any other version
$ brew link --force python@3.11
```

Use this time to prepare and confirm everything is working correctly; ie. `pip`, & `python`. Using `brew` again, we can gather some information:

```
$ brew info python
# ...
Python has been installed as
  /opt/homebrew/bin/python3

You can install Python packages with
  pip3 install <package>
# packages will be installed in:
#   /opt/homebrew/lib/python3.11/site-packages

# @see: https://docs.brew.sh/Homebrew-and-Python
```

Add the Python's binary toolsets in environment PATH, like so:

```
$ vim ~/.zshrc

## add:
# export PATH="$(brew --prefix)/opt/python@3.11/libexec/bin:$PATH"
```

The above output path can be found via `brew info` command. The symlinking will **NOT** be automatically handled;

```
$ ls -l /usr/bin/python*
-rwxr-xr-x  76 root  wheel  167136 Feb  9 10:39 /usr/bin/python3
```

Lets symlink our new Python 3.11 to system's path. This will force system to use `python3.11` when passing `python3` or `python` in Terminal CLI.

```
$ ln -s -f /usr/bin/python3 /opt/homebrew/bin/python3.11
$ ln -s -f /usr/bin/python /opt/homebrew/bin/python3.11
```

**Important**, also sync the Python to the MacOS framework's and XCode:

```
$ sudo mkdir /usr/local/Frameworks
$ sudo chown $USER /usr/local/Frameworks
$ xcode-select -p
## /Applications/Xcode.app/Contents/Developer
$ sudo ln -s /opt/homebrew/opt/python@3.11/bin/python3.11 /Applications/Xcode.app/Contents/Developer/usr/bin/python3
$ sudo ln -s /opt/homebrew/opt/python@3.11/bin/python3.11 /Applications/Xcode.app/Contents/Developer/usr/bin/python

# finally, relink everything
$ brew unlink python@3.11 && brew link python@3.11
```

This will solve typical XCode's pop-up where it asks you to install Developers Command Line Tools.

```
$ python
Python 3.11.2 (main, Feb 16 2023, 02:55:59) [Clang 14.0.0 (clang-1400.0.29.202)] on darwin
>>>
```

**Prepare LLDB Python Version**

On macOS, LLDB (and GDB) are linked against MacOS default Python version, so Voltron must be installed using this version of Python. A possible workaround is to force default's `com.apple.dt.lldb` Python key, to correspond to version 3.

This will obligate LLDB to use Python 3 by default; meaning all Python scripts, plugins and other providers during lldb usage will be powered by Python 3.

```
#          replace "write" w/ "read" to get the DefaultPythonVersion
#
$ defaults write com.apple.dt.lldb DefaultPythonVersion 3
```

**Setup LLDB to use Voltron**

After completing above steps; install Voltron UI as a Python3 module, via pip. Make sure to install voltron to `user-centric` environment.

```
#           where pip3 == /opt/homebrew/lib/python3.11/site-packages/pip
$ pip3 install voltron
# Successfully installed ...
```

or via Git repository;

```
$ cd ~/.config && git clone https://github.com/snare/voltron
$ ./install.sh -s
        # using -s installs voltron in system-wide dir.
```

The output is:

```
Installed for LLDB (/opt/homebrew/opt/llvm/bin/lldb):
  Python:             /opt/homebrew/opt/python@3.11/Frameworks/Python.framework/Versions/3.11/bin/python3.11
  Packages directory: /opt/homebrew/opt/python@3.11/Frameworks/Python.framework/Versions/3.11/lib/python3.11/site-packages
  Added voltron to:   /Users/$USER/.lldbinit
  Entry point:        /opt/homebrew/opt/python@3.11/Frameworks/Python.framework/Versions/3.11/lib/python3.11/site-packages/voltron/entry.py
```

**But, wait!** There seems to be two multiple versions of `lldb`, one from the OS and the other from Homebrew; although they both are version 15.0.7, there seems to be a hash missmatch.

```
$ shasum /opt/homebrew/opt/llvm/bin/lldb /usr/bin/lldb
c45c4e6098ab0d648d5f43a4e58b837f30fc80dc  /opt/homebrew/opt/llvm/bin/lldb
a96c93b07b616a03bf1dfef57b81a19b603f921e  /usr/bin/lldb
```

The **main difference** is that the *lldb provided by the MacOS* **is** already **signed and usable** on most targets, without needing to disable SIP or append special entitlements. On other hand, the *brew's lldb* might be **signed by** those whom published the **formulae** on the homebrews repository, therefore, not being notarized for all targets.

Open up your `~/.lldbinit` and import newely installed Voltron module, like so:

```
$ vim ~/.lldbinit

## add:
script import voltron
command script import /opt/homebrew/Cellar/python@3.11/3.11.2_1/Frameworks/Python.framework/Versions/3.11/lib/python3.11/site-packages/voltron/entry.py
```

After completing all steps, try launching `lldb`. The REPL output should look like this:

```
$ lldb /tmp/ls
# Voltron loaded.
# ...
```

Refer to [Voltron](https://github.com/snare/voltron) official documentation for more details about usage and customisation. Below is author's debug environment for showoff.

{{< imgcap title="Author's LLDB Configuration - Using Tmux, iTerm and lldb" src="/posts/images/lldb-m1.png" >}}
