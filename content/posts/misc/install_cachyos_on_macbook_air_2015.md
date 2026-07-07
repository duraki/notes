Boot Manager ->


# Preparation

## Extract WiFi Firmware

While in MacOS Yosemite, type the following:

```
$ sudo mkdir -p /usr/share/firmware
$ sudo su
$ curl -sL https://wiki.t2linux.org/tools/firmware.sh | bash -s copy_to_efi


# Mounting the EFI partition
# Volume EFI on disk0s1 mounte
# Getting Wi-Fi an d Bluetooth firmware
# Copying this script to EFI
# Volume EFI on disk0s1 unmounted
#
# Run the following commands or run this script itself in Linux now to set up Wi-Fi:
#
# sudo mkdir -p /tmp/apple-wifi-efi
# sudo mount /dev/nvme0n1p1 /tmp/apple-wifi-efi
# bash /tmp/apple-wifi-efi/firmware.sh
# sudo umount /tmp/apple-wifi-efi
```

## Disk Preparation

### Preparing disk for dual-boot

If you want to dual-boot, follow the instructions shown [here](https://wiki.cachyos.org/installation/installation_t2macbook/#prepare-your-disk).

### Preparing disk without dual-boot

If you want CachyOS to live as a single OS on your Macbook, no further requirements are needed. Proceed with steps below.

## Disable Secure Boot

> Note: **Required only for [Mac's with Apple T2 Security Chip](https://support.apple.com/en-in/103265!** The Apple T2 Security chip is introduced in models from 2018 and upwards. Since this setup is for Macbook Air 2015, **this step is not required** per se.

1. Reboot your Mac and hold `CMD+R` immediately after powering on to enter "Recovery Mode"
2. Go to "Utilities > Startup Security Utility" using menubar
3. Select "No Security" under **Secure Boot**
4. Select "Allow booting form external or removable media" under **Allowed Boot Media**

Refer to [Apple’s guide on Startup Security](https://support.apple.com/en-in/102522) Utility for more details.

## Installation Process

### Preparation

Ensure you have Ethernet Network Connection either by sharing it from another Mac, or by plugging Ethernet adapter on the thunderbolt port and connecting an Ethernet cable to your network modem/switch. This must be done **before booting the CacyOS** over the USB shown below. Otherwise, if you plug the ethernet dongle adapter in Macbook's thunderbolt after the live environment has been booted, the kernel module for the adapter adapter won't register it, therefore the automatic network setup will fail to create a DHCP connection. If you happened to experience this, attach the wired ethernet adapter in your Macbook air and then reboot the CachyOS from the USB again.

If you don't have ethernet, use steps described for Wi-Fi in other parts of this document.

### 1. Boot from CachyOS USB

1. Restart your Mac and hold the `Option (⌥)` key immediately after powering on.
2. Enter `216445` if asked for boot selection PIN/Passcode
2. Select the CachyOS USB drive (usually labeled as “EFI Boot”).
4. Select the "CatchyOS" from the CatchyOS Live ISO (UEFI) menu
5. Wait for the CacyOS live environment to load

### 2. (Optional) Enable Wi-Fi in the Live Environment

1. If you need Wi-Fi during installation (ie. you have no ethernet/tethering alternative), open the terminal once the CacyOS live environment loads
2. Run these commands to copy tthe firmware from the EFI partition (as described in [Extract WiFi Firmware](#extract-wifi-firmware)) and configure the NetworkManager

```sh
# Mount the EFI partition (usually nvme0n1p1 on T2 Macs)
sudo mkdir -p /tmp/apple-wifi-efi
sudo mount /dev/nvme0n1p1 /tmp/apple-wifi-efi

# Copy firmware from EFI to the live environment
bash /tmp/apple-wifi-efi/firmware.sh get_from_efi
sudo umount /tmp/apple-wifi-efi

# Configure NetworkManager to use iwd backend(
cat <<EOF | sudo tee /etc/NetworkManager/conf.d/wifi_backend.conf
[device]
wifi.backend=iwd
EOF
sudo systemctl restart NetworkManager
```

You should now be able to connect to Wi-Fi networks using the network applet in the system tray.

### 3. Run the CachyOS Installer

1. From the start menu, find the "CachyOS Hello" application if its not started automatically. Click the "Launch installer" button in the "CachyOS Hello" app.
2. Select the Bootloader/Edition when asked, for example - we will use `systemd-boot (Default)` in this case
3. Once CacyOS Installer window is shown; use the following options:
	- **Welcome**: Leave language as "American English", click **Next**
	- **Location**: Set "Region" to *Europe*, and "Zone" to *Sarajevo*, click **Next**
	- **Keyboard**: Keyboard Model -> 'Apple', 'Croatian', 'Croatian (US)', click **Next**
	- **Partitions**:
		- Select "APPLE SSD SM0128G - (/dev/sda)" in Storage Device
		- Select "Erease disk" to delete all data currently present on the selected storage, and pick the filesystem
			- Choose "btrfs" (recommended for users who want snapshot/backup functionality and transparent compression)
			- Choose "ext4" (commonly used Linux filesystem, reliable, may lack advanced features other filesystems offer)
			- **TL;DR:** Use the default filesystem BTRFS as it is considered stable and has a lot of neat features (snapshots, compression, etc). Use XFS or EXT4 for a simple and fast filesystem for lower-end PCs.
		- We will **select "ext4"** since we dont need advanced functionalities and we are more familiar with it
		- Make sure to **uncheck** the "Encrypt system" option
		- Click **Next** to continue formatting the disk for the CachyOS installation
	- **Desktop**: Pick a Desktop Environment of your choice. CachyOS offers several desktop environments for you to choose from. This decision is based on personal preference. Pick one that you like the most.
		- Screenshots of available DE are shown [here](https://wiki.cachyos.org/installation/screenshots/)
		- [XFCE](https://wiki.cachyos.org/installation/screenshots/#xfce), [LXDE](https://wiki.cachyos.org/installation/screenshots/#lxde), [Cinnamon](https://wiki.cachyos.org/installation/screenshots/#cinnamon) are easy on the resource, [Hyperland](https://wiki.cachyos.org/installation/screenshots/#hyprland) is quite nice but unstable and might require more resoruces
		- We will **select "Hyprland"** to test it out
		- Click **Next** to continue picking *Packages*
	- **Packages**: Click **Next** if nothing else is required to install additionally (ie. printing support etc.)
	- **Users**: Set your name, username, computer name, and passsword
		- Halis Duraki
		- hduraki
		- nix ([ie. becoming `nix.local`]())
		- (password same as on the Apple MacOS)
		- Check the box: "Use the same password for the administrator account."
	- Click **Next** and confirm the settings, then click **Install** and wait for the installation to finish

## Post-Installation

After the installation is complete and you have rebooted into your new CachyOS system, you may need to perform a few additional steps to ensure everything works smoothly. Since we are using [Hyprland]() Desktop Environment, close all the startup windows using `CMD+Q` on the Macbook keyboard. For a default keybindings, check the [CachyOS Hyprland](https://wiki.cachyos.org/desktop_environments/hyprland/) wiki page. The default `Super` key is set to `Command (Cmd)` button if the exact Keyboard instructions were followed.

### 1. Install Wi-Fi Firmware Permanently

If you have followed the optional Enable Wi-Fi in the Live Environment step to get firmware in the live ISO, you can simply follow [extract WiFi Firmware](#extract-wifi-firmware) steps again to enable Wi-Fi. Otherwise, connect to the internet (e.g., Ethernet, USB tethering) and follow the steps below:

1. Download the firmware package form the Arch Linux T2 mirror
2. Install the downloaded package
3. Reload the Wi-Fi kernel modules

Using Hyprland DE, open the Terminal using `Super`+`Return/Enter` keyboard button (ie. `cmd+enter`), and type the following:

```bash
$ nmtui
# Enter 'Activate a connection' from the TUI menu
# If you see a list of "Wi-Fi" connections, the Wi-Fi driver is already installed - you can skip this step
```

If you don't see the WiFi connections listed, please follow the instructions explained [on the docs page](https://wiki.cachyos.org/installation/installation_t2macbook/#install-wi-fi-firmware-permanently) for the T2 Macbook.

### 2. Confirm the CachyOS Hardware Detection

Inside the Terminal, use `chwd` command to confirm if the OS installed required device drivers and necessary packages automatically. The `chwd` is typically ran during installation time to provide the necessary packages for the system out of the box once it has been installed, however, it is also possible to use it post-install.

```bash
$ chwd
> 0000:00:02.0 (xxxxxxxxx) VGA compatible controller Interl Corporation:
# name			priority
# intel			4
# fallback	3

> 0000:03:00.0 (xxxxxxxxx) Network controller Broadcom Inc. and subsidiaries:
# name						priority
# broadcom-wl			1
```

---

- **Auto Configuration** - The `chwd` supports installing and configuring necessary drivers and pkgs so that the system can work at optimal conditions, done using ` sudo chwd -a` CLI command.
- **Installing a profile** - An alternative to the above method is to install each specific profile. List available profiles using `chwd --list-all`, then install a specific profile using `sudo chwd -i [name]`.

Check the [CachyOS Hardware Detection (`chwd`)](https://wiki.cachyos.org/features/chwd/) official documentation for more details.

### 3. Change or tweak CachyOS Settings

Alongside our optimized kernels and repositories, the system provide settings that further improve the desktop experience, including helper scripts for QoL improvements. These configs and scripts are under the `cachyos-settings` package.

Some of the possible tweaks include:

- **sysctl tweaks**, [docs](https://wiki.cachyos.org/features/cachyos_settings/#sysctl-tweaks) - there are a lot of sysctl tweaks that aim to improve overall desktop performance, each sysctl entry is well documented in the file `99-cachyos-settings.conf`
- **udev tweaks**, [docs](https://wiki.cachyos.org/features/cachyos_settings/#udev-rules) - contains userspace `/dev` rules for device manager within Linux kernel
- **modprobe options**, [docs](https://wiki.cachyos.org/features/cachyos_settings/#modprobe-options) - allowing various tweaks for NVIDIA, disabling power_save for some audio drivers etc.
- **Helper Scripts**, [docs](https://wiki.cachyos.org/features/cachyos_settings/#helper-scripts) - which includes:
	- `cachyos-bugreport.sh` - Collects various logs from `inxi`, `dmesg` and `journalctl` to aid in troubleshooting
	- `game-performance` - Wrapper script for powerprofilesctl to switch to performance profile on-demand. See Power Profile Switching On Demand
	- `dlss-swapper` - Wrapper script to force the latest DLSS preset in games that support the technology
	- `dlss-swapper-dll` - Like dlss-swapper, but requires manually updating the nvngx_dlss.dll library shipped with the game; may work with games that have issues with the regular version of the script
	- `kerver` - QoL script to show information about the current kernel
	- `paste-cachyos` - Script to paste terminal output for text files from the system
	- `pci-latency` - Reduces latency_timer value to 80 for PCI sound cards and resets all the other PCI devices to 20 and 0
	- `sbctl-batch-sign` - Helper script to easily sign kernel images and EFI binaries for secure boot and saves them to sbctl’s database
	- `topmem` - Shows RAM & swap & ksm stats of 10 processes in a descending order
	- `zink-run` - Makes it easier to execute an OpenGL program through Zink Gallium Driver
* **Other configurations**, [docs](https://wiki.cachyos.org/features/cachyos_settings/#other-configurations)

### 4. System Update

Use "Octopi" - a graphical package manager for Arch-based distributions that provides a way to manage packages and updates. Otherwise, use typical update command via `pacman` to update the system, ie: `sudo pacman -Syu`.

```bash
$ sudo pacman -Syu
```

It is advised to reboot your computer after a big update (especially if the kernel got an update).

### 5. Firewall Configuration (`ufw`)

> **Note:** UFW is enabled by default after installation. By default, `ufw` allows for all incoming/outgoing traffic.

To configure `ufw`, use command line interface:

```bash
$ sudo ufw enable					# enable firewall
$ sudo ufw disable				# disable firewall
$ sudo ufw allow ssh			# add a specific rule to the firewall to allow specific connections
$ sudo ufw deny ssh				# this would deny ssh rule instead of allowing it
$ sudo ufw deny 80 				# you can also deny a specific port, or allow it per requirements
$ sudo ufw status verbose	# this can be used to show the status of the fw rules
```

Altearnatively, use KDE Plasma to configure "Firewall" via the GUI. I recommend using `sudo ufw allow ssh` if you will use this Linux machine from another Mac or PC. Then make sure to start the `sshd` service using:

```bash
$ systemctl status sshd
# [+] sshd.service - OpenSSH Daemon
#			Loaded: loaded ([path]; disabled;)
#			Active: ...
#				Docs: ...

$ systemctl enable sshd
# Created symlink [path] -> [path]/sshd.service

$ systemctl start sshd.service
# ...
#			Loaded ...
# 		Active: (running)
```

Then copy your `ssh` public key from your Host PC (ie. MacOS) using this Terminal command:

```
$ ssh-copy-id -p 22 hduraki@192.168.0.240 		# replace ipv4 with that shown via `ip a` command on the Linux machine
```

### 6. Configure Wi-Fi Regulatory Domain

The `wireless-regdb` package includes a **database of wireless rules** (allowed frequencies, channels, power limits) for various countries. Setting the right region for your location **can unlock specific Wi-Fi channels** (such as channels 12/13 or 5GHz/6GHz bands) that may be limited by default, helping to **improve your Wi-Fi performance and connection quality**.

To get currently applied regulatory domain,m use this command:

```bash
$ iw reg get
global
country 00: DFS-UNSET # Country 00 uses global defaults
	(755 - 928 @ 2), (N/A, 20), (N/A), PASSIVE-SCAN
	(2402 - 2472 @ 40), (N/A, 20), (N/A)
	(2457 - 2482 @ 20), (N/A, 20), (N/A), AUTO-BW, PASSIVE-SCAN
	(2474 - 2494 @ 20), (N/A, 20), (N/A), NO-OFDM, PASSIVE-SCAN
	(5170 - 5250 @ 80), (N/A, 20), (N/A), AUTO-BW, PASSIVE-SCAN
	(5250 - 5330 @ 80), (N/A, 20), (0 ms), DFS, AUTO-BW, PASSIVE-SCAN
	(5490 - 5730 @ 160), (N/A, 20), (0 ms), DFS, PASSIVE-SCAN
	(5735 - 5835 @ 80), (N/A, 20), (N/A), PASSIVE-SCAN
	(57240 - 63720 @ 2160), (N/A, 0), (N/A)
```

Look for the `country XX:` line, where `XX` should match the code of the country. If it shows `country 00:`, the system might be using default restrictions or hasn’t yet determined the region. To fix this issue, **edit the configuration** file `wireless-regdom` with root privileges and set a two-letter ISO country code (e.g., `WIRELESS_REGDOM="BA"`). Ensure that only one country is commented. Then **reboot** the system to apply the changes.

```bash
$ sudo vim /etc/conf.d/wireless-regdom
# WIRELESS_REGDOM="BA"				(uncomment this line)

$ reboot
# ...

$ iw reg get
global
country BA: DFS-ETSI # Country correctly shows as BA
	# ...
	# ...
```

### 7. Enabling Global Menu

For some apps like Visual Studio Code, the global menu may not work or may be attached to the parent app instead of the panel.

```bash
# To enable global menu support, run the command and restart the app.
$ sudo pacman -S appmenu-gtk-module libdbusmenu-glib
```

### 8. Hyprland Settings

**Version Check**

To check `hyprland` version, use:

```bash
$ hyprctl version
# Hyprland 0.50.1 					....
# Date: Sat Jul 19 21:37:06 2025
# ...
```

**Default Terminal Config**

If you wish to choose the default terminal before you proceed, you can do so in `~/.config/hypr/hyprland.conf` file.

**Theme and Styling**

Use the `qt5ct`/`qt6ct` command in Terminal to launch version of `lxappearance/nwg-look` for themeing option. Some older applications may also require configuring visual palette via `qt4ct`.

**Electron and Chromium-based Apps**

Electron Apps can be configured and forced to use Wayland, as described on [Hyprland Wiki](https://wiki.hypr.land/Getting-Started/Master-Tutorial/#force-apps-to-use-wayland) page. For most electron apps, you should put required flags in the `~/.config/electron-flags.conf` file. **Note** that `VSCode` is known not to work with it. A few more environment variables for forcing Wayland mode are [documented here](https://wiki.hypr.land/Configuring/Environment-variables). To check whether an app is running in `xwaylannd` or not, use the `hyprctl clients` command.

**File Explorer / Fnder**

Install and use [Nautilus](https://apps.gnome.org/en/Nautilus/), called **`Files`** in newer version (and in application picker interface) using the command below:

```bash
$ sudo pacman -S nautilus nautilus-share nautilus-image-converter
```

**Bluetooth/Wireless Interfaces**

* [Overskride](https://github.com/kaii-lb/overskride) for BT
* [network-manager-applet](https://gitlab.gnome.org/GNOME/network-manager-applet) for Network Connections Editor

**Preconfigured Setups**

Here are a few options to consider: [ML4W](https://www.ml4w.com), JaKooLit, [end_4](https://github.com/end-4/dots-hyprland?tab=readme-ov-file), [HyDe](https://github.com/HyDE-Project/HyDE) or others. The mentioned ones are available on [official wiki docs](https://wiki.hypr.land/Getting-Started/Preconfigured-setups/) of Hyprland.

* [Github CachyOS `.dotfiles` Repository](https://github.com/CachyOS/cachyos-hyprland-settings)
* [Awesome Hyprland](https://github.com/hyprland-community/awesome-hyprland)
* [Hyprland - Official Website](https://hypr.land)
* [Quickshell](https://quickshell.org)

### 9. Other Config options

* [Changing the default Terminal shell](https://wiki.cachyos.org/configuration/post_install_setup/#changing-the-default-shell), CachyOS uses `fish` as the user's default login shell
* [Updating & using `tldr`](https://wiki.cachyos.org/configuration/post_install_setup/#updatingusing-tldr), CachyOS uses [`tealdeer`](https://github.com/tealdeer-rs/tealdeer) which is a faster Rust based implementation of the original tldr
* [General System Tweaks](https://wiki.cachyos.org/configuration/general_system_tweaks/), such is tweaking [power saving](https://wiki.cachyos.org/configuration/general_system_tweaks/#power-saving-tweaks), [audio improvements](https://wiki.cachyos.org/configuration/general_system_tweaks/#audio-improvements) and other
* [Automount Additional Drives at Boot](https://wiki.cachyos.org/configuration/automount_with_fstab/) when you need to mount static drives during the boot
* [Enabling Chrome Hardware Acceleration](https://wiki.cachyos.org/configuration/enabling_hardware_acceleration_in_google_chrome/)
* [Hyprland Configuration](https://wiki.cachyos.org/desktop_environments/hyprland/)

## Boot Manager

Change the **systemd-boot** configuration, specifically, the `/boot/loader/loader.conf` file, changing the default timeout of [`systemd-boot`](https://www.freedesktop.org/software/systemd/man/latest/loader.conf.html) to `0` seconds, booting right away as the computer starts up:

```
$ sudo vim /boot/loader/loader.conf

default @saved
timeout 0									# how long the boot menu should be shown before the default entry is booted, in seconds
console-mode keep 				# this options configures the resolution of the console selected by firmware
```

Reference to [Boot Manager Configuration](https://wiki.cachyos.org/configuration/boot_manager_configuration/#systemd-boot) for more details.

# Other Resources

* [A Light Guide for Installing Arch Linux on a MacBook Air 2015 (2024)](http://www.s-oshea.com/blog/light-guide-for-installing-arch-on-macbook/)
