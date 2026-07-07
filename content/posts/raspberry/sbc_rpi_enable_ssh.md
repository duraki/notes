---
title: "Enable SSH on Raspbian OS"
---

### Via RO/RW SD Card 

This seems to work only on Raspbian OS, and not the custom GNU/Linux ARM builds-. To enable SSH on boot, you need to create a new `ssh` file in your SD Card's `/boot` partition:

First, make sure to `mount` the `boot` partition, as seen on [Mounting SBC Operating System](/mounting-sd-cards).

Next, create the `ssh` file:

```
$ sudo touch /Volumes/boot/ssh
```

### Paswordless SSH Authentication

In your Raspberry OS, do the following to generate `~/.ssh` defaults:

```
pi@raspberrypi:~ $ ssh-keygen
Generating public/private rsa key pair.

Enter file in which to save the key (/home/pi/.ssh/id_rsa): Created directory '/home/pi/.ssh'.
...
+---[RSA 3072]----+
      ......
+----[SHA256]-----+
```

Copy the Raspberry OS public key, and place it on your **Host OS** `~/.ssh/authorized_keys`:

```
# => on RPi
pi@raspberrypi:~ $ cat ~/.ssh/id_rsa.pub
ssh-rsa AAAA....

# => on Host OS
galaxy@devil. ~  vim ~/.ssh/authorized_keys
# .. paste the RPi id_rsa.pub ..

galaxy@devil. ~  ssh-copy-id pi@raspberrypi.local
/usr/bin/ssh-copy-id: INFO: Source of key(s) to be installed ...
		pi@raspberrypi.local's password:
Number of key(s) added:        1
...

# => now try logging into the machine, with
$ ssh pi@raspberrypi.local
```

You should be able to login without providing Raspberry Pi password.