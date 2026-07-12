---
title: "Vehicle Hacking Environment"
---

### Using Docker and Kali

Install Docker first:

```
$ brew install docker # => or use docker.io
```

Use the following script:

```
# ... install required kali-docker tools

# setup vehicle hacking environment
$ apt-get install -y build-essential
$ apt-get install -y ruby
$ apt-get install -y ruby-dev
$ apt-get install -y rubygems
$ gem install serialport -- --use-system-libraries
$ apt-get -y install bluez # (for hcitool)
$ apt-get install -y net-tools
```

### Using Virtual Vehicle environments

[jeep](https://github.com/duraki/jeep) has been developed to offer offensive-security solution for penetration testing on vehicle systems and similar attributes. Additionally, you can [use ICSim](https://cougarbytes.net/articles/can-bus-forensics/) to experiment on a `vcan` (virtual) network.

{{< notice >}}
Important Update Errata
{{< /notice >}}
{{< callout emoji="☺️" text="I would like to thank [Chirag J.](https://www.linkedin.com/in/cougarbytes/) since he messaged me on LinkedIn acknowledging that he updated the URL of the blog post mentioning ICSim above. I advice  everyone to let me know of any changes, breaking updates or news regarding the links mentioned in my notes, either via my [LinkedIn](https://www.linkedin.com/in/duraki/), or otherwise - so I can update them accordingly. Thanks Chirag!" >}}

There is also possibility of developing a hardware based training ECU as explained on [Quarkslab's blog](https://blog.quarkslab.com/development-of-a-training-ecu.html) *(Development of a training ECU)*.
