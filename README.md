# wisp
Script to automatically deauth 802.11 clients en masse. Captures packets for later nefariousness. Great conversation starter in your local coffee shop.

## Hardware
### Raspberry Pi
This script was designed to run on a Raspberry Pi 3 or above. It will also run on similar hardware with the same or greater capabilities, of course.

### Required Kit
A fair amount of additional kit is required to operate the script effectively. You will also require:
* At least one wifi radio capable of monitoring. I suggest the [Panda Wireless PAU06](https://www.amazon.com/dp/B00JDVRCI0/).
* One other wifi radio capable of injection, preferably with a higher TX power. I suggest the [ALFA AWUSO36NH](https://www.amazon.com//dp/B0035APGP6/).
* Some method of remote control via SSH. The [Verizon USB730L](https://www.verizonwireless.com/internet-devices/verizon-global-modem-usb730l/) is more than suitable. Local ethernet also works, of course.

### Suggested Kit
For maximum effectiveness, you should also have:
* A battery. The [Anker PowerCore 20100](https://www.anker.com/products/variant/powercore-20100/A1271012) will run this rig for 6 to 12+ hours, depending on use and configuration.
* At least three wifi radios capable of monitoring, as mentioned above. Having three radios set to channels 1, 6, and 11 will cover the bulk of 802.11 traffic.
* A USB hub for connecting all the monitoring radios required. The [Anker 4-Port Ultra Slim USB 3.0 Hub](https://www.anker.com/products/variant/4port-ultra-slim-usb-30-hub/A7518113) is suitable. You will want one that has the ports laid out horizontally, to prevent issues with overheating. One that accepts external power over USB is preferable, but it will depend on the power requirements of your configuration.
* A GPS unit like the [Canada GPS BU353-S4](http://canadagps.com/BU353-S4.html). The script doesn't use gpsd itself, but it is useful to be able to correlate location with the packet capture later on.
* [Gaff tape](https://en.wikipedia.org/wiki/Gaffer_tape), for keeping everything connected.
* A bag or enclosure of any sort, to avoid confusing and awkward conversations. Avoid taking the assembled kit as a carry-on item, believe me.

### Remote Control
I personally use [ConnectBot](https://connectbot.org/) with [Hacker's Keyboard](https://github.com/klausw/hackerskeyboard) on my cell phone for controlling kits like this over SSH. It draws the least attention and fits in your pocket.

I suggest that the device be configured to automatically connect to a VPN that you host, to avoid any routing/NAT issues. Setting up [OpenVPN](https://openvpn.net/) on a cloud host is the easiest way to achieve this. Be sure to use OpenVPN's `client-to-client` server configuration directive, or have forwarding configured otherwise.

You will require some other method besides wifi for connecting the device to the internet, obviously. Cellular access is the simplest candidate. Unless you desire to pull packet captures from the device remotely, very little bandwidth (<100Kib/s) is required. You can get away with using a cheap "unlimited" data plan that restricts your speed after some amount of data is used.

I have had MTU issues when running OpenVPN over cellular. The easiest remedy is to set your MTU to 1200 with `ip link set dev tunX mtu 1200`, where tunX is your tun device. You may have to use a different MTU depending on your network.

### Power
Depending on your specific configuration, the connected USB devices may draw more power than the Raspberry Pi can provide through its usual means. Using a USB powered hub like the one mentioned above will let you power the radios through another USB port on the battery. Some cheap USB hubs will "back-power" the hub on the Raspberry Pi. This is suitable as long as you're using a good quality battery, and even useful.

Another solution is to provide additional power to the USB hub using a splitter [like this](https://www.amazon.com/dp/B00NIGO4NM/). It works, but I don't recommended it. It is one more thing that could accidentally become disconnected, and is just unruly to organize otherwise.

If you are providing remote control through a tethered cell phone, you should ensure the battery has a full charge when starting the kit, if possible. Some cheap devices may not draw enough current to keep up with the power consumed by a constant data connection.

### Thermal Management
The combination of multiple radios, the Raspberry Pi, and cellular modem will get very toasty. The Panda PAU06's run especially hot. If you don't mind the heat, you will end up with melted radios or worse. Do a test run with your chosen bag/enclosure at room temperature beforehand, to ensure it provides suitable heat dissipation. If you must use the kit in a hot environment, like inside a vehicle on a warm day, take some extra steps to prevent overheating. In the case of a vehicle, setting the climate controls for A/C and remote starting the vehicle intermittently will suffice.

Some cheap cell phones are prone to overheating due to the combination of the additional gear and the need to regularly transmit data. They may shut off under these conditions, preventing remote control. Placing the phone in a separate compartment from the rest of the kit will help, but you are better off using a different device.

If you intend to operate the kit covertly, keep in mind that the heat may draw attention in unexpected ways. If it is left on the dashboard of a vehicle during a snowy day, it will melt the snow and ice. There will be a nice round clear space on the windshield, centering the kit in view, where everything else is otherwise covered in snow!

## Software
### Wisp
Wisp install instructions are detailed in [rpi-install.md](https://raw.githubusercontent.com/dougives/wisp/master/rpi-install.md). The steps should be similar for non-raspian systems. Wisp depends on `aireplay-ng` from [aircrack-ng](http://www.aircrack-ng.org/) to transmit deauth frames. Notably, you will need to build Python-3.7.1 for the device, which is also described in the rpi-install.md file.
### Dream
Wisp depends on another small C program called `dream`. The source is included as [dream.c](https://raw.githubusercontent.com/dougives/wisp/master/dream.c). Dream depends on libpcap.

Compile dream for your device with the command `gcc -O3 dream.c -lpcap`.

Dream is a tool for monitoring 802.11 traffic with a line-greppable output. It also saves captured traffic into files with the standard pcap format. Wisp calls dream for each monitoring radio and parses the output for client traffic. Here are its arguments:
* `--a`: Only report traffic from associated clients. (All packets are still logged to disk if --d is enabled.)
* `--d (file)`: Dump packets to the specified file.
* `-[b][c][d][f][s][t]`: Specifies which fields to output per line, specifically:
  * `b`: BSS
  * `c`: Channel number.
  * `d`: Name of the device which received the packet.
  * `f`: Frequency.
  * `s`: Station (STA).
  * `t`: Pcap timestamp.

These fields are always printed in the same order, regardless of the order specified. (That is, `-bcst` is equivalent to `-svtb`.)

## Configuration
Wisp reads a json formatted file named [wisp.json](https://raw.githubusercontent.com/dougives/wisp/master/wisp.json) for configuration. Here is a description of the keys:
* `monitors`: Contains a list of devices to be configured as monitors. Each device contains subkeys describing their specific configuration:
* `channel`: The channel for the device to monitor.
* `injector`: The device to be configured to inject deauth frames.
* `timing`: Lists several timing parameters, all given in milliseconds:
  * `delay`: The delay between deauth packets sent, per client.
  * `jitter`: Modulates the delay time by a random amount, in the range given.
  * `stale`: Amount of time a client is not seen before being removed from the delay list. Has little practical effect unless it is close to the delay timespan.

## Invocation
All parameters are loaded from `wisp.json`, so wisp is invoked simply: `python3 ./wisk.py`

Wisp will automatically configure the radios as described in `wisp.json`. It will also disable rfkill and kill any interfering processes, similar to the behavior of `airmon-ng`.

## Output
Wisp outputs a `.` for every deauth sent. This is a simple and effective way to ensure it is operating as expected.

Wisp (through dream) will output pcap files prefixed with the name of the radio (phy) which captured the packets, along with a random hexadecimal string, ending in `.cap`. Something like `phy0-8cf9ec5ca146943f.cap`, for example. You can then inspect, parse, and manipulate them with any regular tools for pcap files.
