# wisp
Script to automatically deauth 802.11 clients enmasse. Captures packets for later nefariousness.

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
* A USB hub for connecting all of the monitoring radios required. The [Anker 4-Port Ultra Slim USB 3.0 Hub](https://www.anker.com/products/variant/4port-ultra-slim-usb-30-hub/A7518113) is suitable. You will want one that has the ports laid out horizontally, to prevent issues with overheating. One that accepts external power over USB is preferable, but it will depend on the power requirements of your configuration.
* A GPS unit like the [Canada GPS BU353-S4](http://canadagps.com/BU353-S4.html). The script doesn't use gpsd itself, but it is useful to be able to correlate location with the packet capture later on.
* (Gaff tape)[https://en.wikipedia.org/wiki/Gaffer_tape], for keeping everything connected.
* A bag or enclosure of any sort, to avoid confusing and awkward conversations. Avoid taking the assembled kit as a carry-on item, believe me.

### Remote Control
I personally use [ConnectBot](https://connectbot.org/) with (Hacker's Keyboard)[https://github.com/klausw/hackerskeyboard] on my cell phone for controlling kits like this over SSH. It draws the least attention and fits in your pocket. 

I suggest that the device be configured to automatically connect to a VPN that you host, to avoid any routing/NAT issues. Setting up [OpenVPN](https://openvpn.net/) on a cloud host is the easiest way to achieve this. Be sure to use OpenVPN's `client-to-client` server configuration directive, or have forwarding configured otherwise.

You will require some other method besides wifi for connecting the device to the internet, obviously. Cellular access is the simplest candidate. Unless you desire to pull packet captures of the device remotely, very little bandwith (<100Kib/s) is required. You can get away with using a cheap "unlimited" data plan that restricts your speed after some amount of data is used.

I have had MTU issues when running OpenVPN over cellular. The easiest remedy is to set your MTU to 1200 with `ip link set dev tunX mtu 1200`, where tunX is your tun device.

### Power
Depending on your specific configuration, the connected USB devices may draw more power than the Raspberry Pi can provide through its usual means. Using a USB powered hub like the one mentioned above will let you power the radios through another USB port on the battery. Some cheap USB hubs will "back-power" the hub on the Raspbery Pi. This is suitable as long as you're using a good quality battery, and even useful.

Another solution is to provide additional power to the USB hub using a splitter [like this](https://www.amazon.com/dp/B00NIGO4NM/). It works, but I don't recommended it. It is one more thing that could accidently become disconnected, and is just unruly to organize otherwise.

If you are providing remote control through a tethered cell phone, you should ensure the battery has a full charge when starting the kit, if possible. Some cheaper devices may not draw enough current to keep up with the power consumed by a constant data connection.
