# Installing Wisp on a Raspberry Pi

## Bootstrapping
### Update:
- Login and `sudo -i`.
- `apt update && apt upgrade -y && apt install aircrack-ng bluez-tools build-essentials gpsd libpcap0.8 && rpi-update && libreadline-dev uuid-dev libffi-dev libncurses-dev libssl-dev libsqlite3-dev && reboot`

### Basic System Configuration 
- Login again, `sudo -i`.
- Run raspi-config. Change:
    - hostname
    - wifi reg domain
    - password
    - locale and keyboard layout
    - timezone (to UTC)
    - expand partition
    - enable sshd
    - don't reboot
### Python 3.7.1 Build and Installation
- Fetch, build, and install Python 3.7.1: `mkdir /src && cd /src && wget https://www.python.org/ftp/python/3.7.1/Python-3.7.1.tar.xz && tar xvf Python-3.7.1.tar.xz && cd Python-3.7.1 && ./configure --enable-shared --enable-ipv6 --enable-optimizations --enable-loadable-sqlite-extentions --with-lto && make -j4 && make install && reboot`
- Login again, `sudo -i`.

## Bluetooth PAN Configuration
Create the following files:
/etc/systemd/network/pan0.netdev
```
[NetDev]
Name=pan0
Kind=bridge
```
/etc/systemd/network/pan0.network
```
[Match]
Name=pan0

[Network]
Address=172.20.1.1/24
DHCPServer=yes
```
/etc/systemd/system/bt-agent.service
```
[Unit]
Description=Bluetooth Auth Agent

[Service]
ExecStart=/usr/bin/bt-agent -c NoInputNoOutput
Type=simple

[Install]
WantedBy=multi-user.target
```
/etc/systemd/system/bt-network.service
```
[Unit]
Description=Bluetooth NEP PAN
After=pan0.network

[Service]
ExecStart=/usr/bin/bt-network -s nap pan0
Type=simple

[Install]
WantedBy=multi-user.target
```
Then run
```
sudo systemctl enable systemd-networkd
sudo systemctl enable bt-agent
sudo systemctl enable bt-network
sudo systemctl start systemd-networkd
sudo systemctl start bt-agent
sudo systemctl start bt-network
```
Finally to pair, run:
```
sudo bt-adapter --set Discoverable 1
```
