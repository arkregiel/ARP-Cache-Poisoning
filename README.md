# ARP cache poisoning

Python script performing an ARP cache poisoning (ARP spoofing) attack.
Script redirects and captures traffic between a victim and the default gateway.

## Disclaimer

This is for educational purposes only. I DO NOT encourage or promote any illegal activities.

## Install requirements

```
$ pip install -r requirements.txt
```

## Usage

Program has to be run as an administrator or root

```
$ python arp_poison.py --help
usage: arp_poison.py [-h] -i INTERFACE -g GATEWAY [-c COUNT] victim

ARP cache poisoning attack

positional arguments:
  victim                victim's IPv4 address

optional arguments:
  -h, --help            show this help message and exit
  -i INTERFACE, --interface INTERFACE
                        network interface (ie. eth0)
  -g GATEWAY, --gateway GATEWAY
                        default gateway's IPv4 address
  -c COUNT, --count COUNT
                        number of packets to capture
```

Victim's IPv4 address, gateway's IPv4 address and an interface name are required.

## Example

```
$  python arp_poison.py -i eth0 -g 192.168.1.1 192.168.1.100
```
