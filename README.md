# iptables-uwu

This is a xtables module that uwu's the output packet, mostly as a shitpost, but also as a future referance
to me on how to write xtables modules that tamper with the outgoing packet in kernel space.

This repo is mostly based on https://github.com/xiaosuo/xtables-misc and a lot of the code is adapted from that.

GPL-2 Licenced for reasons of Linux and it contains code from xiaosuo that is GPL-2.

## Build

`make install`

## Insert

`insmod xt_UWU.ko`

and then the `-j UWU` target should exist.

You can then tawget packets fow uwu:

```
sudo iptables -t mangle -I OUTPUT -d 38.229.70.22/32 -p tcp -m tcp --dport 8000 -j UWU
```