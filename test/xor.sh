#!/bin/bash

iptables -t mangle -F OUTPUT
rmmod xt_XOR &>/dev/null
iptables -t mangle -A OUTPUT -p udp -j XOR --xor-key 1234
iptables -t mangle -A OUTPUT -p udp -j XOR --xor-key 1234
iptables -t mangle -A OUTPUT -p udp -j XOR --xor-hex-key 1234
iptables -t mangle -A OUTPUT -p udp -j XOR --xor-hex-key 1234
iptables -t mangle -A OUTPUT -p tcp -d 10.13.150.1 -j XOR --xor-hex-key abcdef
iptables -t mangle -A OUTPUT -p tcp -d 10.13.150.1 -j XOR --xor-hex-key abcdef
