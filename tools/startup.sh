#!/bin/sh
# activate proxy_arp on all interfaces
echo 1 > /proc/sys/net/ipv4/conf/eth1/proxy_arp
echo 1 > /proc/sys/net/ipv4/conf/eth2/proxy_arp
echo 1 > /proc/sys/net/ipv4/conf/eth3/proxy_arp
echo 1 > /proc/sys/net/ipv4/conf/eth4/proxy_arp
cd /home

