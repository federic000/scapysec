#!/usr/bin/env python3

import threading
import sys
import time
import signal
import warnings
warnings.filterwarnings("ignore")
from scapy.all import *

pkt__ingress = 0
pkt__egress = 0

ip_src_dict = dict()
egress_int_array = ["eth2", "eth3", "eth4"] #in this example we have 3 outgoing interfaces 

def rotate_int(arr, k):
    #rotates array each time is called
    temp = arr[0]
    for i in range(k-1):
        arr[i] = arr[i+1]
    arr[k-1] = temp
    return arr[0]

def check_hash(source_ip):
    if source_ip in ip_src_dict:
       return ip_src_dict[source_ip]['exit_interface']
    else:
       #add a new ip source address and exit interface + mac-address to dictionary
       #exit interface from the array rotates at every new ip source addition
       ethx = rotate_int(egress_int_array, 3)
       if ethx == "eth2": 
          ip_src_dict[source_ip] = {'exit_interface': ethx, 'dest_mac': mac1}
       elif ethx == "eth3":
          ip_src_dict[source_ip] = {'exit_interface': ethx, 'dest_mac': mac2}
       elif ethx == "eth4":
          ip_src_dict[source_ip] = {'exit_interface': ethx, 'dest_mac': mac3}
       return ip_src_dict[source_ip]['exit_interface']


def packet_manager_ing(packet):
    #on ingress traffic the d_mac changes in round-robin
    global pkt__ingress
    if packet.haslayer(IP):
        ip_src = packet[IP].src
        ethx_intf = check_hash(ip_src) 
        packet[Ether].dst = ip_src_dict[ip_src]['dest_mac']
        sendp(packet, iface=ethx_intf, verbose=0)
        pkt__ingress += 1
        #psize = len(packet)
        #print(f"pkt size {psize}B ingress packets: {pkt__ingress} || ", end = '') 
        print(f"ingress packets: {pkt__ingress}  ", end = '')

def packet_manager_egr(packet):
    #on egress the d_mac is always the mac of dcgw 
    global pkt__egress
    if packet.haslayer(IP):
        if packet.haslayer(Ether):
            packet[Ether].dst = macp1
            sendp(packet, iface="eth1", verbose=0)
            pkt__egress += 1
            #psize = len(packet)  
            #print(f"pkt size {psize}B egress packets: {pkt__egress} ", end = '\r')
            print(f"egress packets: {pkt__egress} ", end = '\r')

def sniff_ing(interface):
    #bpf filter selects isakmp and esp to/from te-ip
    print("start lb ingress...")
    sniff(iface=interface, filter="((udp port 500) or (ip proto 50)) and ip dst 10.2.2.1", prn=packet_manager_ing) 

def sniff_egr(interface):
    #bpf filter selects isakmp and esp to/from te-ip  
    print("start lb egress...")
    sniff(iface=interface, filter="((udp port 500) or (ip proto 50)) and ip src 10.2.2.1", prn=packet_manager_egr)

def arp_finder(ipaddress, interface):
    ans,unans=srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ipaddress),timeout=2,iface=interface,verbose=0)
    return ans[0][1]


if __name__ == "__main__":
   #send out ARP req. to find next hop MAC addresses with TEIP address of Sec-Gateway and adj. nodes
   print("populating arp table with MAC of adjacent nodes...")
   mac1_str = str(arp_finder("10.3.3.254", "eth2")).split(); mac1 = mac1_str[5]
   mac2_str = str(arp_finder("10.3.3.254", "eth3")).split(); mac2 = mac2_str[5]
   mac3_str = str(arp_finder("10.3.3.254", "eth4")).split(); mac3 = mac3_str[5] 
   macp1_str = str(arp_finder("10.3.3.3", "eth1")).split(); macp1 = macp1_str[5]
   print(f"arp table populated as eth1-> {macp1} , eth2-> {mac1} , eth3-> {mac2} , eth4-> {mac3}")
 
   #start capture and modify packets - stops with CTRL^C    
   threads = list()
   threadingress = threading.Thread(target=sniff_ing, args=("eth1",))
   threadegress = threading.Thread(target=sniff_egr, args=(["eth2","eth3","eth4"],))
   threads.append(threadingress)
   threads.append(threadegress)
   threadingress.start()         
   threadegress.start()
   
