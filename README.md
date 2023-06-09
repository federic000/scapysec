# scapysec

## intro

scapysec is L2 (transparent) IPsec tunnel load balancer, it has to be used as **modeling tool** by which you 
can study and test effects of load balancing across a set of tunnel termination devices, 
hereinafter called security gateways (aka _segw_).

it is based on [scapy](https://scapy.readthedocs.io/en/latest/index.html) and runs on [containerlab](https://github.com/srl-labs/containerlab) as usual

## how it works

the SCPY container (based on a customized Alpine image you can get from [dockerhub](https://hub.docker.com/repository/docker/federic0/fedepine/general)) keeps track of source IP addresses
of tunnels generated by SEGW0. An hash table provides for associating tunnels-IP-destMAC addresses to spray tunnels
across a set of segw. in this case, there are 3 serving segw implemented on Nokia SR-OS virtual sim's. 
SEGW-1-2-3 are configured exactly the same, same TEIP, same services, this allows SCPY to perform as a load-balancer exposing a single IP address to external clients. SEGW0 opens 6 tunnels in the current configuration, all of them are poiting at 10.2.2.1 as the TEIP. 

![the diagram shows the idea](./pictures/scpy.png)

There's also an instance of Nokia SRL, used in this case as Datacenter Gateway. 
The SCPY node at startup configures proxy-arp in all its interfaces. 
Then the SCPY node performs some functions: 
1. filters the packet with a BFP filter inside the sniff scapy primitive  
2. the BPF filter takes isakmp or esp traffic coming from/to set of segws and passes it to the packet manager
3. segw1-2-3 are configured all the same as said above, but they can't see each other in the L2 domain (because SCPY interfaces are NOT bridged) 
4. packets are now passed to a packet manager function that provides for mac-swap and packet forward on a proper interface
5. tunnels and their destination are tracked with a dict() hash table

Eventually, you will end up with SEGW1-2-3 loaded with tunnels in a round-robin way as:  

```
A:admin@SEGW1# show ipsec gateway name "IPSECGW1" tunnel 

===============================================================================
IPsec Remote User Tunnels
===============================================================================
Remote Endpoint Addr                      GW Name            
 GW Lcl Addr                              SvcId             TnlType
  Private Addr                            Secure SvcId      BiDirSA
   Idi-Type      Value*                                     
-------------------------------------------------------------------------------
10.100.1.2:500                            IPSECGW1          
 10.2.2.1                                 100               psk
                                          200               true
   ipv4Addr       10.100.1.2                                                  
10.100.2.2:500                            IPSECGW1          
 10.2.2.1                                 100               psk
                                          200               true
   ipv4Addr       10.100.2.2                                                  
10.100.4.2:500                            IPSECGW1          
 10.2.2.1                                 100               psk
                                          200               true
   ipv4Addr       10.100.4.2                                                  
10.100.5.2:500                            IPSECGW1          
 10.2.2.1                                 100               psk
                                          200               true
   ipv4Addr       10.100.5.2                                                  
-------------------------------------------------------------------------------
IPsec Gateway Tunnels: 4
===============================================================================

A:admin@SEGW2# show ipsec gateway name "IPSECGW1" tunnel 

===============================================================================
IPsec Remote User Tunnels
===============================================================================
Remote Endpoint Addr                      GW Name            
 GW Lcl Addr                              SvcId             TnlType
  Private Addr                            Secure SvcId      BiDirSA
   Idi-Type      Value*                                     
-------------------------------------------------------------------------------
10.100.0.2:500                            IPSECGW1          
 10.2.2.1                                 100               psk
                                          200               true
   ipv4Addr       10.100.0.2                                                  
10.100.2.2:500                            IPSECGW1          
 10.2.2.1                                 100               psk
                                          200               true
   ipv4Addr       10.100.2.2                                                  
10.100.3.2:500                            IPSECGW1          
 10.2.2.1                                 100               psk
                                          200               true
   ipv4Addr       10.100.3.2                                                  
10.100.5.2:500                            IPSECGW1          
 10.2.2.1                                 100               psk
                                          200               true
   ipv4Addr       10.100.5.2                                                  
-------------------------------------------------------------------------------
IPsec Gateway Tunnels: 4
===============================================================================

A:admin@SEGW3# show ipsec gateway name "IPSECGW1" tunnel 

===============================================================================
IPsec Remote User Tunnels
===============================================================================
Remote Endpoint Addr                      GW Name            
 GW Lcl Addr                              SvcId             TnlType
  Private Addr                            Secure SvcId      BiDirSA
   Idi-Type      Value*                                     
-------------------------------------------------------------------------------
10.100.0.2:500                            IPSECGW1          
 10.2.2.1                                 100               psk
                                          200               true
   ipv4Addr       10.100.0.2                                                  
10.100.1.2:500                            IPSECGW1          
 10.2.2.1                                 100               psk
                                          200               true
   ipv4Addr       10.100.1.2                                                  
10.100.3.2:500                            IPSECGW1          
 10.2.2.1                                 100               psk
                                          200               true
   ipv4Addr       10.100.3.2                                                  
10.100.4.2:500                            IPSECGW1          
 10.2.2.1                                 100               psk
                                          200               true
   ipv4Addr       10.100.4.2                                                  
-------------------------------------------------------------------------------
IPsec Gateway Tunnels: 4
===============================================================================
```
**more info coming soon** (hopefully!)





