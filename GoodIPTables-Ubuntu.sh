#!/bin/bash

# removed prerouting new chain as these rules can be moved to RAW and MANGLE tables respectively (this saves CPU cycles as during a DDoS, the connection tracker will get slaughtered)
# removed syn flood chain as these rules can be moved to RAW and MANGLE tables respectively (this saves CPU cycles as during a DDoS, the connection tracker will get slaughtered)
# removed port scanning chain for the same reason as the other two chains.\
# the MANGLE table does occur after the connection tracker so it's nice to duplicate these rules in raw and mangle (that don't invoke connection state) to ensure we're processing rules as fast as possible and putting as little load on the CPU as possible
# removed fragmentation rule as the linux kernel has builtin methods of dealing with (and if necessary - reconstructing) packet fragments

# Little INPUT chain that quickly determines the behaviour of our firewall (can be deduced by inspection)
# Quickly allow inbound traffic from lo iface, established and related connections
# Packet filter rules to sift out bogus traffic
# Followed by legit traffic on specific ports
#
# Few FORWARD chain rules purely for counters and stopping bogus traffic (if you're using this device as a gateway then these rules apply otherwise the kernel disables forwarding pkts on normal hosts anyway)
#
#
#Few OUTPUT chain rules for counters
#
# IN_DPI_RULES
# Boilerplate rules to ensure only legit traffic reaches the server and bogus traffic is logged and silently discarded
#
# IN_CUSTOMRULES
# This chain is where you open your tcp/udp ports and will be 1 of only 2 places that users' should modify
# Since we're already allowing related and established traffic all that's left is to allow new connections to specific ports.
# If you wan't to restrict port access to a specific IP/ip-range then I'd suggest following the SSH example which jumps to the safezone list of IP's/IP-ranges
#
# SAFEZONE
# SAFEZONE or permitted IP/IP-ranges in a dedicated chain for neatness and readibility, Since iptables doesn't have the ability (as far as i'm aware) to have iplists by default. 
#

iptables -N SAFEZONE
iptables -N IN_DPI_RULES 
iptables -N IN_CUSTOMRULES

iptables -t raw -A PREROUTING -p tcp --tcp-flags FIN,SYN,RST,PSH,ACK,URG NONE -j DROP
iptables -t raw -A PREROUTING -p tcp --tcp-flags FIN,SYN FIN,SYN -j DROP
iptables -t raw -A PREROUTING -p tcp --tcp-flags SYN,RST SYN,RST -j DROP
iptables -t raw -A PREROUTING -p tcp --tcp-flags FIN,RST FIN,RST -j DROP
iptables -t raw -A PREROUTING -p tcp --tcp-flags FIN,ACK FIN -j DROP
iptables -t raw -A PREROUTING -p tcp --tcp-flags ACK,URG URG -j DROP
iptables -t raw -A PREROUTING -p tcp --tcp-flags ACK,FIN FIN -j DROP
iptables -t raw -A PREROUTING -p tcp --tcp-flags ACK,PSH PSH -j DROP
iptables -t raw -A PREROUTING -p tcp --tcp-flags ALL ALL -m comment --comment "xmas pkts (xmas portscanners)" -j DROP
iptables -t raw -A PREROUTING -p tcp --tcp-flags ALL NONE -m comment --comment "null pkts (null portscanners)" -j DROP
iptables -t raw -A PREROUTING -p tcp --tcp-flags ALL FIN,PSH,URG -j DROP
iptables -t raw -A PREROUTING -p tcp --tcp-flags ALL SYN,FIN,PSH,URG -j DROP
iptables -t raw -A PREROUTING -p tcp --tcp-flags ALL SYN,RST,ACK,FIN,URG -j DROP
iptables -t raw -A PREROUTING -p tcp --tcp-flags SYN,ACK,FIN,RST RST -m limit --limit 1/s --limit-burst 2 -m comment --comment "limit RST pkts (half-conns etc...)" -j DROP
iptables -t raw -A PREROUTING -s 224.0.0.0/3 -m comment --comment "BOGONS" -j DROP
iptables -t raw -A PREROUTING -s 169.254.0.0/16 -m comment --comment "BOGONS" -j DROP
iptables -t raw -A PREROUTING -s 172.16.0.0/12 -m comment --comment "BOGONS" -j DROP
iptables -t raw -A PREROUTING -s 192.0.2.0/24 -m comment --comment "BOGONS" -j DROP
iptables -t raw -A PREROUTING -s 10.0.0.0/8 -m comment --comment "BOGONS" -j DROP
iptables -t raw -A PREROUTING -s 0.0.0.0/8 -m comment --comment "BOGONS" -j DROP
iptables -t raw -A PREROUTING -s 240.0.0.0/5 -m comment --comment "BOGONS" -j DROP
iptables -t raw -A PREROUTING -s 127.0.0.0/8 ! -i lo -m comment --comment "Only lo iface can have an addr-range of 127.0.0.x/8" -j DROP
iptables -t raw -A PREROUTING -m limit --limit 100/s --limit-burst 10000 -j RETURN # changed to lower number incase you're recylcling an old PC or NUC or SBC device to use as gateway (there's a better way to do this with hashes and ipset but I can't remember offhand)


iptables -t mangle -A PREROUTING -m conntrack --ctstate INVALID -j DROP
iptables -t mangle -A PREROUTING -p tcp ! --syn -m conntrack --ctstate NEW -m comment --comment "DROP new packets that don't present the SYN flag" -j DROP
iptables -t mangle -A PREROUTING -p tcp -m conntrack --ctstate NEW -m tcpmss ! --mss 536:65535 -m comment --comment "DROP new pkts that have malformed mss values" -j DROP
iptables -t mangle -A PREROUTING -p tcp --tcp-flags FIN,SYN,RST,PSH,ACK,URG NONE -j DROP
iptables -t mangle -A PREROUTING -p tcp --tcp-flags FIN,SYN FIN,SYN -j DROP
iptables -t mangle -A PREROUTING -p tcp --tcp-flags SYN,RST SYN,RST -j DROP
iptables -t mangle -A PREROUTING -p tcp --tcp-flags FIN,RST FIN,RST -j DROP
iptables -t mangle -A PREROUTING -p tcp --tcp-flags FIN,ACK FIN -j DROP
iptables -t mangle -A PREROUTING -p tcp --tcp-flags ACK,URG URG -j DROP
iptables -t mangle -A PREROUTING -p tcp --tcp-flags ACK,FIN FIN -j DROP
iptables -t mangle -A PREROUTING -p tcp --tcp-flags ACK,PSH PSH -j DROP
iptables -t mangle -A PREROUTING -p tcp --tcp-flags ALL ALL -m comment --comment "xmas pkts (xmas portscanners)" -j DROP
iptables -t mangle -A PREROUTING -p tcp --tcp-flags ALL NONE -m comment --comment "null pkts (null portscanners)" -j DROP
iptables -t mangle -A PREROUTING -p tcp --tcp-flags ALL FIN,PSH,URG -j DROP
iptables -t mangle -A PREROUTING -p tcp --tcp-flags ALL SYN,FIN,PSH,URG -j DROP
iptables -t mangle -A PREROUTING -p tcp --tcp-flags ALL SYN,RST,ACK,FIN,URG -j DROP
iptables -t mangle -A PREROUTING -p tcp --tcp-flags SYN,ACK,FIN,RST RST -m limit --limit 1/s --limit-burst 2 -m comment --comment "limit RST pkts (half-handshakes)" -j DROP
iptables -t mangle -A PREROUTING -s 224.0.0.0/3 -m comment --comment "BOGONS" -j DROP
iptables -t mangle -A PREROUTING -s 169.254.0.0/16 -m comment --comment "BOGONS" -j DROP
iptables -t mangle -A PREROUTING -s 172.16.0.0/12 -m comment --comment "BOGONS" -j DROP
iptables -t mangle -A PREROUTING -s 192.0.2.0/24 -m comment --comment "BOGONS" -j DROP
iptables -t mangle -A PREROUTING -s 10.0.0.0/8 -m comment --comment "BOGONS" -j DROP
iptables -t mangle -A PREROUTING -s 0.0.0.0/8 -m comment --comment "BOGONS" -j DROP
iptables -t mangle -A PREROUTING -s 240.0.0.0/5 -m comment --comment "BOGONS" -j DROP
iptables -t mangle -A PREROUTING -s 127.0.0.0/8 ! -i lo -m comment --comment "Only lo iface can have an addr-range of 127.0.0.x/8" -j DROP
#iptables -t mangle -A PREROUTING -s 192.168.0.0/16 -m comment --comment "BOGONS" -j DROP # check if you require this CLASS C addr-range before enabling
#iptables -t mangle -A PREROUTING -p icmp -m comment --comment "unecessary drop rule without useful accept rules" -j DROP # try accepting echo-requests, echo-replies and source-quench pkts (maybe exceeded icmp pkts too


iptables -A INPUT -i lo -j ACCEPT
iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -m comment --comment "ESTABLISHED,RELATED conns quick accept" -j ACCEPT
iptables -A INPUT -m comment --comment "Security Rules" -j IN_DPI_RULES
iptables -A INPUT -m comment --comment "Allowed Ports and Services" -j IN_CUSTOMRULES
#iptables -A INPUT -m comment --comment "Log All Dropped packets" -j LOG --log-prefix "[IPTABLES-BLOCKED]: " --log-level 7 ## This rule is mostly for debug incase you missed a rule or service to allow in
iptables -A INPUT -m comment --comment "Explicitly DROP other connections" -j DROP


iptables -A FORWARD -i lo -j ACCEPT
iptables -A FORWARD -m conntrack --ctstate RELATED,ESTABLISHED -m comment --comment "RELATED,ESTABLISHED conns quick accept" -j ACCEPT
iptables -A FORWARD -m conntrack --ctstate INVALID -m comment --comment "Drop INVALID state connections" -j DROP
#iptables -A FORWARD -m conntrack --ctstate UNTRACKED -m comment --comment "Drop UNTRACKED state connections" -j DROP
iptables -A FORWARD -s 10.8.0.0/24 -j ACCEPT


iptables -A OUTPUT -o lo -j ACCEPT
iptables -A OUTPUT -m conntrack --ctstate RELATED,ESTABLISHED -m comment --comment "RELATED,ESTABLISHED conns quick accept" -j ACCEPT
iptables -A OUTPUT -m conntrack --ctstate NEW -m comment --comment "Egress - NEW counters" -j ACCEPT
iptables -A OUTPUT -m comment --comment "Egress - LOG DROPPED PACKETS counters" -j LOG --log-prefix "[OUT-BLOCKED]: " --log-level 7
iptables -A OUTPUT -m comment --comment "Egress - DROPPED PACKETS counters" -j DROP


#iptables -A IN_DPI_RULES -m conntrack --ctstate INVALID -m comment --comment "Drop INVALID state connections" -j LOG --log-prefix "[BLOCKED-TCP-INVALID]: " --log-level 7 ## sample log rules to see what makes it passed our raw and mangle rules
iptables -A IN_DPI_RULES -m conntrack --ctstate INVALID -m comment --comment "Drop INVALID state connections" -j DROP
#iptables -A IN_DPI_RULES -m conntrack --ctstate UNTRACKED -m comment --comment "Drop UNTRACKED state connections" -j LOG --log-prefix "[BLOCKED-TCP-UNTRACKED]: " --log-level 7
iptables -A IN_DPI_RULES -m conntrack --ctstate UNTRACKED -m comment --comment "Drop UNTRACKED state connections" -j DROP
iptables -A IN_DPI_RULES -m comment --comment "Jump back to main filter rules" -j RETURN


iptables -A IN_CUSTOMRULES -p tcp -m tcp --dport 22 -m conntrack --ctstate NEW -s 0.0.0.0/0 -m comment --comment "Allow SSH" -j SAFEZONE
iptables -A IN_CUSTOMRULES -p tcp -m tcp --dport 222 -m conntrack --ctstate NEW -s 0.0.0.0/0 -m comment --comment "Allow SSH alt" -j SAFEZONE # if you have DNAT on this port then you can leave this rule out due to DNAT occuring before this chain
iptables -A IN_CUSTOMRULES -p tcp -m tcp --dport 80 -m conntrack --ctstate NEW -s 0.0.0.0/0 -m comment --comment "Allow http" -j ACCEPT
iptables -A IN_CUSTOMRULES -p tcp -m tcp --dport 80 -m conntrack --ctstate NEW -s 0.0.0.0/0 -m comment --comment "Allow http" -j ACCEPT
iptables -A IN_CUSTOMRULES -p tcp -m tcp --dport 443 -m conntrack --ctstate NEW -s 0.0.0.0/0 -m comment --comment "Allow https" -j ACCEPT
iptables -A IN_CUSTOMRULES -p udp -m udp --dport 443 -m conntrack --ctstate NEW -s 0.0.0.0/0 -m comment --comment "Allow quic" -j ACCEPT
iptables -A IN_CUSTOMRULES -p tcp -m tcp --dport 1194 -m conntrack --ctstate NEW -s 0.0.0.0/0 -m comment --comment "Allow OpenVPN" -j ACCEPT
iptables -A IN_CUSTOMRULES -p tcp -m tcp --dport 25565 -m conntrack --ctstate NEW -s 0.0.0.0/0 -m comment --comment "Allow whatever tcp server is behind this port" -j ACCEPT
iptables -A IN_CUSTOMRULES -p udp -m udp --dport 123 -m conntrack --ctstate NEW -s 0.0.0.0/0 -m comment --comment "Allow NTP" -j ACCEPT
iptables -A IN_CUSTOMRULES -p udp -m udp --dport 1194 -m conntrack --ctstate NEW -s 0.0.0.0/0 -m comment --comment "Allow OpenVPN" -j ACCEPT
iptables -A IN_CUSTOMRULES -p ICMP --icmp-type 0 -s 0.0.0.0/0 -m comment --comment "ICMP ping" -j ACCEPT
iptables -A IN_CUSTOMRULES -p ICMP --icmp-type 8 -s 0.0.0.0/0 -m comment --comment "ICMP ping" -j ACCEPT
iptables -A IN_CUSTOMRULES -p ICMP --icmp-type 11 -s 0.0.0.0/0 -m comment --comment "ICMP traceroute" -j ACCEPT
iptables -A IN_CUSTOMRULES -m comment --comment "Jump back to main filter rules" -j RETURN
iptables -A IN_CUSTOMRULES -m comment --comment "Explicit drop rule */paranoid*/" -j DROP


iptables -A SAFEZONE -i lo -j RETURN
iptables -A SAFEZONE -s x.x.x.x/32 -m comment --comment "allow-ingress-from-xxx-secure-IP" -j ACCEPT
iptables -A SAFEZONE -s x.x.x.x/32 -m comment --comment "allow-ingress-from-xxx-secure-IP" -j ACCEPT
iptables -A SAFEZONE -s x.x.x.x/32 -m comment --comment "allow-ingress-from-xxx-hq" -j ACCEPT
iptables -A SAFEZONE -m comment --comment "JUMP back to IN_CUSTOMRULES chain" -j RETURN
# iptables iptables -A INPUT -p tcp -m connlimit --connlimit-above 111 -j REJECT --reject-with tcp-reset ## There's no reason to have this rule if you're already dropping pkts in RAW and MANGLE tables' prerouting chain.
