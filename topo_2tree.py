#coding=utf-8
#子网掩码默认8位

#像普通mininet一样，ovs不放在docker里

#    docker exec 97 iptables -t filter -I INPUT -s 192.168.1.1 -j REJECT
#    docker exec 97 iptables -t filter -nL INPUT
#    python3.4 sfc_agent.py --rest --odl-ip-port 192.168.1.5:8181 --auto-sff-name
#    unset http_proxy https_proxy ftp_proxy socks_proxy
import sys, os
from mn_wifi.cli import CLI_wifi
from mn_wifi.net import Mininet_wifi, Containernetcx
from mn_wifi.link import TCWirelessLink
import sqlite3

#print(sys.path) #cx
from mininet.node import Controller, RemoteController, Ryu, OVSKernelSwitch
from mininet.log import setLogLevel, info
#from mininet.net import Containernet
from mininet.link import TCLink

#注意不连控制器的时候要关掉fail-mode
def topology():
    "Create a network."
    #net = Mininet_wifi( controller=Controller )
    net = Containernetcx( link=TCLink, autoSetMacs=True )
    
    info('*** Adding switches\n')
    s2   = net.addSwitch('s2',   cls=OVSKernelSwitch, dpid='0000000000000002') 
    s3   = net.addSwitch('s3',   cls=OVSKernelSwitch, dpid='0000000000000003') 
    s4   = net.addSwitch('s4',   cls=OVSKernelSwitch, dpid='0000000000000004') 
    s5   = net.addSwitch('s5',   cls=OVSKernelSwitch, dpid='0000000000000005') 
    s6   = net.addSwitch('s6',   cls=OVSKernelSwitch, dpid='0000000000000006') 
    s7   = net.addSwitch('s7',   cls=OVSKernelSwitch, dpid='0000000000000007') 
    
    info('*** Adding docker containers\n')
    # node2
    cdn1    = net.addDocker( 'cdn1',    ip='192.168.20.21/24', dimage="ubuntu14.04:ids", network_mode="none")
    client1 = net.addDocker( 'client1', ip='192.168.20.22/24', dimage="ubuntu14.04:ids", network_mode="none")
    # node3
    cdn2    = net.addDocker( 'cdn2',    ip='192.168.20.31/24', dimage="ubuntu14.04:ids", network_mode="none")
    dns     = net.addDocker( 'dns',     ip='192.168.20.32/24', dimage="ubuntu14.04:ids", network_mode="none")
    ids     = net.addDocker( 'ids',     ip='192.168.20.33/24', dimage="ubuntu14.04:ids", network_mode="none")
    # node4
    client2 = net.addDocker( 'client2', ip='192.168.20.41/24', dimage="ubuntu14.04:ids", network_mode="none")
    cdn3    = net.addDocker( 'cdn3',    ip='192.168.20.42/24', dimage="ubuntu14.04:ids", network_mode="none")
    firewall= net.addDocker( 'firewall',ip='192.168.20.43/24', dimage="ubuntu14.04:ids", network_mode="none")
    # node5
    web     = net.addDocker( 'web',     ip='192.168.20.51/24', dimage="ubuntu14.04:ids", network_mode="none")
    
    
    info('*** Adding controller\n')
    ryu = net.addController('ryu',controller=RemoteController, ip='192.168.1.5', port=6653)
    

    info('*** Adding links\n')
    net.addLink(s6, s2)
    net.addLink(s6, s3)
    net.addLink(s6, s4)
    net.addLink(s6, s5)
    
    net.addLink(s7, s2)
    net.addLink(s7, s3)
    net.addLink(s7, s4)
    net.addLink(s7, s5)
    
    net.addLink(cdn1,    s2)
    net.addLink(client1, s2)
    net.addLink(cdn2,    s3)
    net.addLink(dns,     s3)
    net.addLink(ids,     s3)
    net.addLink(client2, s4)
    net.addLink(cdn3,    s4)
    net.addLink(firewall,s4)
    net.addLink(web,     s5)

    print "*** Starting network"
    net.start()

#    info("*** Configuring Switches\n")
#    s2.cmd( 'ovs-vsctl set bridge s2 stp_enable=true' )
#    s3.cmd( 'ovs-vsctl set bridge s3 stp_enable=true' )
#    s4.cmd( 'ovs-vsctl set bridge s4 stp_enable=true' )
#    s5.cmd( 'ovs-vsctl set bridge s5 stp_enable=true' )
#    s6.cmd( 'ovs-vsctl set bridge s6 stp_enable=true' )
#    s7.cmd( 'ovs-vsctl set bridge s7 stp_enable=true' )
    
    #mininet默认是fail_mode=secure    
#    s2.cmd( 'ovs-vsctl set-fail-mode s2 standalone' )
#    s3.cmd( 'ovs-vsctl set-fail-mode s3 standalone' )
#    s4.cmd( 'ovs-vsctl set-fail-mode s4 standalone' )
#    s5.cmd( 'ovs-vsctl set-fail-mode s5 standalone' )
#    s6.cmd( 'ovs-vsctl set-fail-mode s6 standalone' )
#    s7.cmd( 'ovs-vsctl set-fail-mode s7 standalone' )

    info("*** Closing route redirect\n")
    ids.cmd('echo 0 > /proc/sys/net/ipv4/conf/all/send_redirects')
    ids.cmd('echo 0 > /proc/sys/net/ipv4/conf/default/send_redirects')
    ids.cmd('echo 0 > /proc/sys/net/ipv4/conf/ids-eth0/send_redirects')
    
    firewall.cmd('echo 0 > /proc/sys/net/ipv4/conf/all/send_redirects')
    firewall.cmd('echo 0 > /proc/sys/net/ipv4/conf/default/send_redirects')
    firewall.cmd('echo 0 > /proc/sys/net/ipv4/conf/firewall-eth0/send_redirects')
    
    info("*** Running CLI\n")
    CLI_wifi(net)

    info("*** Stopping network\n")
    net.stop()


if __name__ == '__main__':
    setLogLevel('info')
    topology()
