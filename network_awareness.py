# coding=utf-8

# Copyright (C) 2016 Li Cheng at Beijing University of Posts
# and Telecommunications. www.muzixing.com
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import logging
import struct
import copy
import networkx as nx
from operator import attrgetter
from ryu import cfg
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import CONFIG_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types
from ryu.lib.packet import ipv4
from ryu.lib.packet import arp
from ryu.lib import hub

from ryu.topology import event, switches
from ryu.topology.api import get_switch, get_link
import matplotlib.pyplot as plt

# user defined
import setting


CONF = cfg.CONF

ETHERNET_GROUP_MULTICAST = "01:00:5e:00:00:fb"

# arp_proxy
import threading  # timer
ETHERNET = ethernet.ethernet.__name__
ETHERNET_MULTICAST = "ff:ff:ff:ff:ff:ff"
ETHERNET_GROUP_MULTICAST = "01:00:5e:00:00:fb"
ARP = arp.arp.__name__


class NetworkAwareness(app_manager.RyuApp):
    """
        NetworkAwareness is a Ryu app for discover topology information.
        This App can provide many data services for other App, such as
        link_to_port, access_table, switch_port_table,access_ports,
        interior_ports,topology graph and shortest paths.

    """
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(NetworkAwareness, self).__init__(*args, **kwargs)
        self.topology_api_app = self
        self.name = "awareness"
        self.switches = []           # [dpid]  [1, 2]
        self.link_to_port = {}       # {(src_dpid,dst_dpid):(src_port,dst_port)}  {(1, 2): (2, 1), (2, 1): (1, 2)}
        self.access_table = {}       # {(dpid,port):(host_ip,host_mac)}  {(1, 1): ('192.168.2.100', '00:00:00:00:00:01'), (2, 1): ('192.168.2.200', '00:00:00:00:00:02')}
        self.access_table_distinct = {} 
        self.switch_port_table = {}  # dpip->port_num  {1: set([1, 2]), 2: set([1, 2])}
        self.access_ports = {}       # dpid->port_num  {1: set([1]), 2: set([2])}  #连其他的端口，比如主机
        self.interior_ports = {}     # dpid->port_num  {1: set([2]), 2: set([1])}  #连交换机的端口
        self.graph = nx.DiGraph()    # 有向图
        self.pre_graph = nx.DiGraph()
        self.pre_access_table = {}
        self.pre_link_to_port = {}
        self.shortest_paths = None
        # Start a green thread to discover network resource.
        self.discover_thread = hub.spawn(self._discover)

    def _discover(self):
        while True:
            self.get_topology(None)
            try:
#                self.show_topology()
                pass
            except Exception:
                print "please input pingall in mininet and wait a moment"
            hub.sleep(10)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        """
            Initial operation, send miss-table flow entry to datapaths.
        """
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        self.logger.info("awareness>>> switch:%s connected", datapath.id)

        # install table-miss flow entry
        match = parser.OFPMatch()  # no match
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.del_flow(datapath, match)   #delete all flow entries
        print "awareness>>> add default flow"
        self.add_flow(datapath, 0, match, actions)

    def add_flow(self, dp, p, match, actions, idle_timeout=0, hard_timeout=0):
        ofproto = dp.ofproto
        parser = dp.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]

        mod = parser.OFPFlowMod(datapath=dp, priority=p,
                                idle_timeout=idle_timeout,
                                hard_timeout=hard_timeout,
                                match=match, instructions=inst)
        dp.send_msg(mod)

    def del_flow(self, datapath, match):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        mod = parser.OFPFlowMod(datapath=datapath,
                    command=ofproto.OFPFC_DELETE,
                    out_port=ofproto.OFPP_ANY,
                    out_group=ofproto.OFPG_ANY,
                    match=match)
        datapath.send_msg(mod)
        
#    def get_host_location(self, host_ip):
#        """
#            Get host location info:(datapath, port) according to host ip.
#        """
#        for key in self.access_table.keys():
#            if self.access_table[key][0] == host_ip:
#                return key  # (dpid, port)
#        self.logger.info("%s location is not found." % host_ip)
#        return None

    def get_switches(self):
        return self.switches

    def get_links(self):
        return self.link_to_port


    def get_graph(self, link_list):
        """
            Get Adjacency matrix from link_to_port
        """
#        print "link_list:", link_list  #cx
        for src in self.switches:
            for dst in self.switches:
                if src == dst:
                    self.graph.add_edge(src, dst, weight=0)
                elif (src, dst) in link_list:
                    self.graph.add_edge(src, dst, weight=1)
        return self.graph

    def create_port_map(self, switch_list):
        """
            Create interior_port table and access_port table. 
        """
        for sw in switch_list:
            dpid = sw.dp.id
            self.switch_port_table.setdefault(dpid, set())
            self.interior_ports.setdefault(dpid, set())
            self.access_ports.setdefault(dpid, set())

            for p in sw.ports:
                self.switch_port_table[dpid].add(p.port_no)

    def create_interior_links(self, link_list):
        """
            Get links`srouce port to dst port  from link_list,
            link_to_port:(src_dpid,dst_dpid)->(src_port,dst_port)
        """
        for link in link_list:
            src = link.src
            dst = link.dst
            self.link_to_port[(src.dpid, dst.dpid)] = (src.port_no, dst.port_no)

            # Find the access ports and interior ports
            if link.src.dpid in self.switches:
                self.interior_ports[link.src.dpid].add(link.src.port_no)
            if link.dst.dpid in self.switches:
                self.interior_ports[link.dst.dpid].add(link.dst.port_no)
            

    def create_access_ports(self):
        """
            Get ports without link into access_ports
        """
        for sw in self.switch_port_table:
            all_port_table = self.switch_port_table[sw]
            interior_port = self.interior_ports[sw]
            self.access_ports[sw] = all_port_table - interior_port

    def k_shortest_paths(self, graph, src, dst, weight='weight', k=1):
        """
            Great K shortest paths of src to dst.
        """
        # dijkstra_path
        shortest_paths = []
        try:                                     
            sp = nx.dijkstra_path(graph, source=src, target=dst)
            shortest_paths.append(sp)
#            print "dijkstra:", sp  #cx
#            print "shortest_paths:", shortest_paths  #cx
            return shortest_paths
        except:
            self.logger.debug("No path between %s and %s" % (src, dst))
                    
        # shortest_simple_paths
#        generator = nx.shortest_simple_paths(graph, source=src,
#                                             target=dst, weight=weight)                                                 
#        shortest_paths = []
#        try:
#            for path in generator:
#                if k <= 0:
#                    break
#                shortest_paths.append(path)
#                k -= 1
#            return shortest_paths
#        except:
#            self.logger.debug("No path between %s and %s" % (src, dst))

    def all_k_shortest_paths(self, graph, weight='weight', k=1):
        """
            Creat all K shortest paths between datapaths.
        """
        _graph = copy.deepcopy(graph)
        paths = {}

        # Find ksp in graph.
        for src in _graph.nodes():
            paths.setdefault(src, {src: [[src] for i in xrange(k)]})
            for dst in _graph.nodes():
                if src == dst:
                    continue
                paths[src].setdefault(dst, [])
                paths[src][dst] = self.k_shortest_paths(_graph, src, dst,
                                                        weight=weight, k=k)
        return paths

    # List the event list should be listened.
    events = [event.EventSwitchEnter,
              event.EventSwitchLeave, event.EventPortAdd,
              event.EventPortDelete, event.EventPortModify,
              event.EventLinkAdd, event.EventLinkDelete]
    @set_ev_cls(events)
    def get_topology(self, ev):
        """
            Get topology info and calculate shortest paths.
        """
        self.create_port_map(get_switch(self.topology_api_app))
#        print "self.switch_port_table:%r" % self.switch_port_table
        
        self.switches = self.switch_port_table.keys()
#        print "self.switches:%r" % self.switches
        
        self.create_interior_links(get_link(self.topology_api_app))
#        print "self.link_to_port:%r" % self.link_to_port
#        print "self.interior_ports:%r" % self.interior_ports
        
        self.create_access_ports()
#        print "self.access_ports:%r" % self.access_ports
        
        self.get_graph(self.link_to_port.keys())
#        print "self.graph:%r" % self.graph
#        nx.draw(self.graph)
#        plt.show()
#        plt.savefig("topo.png")
        
        self.shortest_paths = self.all_k_shortest_paths(self.graph, weight='weight', k=CONF.k_paths)  # CONF.k_paths=1
#        print "self.shortest_paths:%r" % self.shortest_paths  # {1: {1: [[1]], 2: [[1, 2]]}, 2: {1: [[2, 1]], 2: [[2]]}}
        
#        shortest_path = self.k_shortest_paths(self.graph, 1, 2)
#        print "shortest_path:%r" % shortest_path  # [[1, 2]]


    def register_access_info(self, dpid, in_port, ip, mac):
        """
            Register access host info into access table.
        """
        if in_port in self.access_ports[dpid]:
            if (dpid, in_port, ip) in self.access_table_distinct:
                if self.access_table_distinct[(dpid, in_port, ip)] == (ip, mac):  #cx
                    return
                else:
                    self.access_table[(dpid, in_port)] = (ip, mac)
                    self.access_table_distinct[(dpid, in_port, ip)] = (ip, mac)  #cx
                    return
            else:
                self.access_table.setdefault((dpid, in_port), None)
                self.access_table[(dpid, in_port)] = (ip, mac)
                
                self.access_table_distinct.setdefault((dpid, in_port, ip), None)  #cx
                self.access_table_distinct[(dpid, in_port, ip)] = (ip, mac)  #cx
                
                return

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        """
            Hanle the packet in packet, and register the access info.
        """
        if ev.msg.msg_len < ev.msg.total_len:
            self.logger.debug("packet truncated: only %s of %s bytes",
                              ev.msg.msg_len, ev.msg.total_len)
#        print "myapp"
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']
        # 包过滤开始
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]  # pkt.get_protocols(ethernet.ethernet)是个列表，列表里只有一个元素，用[0]直接取出元素
                                                       # 所有的包都有以太网头部，所以能直接get，但是ip等协议需要判断是否存在
#        print "pkt.get_protocols:", pkt.get_protocols, '\n'
#        print "pkt.get_protocols(ethernet.ethernet)[0]:", pkt.get_protocols(ethernet.ethernet)[0], '\n'


        if eth.ethertype == ether_types.ETH_TYPE_LLDP or eth.ethertype == ether_types.ETH_TYPE_IPV6:
            # ignore lldp packet 
            return
        dst = eth.dst
        src = eth.src
        dpid = datapath.id
        
        if dst == ETHERNET_GROUP_MULTICAST:
            # ignore mDNS packet
#            print "Drop eth_dst == 01:00:5e:00:00:fb"
            return
        if eth.ethertype == ether_types.ETH_TYPE_IP and dst == ETHERNET_MULTICAST:  # DHCP广播包, IP=0x0800
            # ignore DHCP packet
#            print "Drop ip_type and eth_dst == ff:ff:ff:ff:ff:ff"
            return
            
#        print "pkt.get_protocols:", pkt.get_protocols, '\n'
        header_list = dict( (p.protocol_name, p)for p in pkt.protocols if type(p) != str)
#        print "header_list:", header_list
        if ipv4 in header_list:
            ipv4_packet = pkt.get_protocols(ipv4.ipv4)[0]
#            print "pkt.get_protocols(ipv4.ipv4)[0]:", pkt.get_protocols(ipv4.ipv4)[0], '\n'
            if ipv4_packet.src == "0.0.0.0" or ipv4_packet.dst == "255.255.255.255":
                # ignore DHCP packet
#                print "Drop ip_src == 0.0.0.0 or ip_dst == 255.255.255.255"    
                return
        # 包过滤结束
              
        # 获取access info
        arp_pkt = pkt.get_protocol(arp.arp)
        ip_pkt = pkt.get_protocol(ipv4.ipv4)
#        print "ip_pkt:", ip_pkt, '\n'
        if arp_pkt:
            arp_src_ip = arp_pkt.src_ip
#            arp_dst_ip = arp_pkt.dst_ip
            mac = arp_pkt.src_mac
            # Record the access info
            self.register_access_info(datapath.id, in_port, arp_src_ip, mac)
        elif ip_pkt:
            if ip_pkt.src == "0.0.0.0" or ip_pkt.dst == "255.255.255.255":
                # ignore DHCP packet
#                print "Drop 0.0.0.0 -> 255.255.255.255"
                return            
            src_ip = ip_pkt.src
#            dst_ip = ip_pkt.dst
            mac = src
            # Record the access info
            self.register_access_info(datapath.id, in_port, src_ip, mac)
#        print "aware>>> self.access_table:%r" % self.access_table

    def show_topology(self):
        switch_num = len(list(self.graph.nodes()))
#        if self.pre_graph != self.graph and setting.TOSHOW:
        if setting.TOSHOW:
            print "---------------------Topo Link---------------------"
            print '%10s' % ("switch"),
            for i in self.graph.nodes():
                print '%10d' % i,
            print ""
            for i in self.graph.nodes():
                print '%10d' % i,
                for j in self.graph[i].values():
                    if not j:
                        print '%10s' % 'No',   # ???
                    else:
                        print '%10.0f' % j['weight'],
                print ""
            self.pre_graph = copy.deepcopy(self.graph)

#        if self.pre_link_to_port != self.link_to_port and setting.TOSHOW:
        if setting.TOSHOW:
            print "---------------------Link Port---------------------"
            print '%10s' % ("switch"),
            for i in self.graph.nodes():
                print '%10d' % i,
            print ""
            for i in self.graph.nodes():
                print '%10d' % i,
                for j in self.graph.nodes():
                    if (i, j) in self.link_to_port.keys():
                        print '%10s' % str(self.link_to_port[(i, j)]),
                    else:
                        print '%10s' % "No-link",
                print ""
            self.pre_link_to_port = copy.deepcopy(self.link_to_port)

#        if self.pre_access_table != self.access_table and setting.TOSHOW:
        if setting.TOSHOW:
            access_table_keys_list = sorted(self.access_table.keys())   # [(3, 1), (3, 2), (4, 1), (4, 2), (6, 1), (6, 2), (7, 1), (7, 2)]
            print "---------------------Access Host-------------------"
            print '%10s' % ("switch"), '%20s' % "Host"
            if not access_table_keys_list:
                print "    Not found host"
            else:
                for tup in access_table_keys_list:
                    print '%10d:    ' % tup[0], self.access_table[tup]
            self.pre_access_table = copy.deepcopy(self.access_table)
            
            
