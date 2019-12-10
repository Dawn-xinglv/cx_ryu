#coding=utf-8

#   ryu-manager myapp.py --observe-links
#   ryu-manager myapp.py --log-dir /home/jkw/mininetcx/sfc_ryu --observe-links
#   ryu-manager myapp.py --log-dir /home/jkw/ryu_sfc/cx_ryu --log-file ryu.log --observe-links

import sqlite3
import json
import copy
import logging
import datetime
from ryu.app.wsgi import ControllerBase, WSGIApplication, route
from webob import Response
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER,CONFIG_DISPATCHER,DEAD_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3

from ryu.lib.packet import packet
from ryu.lib.packet import ethernet, arp, ipv4
from ryu.lib.packet import ether_types

from ryu.topology import event, switches
from ryu.topology.api import get_switch, get_link, get_host
from ryu.lib import hub
# network_awareness
import network_awareness
# gui
import os
from webob.static import DirectoryApp
PATH = os.path.dirname(__file__)
# user defined
import setting
# arp_proxy
import threading  # timer
#import time
ETHERNET = ethernet.ethernet.__name__
ETHERNET_MULTICAST = "ff:ff:ff:ff:ff:ff"
ETHERNET_ZERO = "00:00:00:00:00:00"
ETHERNET_GROUP_MULTICAST = "01:00:5e:00:00:fb"
ARP = arp.arp.__name__
IPv4 = ipv4.ipv4.__name__

sfc_instance_name = 'sfc_api_app'

#add_flow()  inst_flag
GOTOTABLE = 1    
ACTIONS   = 0

#create_link_to_port()   self.host_or_switch = {}
SWITCH = 1
HOST   = 2

#sfc_add_flow()
find_vnf_flag = 0     # 1:find  0:not find
#PATH1 = [2, 3, 4, 5]   # sfc_path, start from classifier  #dpid

class SFCController(ControllerBase):
    def __init__(self, req, link, data, **config):
        super(SFCController, self).__init__(req, link, data, **config)
        self.sfc_api_app = data[sfc_instance_name]
        # gui
        path = "%s/html/" % PATH
        self.static_app = DirectoryApp(path)
        sfc_app.logger.info('SFCController Init')
        
# JUST FOR FUN
#    @route('hello', '/{greeting}/{name}', methods=['GET'])
#    def hello(self, req, **kwargs):
#        print kwargs
#        greeting = kwargs['greeting']
#        name = kwargs['name']
#        message = greeting +' '+ name
#        privet = {'message': message}
#        body = json.dumps(privet)
        
#        return Response(content_type='application/json', body=body)

    @route('sfc-add-flow', '/sfc_add_flow/{sfc_nsh_spi}', methods=['GET'])   #data来自数据库而不是REST，所以用GET方法
    def sfc_add_flow(self,req, **kwargs):
        sfc_app = self.sfc_api_app
        # get sfc information
        #---------------connect to sfc_db.sqlite----------------------------------
        conn = sqlite3.connect('sfc_db.sqlite')
        cur = conn.cursor()
        cur.execute('''select * from sfc where sfc_nsh_spi = ?''',(kwargs['sfc_nsh_spi'],))
        flow_spec = cur.fetchone()
        if not flow_spec: 
            return Response(status = 404)
        sfc_app.logger.debug("flow_spec: %s", flow_spec)
        (sfc_id, sfc_nsh_spi, sfc_nsh_si, ipv4_src, ipv4_dst, sf1_ip, sf2_ip, sf3_ip, sf4_ip, sf5_ip)=flow_spec
        sf_ip = [sf1_ip, sf2_ip, sf3_ip, sf4_ip, sf5_ip, None]    # end with None
        sfc_app.logger.debug("sf_ip: %r" % sf_ip)
        # get path information
        cur.execute('''select * from sfc_path where sfc_nsh_spi = ?''',(kwargs['sfc_nsh_spi'],))
        path_spec = cur.fetchone()
        sfc_path = []
        for i in path_spec[2:]:   # remove those value = None
            if i != None:
                sfc_path.append(i)
        sfc_app.logger.info("sfc_path: %r", sfc_path)
        conn.close()
        #---------------close sfc_db.sqlite---------------------------------------
        sf_ip_index = 0
        if sf_ip[sf_ip_index] != None:
            next_sf_ip = sf_ip[sf_ip_index]
            sf_ip_index += 1
        else:
            sfc_app.logger.warning("No service function was specified!")         
            return Response(status = 200)
        # add flow
        # c1:push_mpls--------------------------------------------------------
        dpid = sfc_path[0]
        next_dpid = sfc_path[1]
        dp = sfc_app.datapaths[dpid]
        priority = 10
        # ip -> mac -> in_por
#        print "sfc_app.awareness.access_table_distinct:%r\n" % sfc_app.awareness.access_table_distinct  #cx
        for a, b in sfc_app.awareness.access_table_distinct.items():
            dpid_in_dict = a[0]
            port_in_dict = a[1]
            src_ip  = b[0]
            src_mac = b[1]
            if src_ip == ipv4_src:
                src_mac1 =src_mac
                break
        for c, d in sfc_app.mac_to_port.items():  # {dpid:{mac:port}} 
            dpid_in_dict = c
            if dpid_in_dict == dpid:
                in_port_for_classifier = d[src_mac1]
                break
        in_port = in_port_for_classifier 
        (dpid_out_port, next_dpid_in_port) = sfc_app.link_to_port[(dpid,next_dpid)]
        match = dp.ofproto_parser.OFPMatch(in_port=in_port, eth_type=0x0800, ipv4_src=ipv4_src, ipv4_dst=ipv4_dst) 
        mpls_label = sfc_nsh_spi<<8 | sfc_nsh_si
        actions  = [dp.ofproto_parser.OFPActionPushMpls()]   #push mpls
        actions += [dp.ofproto_parser.OFPActionSetField(mpls_label=mpls_label)]
        actions += [dp.ofproto_parser.OFPActionOutput(dpid_out_port)]
        sfc_app.add_flow(dp, priority, match, actions, table_id=0, inst_flag=ACTIONS)
        #-----------------------sff for loop start-----------------------------
        for i in range(2, len(sfc_path)):  # range[ ), range(2,5)=[2,3,4]
            # sff1: 1.pop_mpls 2.push_mpls
            dpid = next_dpid
            next_dpid = sfc_path[i]    #4
            dp = sfc_app.datapaths[dpid]
            priority = 10
            in_port = next_dpid_in_port
            find_vnf_flag = 0  #clear flag
            if next_sf_ip != None:
                for a, b in sfc_app.awareness.access_table_distinct.items():
                    dpid_in_dict = a[0]
                    port_in_dict = a[1]
                    dst_ip  = b[0]
                    dst_mac = b[1]           
#                    print "dpid_in_dict:%r , port_in_dict:%r , dst_mac:%r , dst_ip:%r " % (dpid_in_dict, port_in_dict, dst_mac, dst_ip) #cx
                    if dpid_in_dict == dpid and dst_ip == next_sf_ip:  # find vnf in this datapath
                        # pop_mpls
                        match = dp.ofproto_parser.OFPMatch(in_port=in_port, eth_type=0x8847, mpls_label=mpls_label)
                        actions  = [dp.ofproto_parser.OFPActionPopMpls(0x0800)] 
                        actions += [dp.ofproto_parser.OFPActionSetField(eth_dst=dst_mac)] 
                        actions += [dp.ofproto_parser.OFPActionOutput(port_in_dict)] 
                        sfc_app.add_flow(dp, priority, match, actions, table_id=0, inst_flag=ACTIONS)
                        # push_mpls
                        in_port = port_in_dict
#                        print "self.link_to_port{}: %r\n" % sfc_app.link_to_port  #cx
                        (dpid_out_port, next_dpid_in_port) = sfc_app.link_to_port[(dpid,next_dpid)]
                        match = dp.ofproto_parser.OFPMatch(in_port=in_port, eth_type=0x0800, ipv4_src=ipv4_src, ipv4_dst=ipv4_dst) 
                        mpls_label = mpls_label-1
                        actions  = [dp.ofproto_parser.OFPActionPushMpls()]   #push mpls
                        actions += [dp.ofproto_parser.OFPActionSetField(mpls_label=mpls_label)] 
                        actions += [dp.ofproto_parser.OFPActionOutput(dpid_out_port)] 
                        sfc_app.add_flow(dp, priority, match, actions, table_id=0, inst_flag=ACTIONS)
                        find_vnf_flag = 1
                        break
                
            if find_vnf_flag == 0:  # not find vnf in this datapath
                # forward to next switch 
#                print "self.link_to_port{}: %r\n" % sfc_app.link_to_port  #cx
                (dpid_out_port, next_dpid_in_port) = sfc_app.link_to_port[(dpid,next_dpid)]
                match = dp.ofproto_parser.OFPMatch(in_port=in_port, eth_type=0x8847, mpls_label=mpls_label)
                actions = [dp.ofproto_parser.OFPActionOutput(dpid_out_port)] 
                sfc_app.add_flow(dp, priority, match, actions, table_id=0, inst_flag=ACTIONS)
            else:                   # find vnf in this datapath
                # update next_sf_ip
                next_sf_ip = sf_ip[sf_ip_index]
                sf_ip_index += 1
        #-----------------------sff for loop end-------------------------------
        # c2:pop mpls
        dpid = next_dpid
        dp = sfc_app.datapaths[dpid]
        priority = 10
        in_port = next_dpid_in_port
        for a, b in sfc_app.awareness.access_table_distinct.items():
            dpid_in_dict = a[0]
            port_in_dict = a[1]
            dst_ip  = b[0]
            dst_mac = b[1]           
#            print "dpid_in_dict:%r , port_in_dict:%r , dst_mac:%r , dst_ip:%r " % (dpid_in_dict, port_in_dict, dst_mac, dst_ip) #cx
            if dpid_in_dict == dpid and dst_ip == ipv4_dst:
                match = dp.ofproto_parser.OFPMatch(in_port=in_port, eth_type=0x8847, mpls_label=mpls_label)
                actions  = [dp.ofproto_parser.OFPActionPopMpls(0x0800)]
                actions += [dp.ofproto_parser.OFPActionSetField(eth_dst=dst_mac)]
                actions += [dp.ofproto_parser.OFPActionOutput(port_in_dict)]
                sfc_app.add_flow(dp, priority, match, actions, table_id=0, inst_flag=ACTIONS)
        
        return Response(status = 200)

    @route('delete-flow', '/delete_flow/{flow_id}', methods=['GET'])  
    def api_delete_flow(self,req, **kwargs):                             #暂时没用
        sfc_app = self.sfc_api_app

        cur.execute('''select * from flows where id = ?''',(kwargs['flow_id'],))
        flow_spec = cur.fetchone()
        if not flow_spec: return Response(status = 404)
        (flow_id,name,in_port,eth_dst,eth_src,eth_type,ip_proto,ipv4_src,ipv4_dst,tcp_src,tcp_dst,udp_src,udp_dst,ipv6_src,ipv6_dst,service_id)=flow_spec
        if not eth_type: eth_type = 0x0800  
        for dp in sfc_app.datapaths.values():
            match_del = sfc_app.create_match(dp.ofproto_parser, [
#                                               (dp.ofproto.OXM_OF_METADATA,int(kwargs['flow_id']))
                                               (dp.ofproto.OXM_OF_IN_PORT,in_port),
                                               (dp.ofproto.OXM_OF_ETH_SRC,eth_src),
                                               (dp.ofproto.OXM_OF_ETH_DST,eth_dst),
                                               (dp.ofproto.OXM_OF_ETH_TYPE,eth_type),
                                               (dp.ofproto.OXM_OF_IPV4_SRC,sfc_app.ipv4_to_int(ipv4_src)),
                                               (dp.ofproto.OXM_OF_IPV4_DST,sfc_app.ipv4_to_int(ipv4_dst)),
                                               (dp.ofproto.OXM_OF_IP_PROTO,ip_proto),
                                               (dp.ofproto.OXM_OF_TCP_SRC,tcp_src),
                                               (dp.ofproto.OXM_OF_TCP_DST,tcp_dst),
                                               (dp.ofproto.OXM_OF_UDP_SRC,udp_src),
                                               (dp.ofproto.OXM_OF_UDP_DST,udp_dst),
                                               (dp.ofproto.OXM_OF_IPV6_SRC,ipv6_src),
                                               (dp.ofproto.OXM_OF_IPV6_DST,ipv6_dst)
                                               ])

            match = copy.copy(match_del)
            sfc_app.del_flow(datapath=dp,match=match)
        return Response(status = 200)  

    @route('topology', '/{filename:[^/]*}')
    def static_handler(self, req, **kwargs):
        if kwargs['filename']:
            req.path_info = kwargs['filename']
        return self.static_app(req)

class sfc_app (app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    _CONTEXTS = { 'wsgi': WSGIApplication,
                  "network_awareness": network_awareness.NetworkAwareness }

    def __init__(self, *args, **kwargs):
        super(sfc_app, self).__init__(*args, **kwargs)
        wsgi = kwargs['wsgi']
        wsgi.register(SFCController, {sfc_instance_name: self})
        self.awareness = kwargs["network_awareness"]
        self.topology_api_app = self
        self.datapaths = {}        # {dpid:Datapath object}  # sfc use  # no database
        self.mac_to_port = {}      # {dpid:{mac:port}}   # packet_in_handler,sfc use #每一个dpid都有
                                   # 7: {'00:00:00:00:00:03': 3, '00:00:00:00:00:01': 1}
        self.link_to_port = {}     # {(src_dpid,dst_dpid):(src_port,dst_port)}    links 两个方向 
                                   # myapp and network_awareness self.link_to_port are same
        self.host_or_switch = {}   # {(dpid,port):SWITCH}   node type  #还没用，先不写数据库
        self.weight = 'weight'
        self.pre_path = []
        self.pre_ipv4_packet_identification = {}
        # arp_proxy ----------------------------------------------------------
        self.arp_table = {}        # arp_table: {'192.168.20.31': '00:00:00:00:00:03', '192.168.20.21': '00:00:00:00:00:01'}
        self.sw_dict = {}          # 记录某个arp包之前有没有见过，不要写入数据库，要定时清空，这样某个主机arp到期之后再次发arp广播也可以获得回复
        self.arp_clean_thread = hub.spawn(self._arp_clean)
        
        # read database-------------------------------------------------------
        self.mac_to_port = setting.read_from_database_mac_to_port()
        self.logger.debug('self.mac_to_port: %r', self.mac_to_port)
        self.link_to_port = setting.read_from_database_link_to_port()
        self.logger.debug('self.link_to_port: %r', self.link_to_port)
#        self.pre_path = setting.read_from_database_pre_path()   # 不要保存上次的pre_path，保证第一次最短路径流表一定可以下发
#        print 'myapp>>> self.pre_path:', self.pre_path
        self.arp_table = setting.read_from_database_arp_table()
        self.logger.debug('self.arp_table: %r', self.arp_table)

        # log configuration-----
        self.logger = logging.getLogger(self.__class__.__name__)
        self.logger.propagate = False   # 隔离父logger
        # filename:设置日志输出文件，以天为单位输出到不同的日志文件，以免单个日志文件日志信息过多，
        # 日志文件如果不存在则会自动创建，但前面的路径如log文件夹必须存在，否则会报错
        log_file = 'log/sys_%s.log' % datetime.datetime.strftime(datetime.datetime.now(), '%Y-%m-%d')
        handler1 = logging.StreamHandler()                  # console
        handler2 = logging.FileHandler(filename=log_file)   # log file
        
        self.logger.setLevel(logging.DEBUG)
        handler1.setLevel(logging.INFO)  # level 20
        handler2.setLevel(logging.DEBUG) # level 10
        
        formatter = logging.Formatter("%(asctime)s %(name)s[%(levelname)s] %(message)s")
        handler1.setFormatter(formatter)
        handler2.setFormatter(formatter)
        
        self.logger.addHandler(handler1)
        self.logger.addHandler(handler2)

        self.logger.debug('\n'*5)
        # start timer-----
        timer = threading.Timer(5, self.fun_timer)
        timer.start()
        
        
# 定时更新所有mac_to_port
    def fun_timer(self): 
        try:
            self.update_mac_to_port_all()
            self.logger.info('update all mac_to_port')
        except:
            self.logger.error('update_mac_to_port_all failed')
            pass
        global timer
        timer = threading.Timer(60, self.fun_timer)
        timer.start()
    
# 定时清空sw_dict的线程，以便arp缓存过期了也可以获得回复
# 连续ping 10s以上应该也没事，应该会有arp_proxy_reply
    def _arp_clean(self):
        while True:
            self.sw_dict.clear()
            hub.sleep(5)  # 10s


# Setting default rules upon DP is connected
#    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
#    def switch_features_handler(self, ev):
#        datapath = ev.msg.datapath
#        ofproto = datapath.ofproto
#        parser = datapath.ofproto_parser
#        #cx
##        print ev        #ryu.controller.ofp_event.EventOFPSwitchFeatures object
##        print ''
##        print ev.msg    #version=0x4,msg_type=0x6,msg_len=0x20,xid=0xc0656abd,OFPSwitchFeatures(auxiliary_id=0,capabilities=79,datapath_id=1,n_buffers=0,n_tables=254)
##        print ''
##        print datapath  #ryu.controller.controller.Datapath object
##        print ''
#
#        # install table-miss flow entry
#        #
#        # We specify NO BUFFER to max_len of the output action due to
#        # OVS bug. At this moment, if we specify a lesser number, e.g.,
#        # 128, OVS will send Packet-In with invalid buffer_id and
#        # truncated packet data. In that case, we cannot output packets
#        # correctly.  The bug has been fixed in OVS v2.1.0.
#        match = parser.OFPMatch()   # no match
#        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
#                                          ofproto.OFPCML_NO_BUFFER)]
#        self.del_flow(datapath, match)   #delete all flow entries
#        print ">>> add default flow"
#        self.add_flow(datapath, 0, match, actions, table_id=0, inst_flag=ACTIONS)    # add default flow entry

# Register/Unregister DataPathes in self.datapaths dictionary  
# learn self.datapaths dictionary  
    @set_ev_cls(ofp_event.EventOFPStateChange,
            [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def _state_change_handler(self, ev):
        datapath = ev.datapath
#        if isinstance(datapath.id,int):
#            datapath.id = hex(datapath.id)  # int -> hexadecimal string
        if ev.state == MAIN_DISPATCHER:
            if not datapath.id in self.datapaths:
                self.logger.debug("register datapath: %r", datapath.id)
                self.datapaths[datapath.id] = datapath
        elif ev.state == DEAD_DISPATCHER:
            if datapath.id in self.datapaths:
                self.logger.debug('unregister datapath: %r', datapath.id)
                del self.datapaths[datapath.id]
                self.logger.error("datapath %r left", datapath.id)
                
                
# Packet_IN handler
# learn self.mac_to_port dictionary
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        # If you hit this you might want to increase
        # the "miss_send_length" of your switch
        if ev.msg.msg_len < ev.msg.total_len:
            self.logger.debug("packet truncated: only %s of %s bytes",
                              ev.msg.msg_len, ev.msg.total_len)
#        print "myapp"
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']
        '''
            out_port初始值为OFPP_FLOOD，对于arp广播会做处理，对于DHCP广播会丢弃
            对于单播包泛洪可能会出现广播风暴，所以需要丢弃重复包
            对于其他的广播还是会出现广播风暴，到时需要增加针对性处理
        '''     
        out_port = ofproto.OFPP_FLOOD 
                         
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]  # pkt.get_protocols(ethernet.ethernet)是个列表，列表里只有一个元素，用[0]直接取出元素
                                                       # 所有的包都有以太网头部，所以能直接get，但是ip等协议需要判断是否存在
#        print "pkt.get_protocols:", pkt.get_protocols, '\n'
#        print "pkt.get_protocols(ethernet.ethernet)[0]:", pkt.get_protocols(ethernet.ethernet)[0], '\n'

        # 包过滤开始
        if eth.ethertype == ether_types.ETH_TYPE_LLDP or eth.ethertype == ether_types.ETH_TYPE_IPV6:
            # ignore lldp packet 
            return
            
        dst = eth.dst
        src = eth.src
        dpid = datapath.id
        
        if dst == ETHERNET_GROUP_MULTICAST:
            # ignore mDNS packet
#            print "Ignore eth_dst == 01:00:5e:00:00:fb"
            return
            
        if eth.ethertype == ether_types.ETH_TYPE_IP and dst == ETHERNET_MULTICAST:  # DHCP广播包, IP=0x0800
            # drop DHCP packet
            self.logger.debug("Drop ip_type and eth_dst == ff:ff:ff:ff:ff:ff")
            out = datapath.ofproto_parser.OFPPacketOut(            
                    datapath=datapath,                                 
                    buffer_id=datapath.ofproto.OFP_NO_BUFFER,           
                    in_port=in_port,
                    actions=[], data=None)
            datapath.send_msg(out)               
            return
            
#        self.logger.debug("\npkt.get_protocols: %s", pkt.get_protocols)
        
        header_list = dict( (p.protocol_name, p)for p in pkt.protocols if type(p) != str)
#        print "header_list:", header_list
        if IPv4 in header_list:
            ipv4_packet = pkt.get_protocols(ipv4.ipv4)[0]
#            print "pkt.get_protocols(ipv4.ipv4)[0]:", pkt.get_protocols(ipv4.ipv4)[0], '\n'
            if ipv4_packet.src == "0.0.0.0" or ipv4_packet.dst == "255.255.255.255":    # DHCP广播包
                self.logger.debug("Drop ip_src == 0.0.0.0 or ip_dst == 255.255.255.255")  
                out = datapath.ofproto_parser.OFPPacketOut(            
                    datapath=datapath,                                 
                    buffer_id=datapath.ofproto.OFP_NO_BUFFER,           
                    in_port=in_port,
                    actions=[], data=None)
                datapath.send_msg(out)  
                return
        # 包过滤结束
        
        print ''  # new line
        self.logger.info('New packet in...')
        self.logger.debug("pkt.get_protocols: %s", pkt.get_protocols)
        '''
            如果源主机已知目的主机的mac地址，而控制器不知道（比如人为清空数据库再重启控制器），
            那么这个ip包就计算不出最短路径，然后就会泛洪输出。
            所以要丢弃重复的ipv4包，防止其泛洪产生广播风暴。
            这里以ip头部的identification作为区分依据，记录每个dpid的identification，
            不同的ipv4包拥有相同的identification的概率应该非常小，再乘以同时进入同一个交换机的概率应该非常非常小。
        '''     
        if IPv4 in header_list:
            self.pre_ipv4_packet_identification.setdefault(dpid, None) 
            ipv4_packet = pkt.get_protocol(ipv4.ipv4)
#            print "ipv4_packet:", ipv4_packet
#            print 'identification:', ipv4_packet.identification
            if ipv4_packet.identification == self.pre_ipv4_packet_identification[dpid]:
                out = datapath.ofproto_parser.OFPPacketOut(            
                    datapath=datapath,                                 
                    buffer_id=datapath.ofproto.OFP_NO_BUFFER,           
                    in_port=in_port,
                    actions=[], data=None)
                datapath.send_msg(out)  
                self.logger.info('Dpid:%s Drop dup ipv4 packet', dpid)
                return
            else:
                self.pre_ipv4_packet_identification[dpid] = ipv4_packet.identification
                self.logger.debug('new self.pre_ipv4_packet_identification: %s', self.pre_ipv4_packet_identification)
        
        
        self.mac_to_port.setdefault(dpid, {})  #每一个dpid的值都是一个字典
        self.logger.info("packet in dpid:%s src:%s dst:%s in_port:%s" % (dpid, src, dst, in_port))
        # learn a mac address
        self.mac_to_port[dpid][src] = in_port
        setting.write_to_database_mac_to_port(self.mac_to_port)
        '''
            ipv4包：先判断源主机和目的主机是否在self.access_table_distinct里，
                   如果在就下发最短路径流表，然后按照最短路径更新mac_to_port,继续往下
                   否则就继续往下处理
        '''
        # shortest path
        if IPv4 in header_list:
            ip_pkt = pkt.get_protocol(ipv4.ipv4)
            result = self.shortest_forwarding(msg, eth.ethertype, ip_pkt.src, ip_pkt.dst)
            # update mac_to_port
            if result == True:  # shortest path is successful
                self.update_mac_to_port(src, dst, ip_pkt.src, ip_pkt.dst, self.pre_path)
                self.logger.info('ipv4: update_mac_to_port')
                
        '''
            arp包：先记录源ip和mac信息，然后交给arp_handler处理
        '''
        if ARP in header_list:  # arp packet
            self.arp_table[header_list[ARP].src_ip] = src  # ARP learning 
            setting.write_to_database_arp_table(self.arp_table)
#            print 'self.arp_table:', self.arp_table   
            
            arp_handler_return = self.arp_handler(header_list, datapath, in_port, msg.buffer_id)
            # 2: Normal arp reply or other arp packet    1: reply or drop   0: flood
            if arp_handler_return == 1:
                return None
            elif arp_handler_return == 2:
                # shortest path
                arp_pkt = pkt.get_protocol(arp.arp)
                # install ip flow entry, arp reply depends on mac_to_port 
                result = self.shortest_forwarding(msg, ether_types.ETH_TYPE_IP, arp_pkt.src_ip, arp_pkt.dst_ip)
                # update mac_to_port
                if result == True:  # shortest path is successful
                    self.update_mac_to_port(src, dst, arp_pkt.src_ip, arp_pkt.dst_ip, self.pre_path)
                    self.logger.info('arp: update_mac_to_port')
            else:
                out_port = ofproto.OFPP_FLOOD
        '''
            一般处理流程：先判断目的mac是否在mac_to_port里，
                         如果在就按对应端口输出，记录源mac和端口，并下发一条临时流表；
                         否则就应该是arp广播包，泛洪输出；
                         其他情况应该是异常
        '''

        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]     # self.mac_to_port[dpid][dst]->{'00:00:00:00:00:02':2}
        
        actions = [parser.OFPActionOutput(out_port)]
        
        # install a flow to avoid packet_in next time
        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(eth_dst=dst)  # 去掉eth_src,in_port
            self.add_flow(datapath, 1, match, actions, table_id=0, inst_flag=ACTIONS, idle_timeout=10, hard_timeout=15 )
            self.logger.info('Add temp flow')
            self.logger.debug("dpid:%r,src:%r,dst:%r,in_port:%r,out_port:%r", dpid, src, dst, in_port, out_port)
            
        #检查buffer_id，如果有dpid缓存就发空data，如果没有dpid缓存就发msg.data
        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data
        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)
        
#        # shortest path, only for ipv4 packet
#        if eth.ethertype == ether_types.ETH_TYPE_IP:
#            ip_pkt = pkt.get_protocol(ipv4.ipv4)
#            self.shortest_forwarding(msg, eth.ethertype, ip_pkt.src, ip_pkt.dst)
#        self.logger.info('The end of packet_in_handler\n')
                
# Function definitions 

    def add_flow(self, datapath, priority, match, actions, buffer_id=None, table_id=0, inst_flag=ACTIONS, idle_timeout=0, hard_timeout=0 ):  #add table_id inst_flag
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        # inst_flag=1->gototable    inst_flag=0->actions
        if inst_flag == GOTOTABLE:
            inst = [parser.OFPInstructionGotoTable(table_id)]
        else:
            inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        #OFPFlowMod默认是添加流表,也可以是修改或删除
        mod = parser.OFPFlowMod(datapath=datapath, table_id=table_id, priority=priority,    #add table_id
                                idle_timeout=idle_timeout, hard_timeout=hard_timeout, 
                                match=match, instructions=inst)
        datapath.send_msg(mod)
#        print "myapp>>> add flow ok"
    

    def del_flow(self, datapath, match):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        mod = parser.OFPFlowMod(datapath=datapath,
                    command=ofproto.OFPFC_DELETE,
                    out_port=ofproto.OFPP_ANY,
                    out_group=ofproto.OFPG_ANY,
                    match=match)
        datapath.send_msg(mod)

    #fill the link information
    def create_link_to_port(self, link_list, host_list):
        for link in link_list:   # link -> ryu.topology.switches.Link object
            src = link.src       # src  -> ryu.topology.switches.Port object
            dst = link.dst
            self.link_to_port[(src.dpid, dst.dpid)] = (src.port_no, dst.port_no)
            self.host_or_switch[(src.dpid, src.port_no)] = SWITCH
            self.host_or_switch[(dst.dpid, dst.port_no)] = SWITCH
#        print "myapp>>> self.link_to_port: %r\n" % self.link_to_port  #cx
#        setting.write_to_database_link_to_port(self.link_to_port)

        for host in host_list:   # host -> ryu.topology.switches.Host object
            port = host.port     # port -> ryu.topology.switches.Port object
            self.host_or_switch[(port.dpid, port.port_no)] = HOST
        
            
    # List the event list should be listened.
    events = [event.EventSwitchEnter, event.EventSwitchLeave, 
              event.EventPortAdd, event.EventPortDelete, event.EventPortModify,
              event.EventLinkAdd, event.EventLinkDelete,
              event.EventHostAdd, event.EventHostDelete]
    @set_ev_cls(events)
    def get_topology(self, ev):
        self.create_link_to_port(get_link(self.topology_api_app), get_host(self.topology_api_app))
        

    '''
       --------------------------shortest path-----------------------------------
    '''
    def get_path(self, src, dst, weight):
        """
            Get shortest path from network awareness module.
        """
        shortest_paths = self.awareness.shortest_paths
        return shortest_paths.get(src).get(dst)[0]

    def get_host_location(self, host_ip):
        """
            Get host location info:(datapath, port) according to host ip.
        """
#        print "awareness.access_table_distinct:", self.awareness.access_table_distinct #cx
        for key in self.awareness.access_table_distinct.keys():
            if self.awareness.access_table_distinct[key][0] == host_ip:
                return key  # (dpid, port, ip)
        self.logger.info("%s location is not found." % host_ip)
        return None
        
    def get_sw(self, src_ip, dst_ip):
        """
            Get pair of source and destination switches.
        """
        src_location = self.get_host_location(src_ip)
        if src_location != None:
            src_sw = src_location[0]
        else:
            src_sw = None
        dst_location = self.get_host_location(dst_ip)
        if dst_location != None:
            dst_sw = dst_location[0]
        else:
            dst_sw = None
        return src_sw, dst_sw
        
    def get_port(self, dst_ip, access_table_distinct):
        """
            Get access port if dst host.
            access_table_distinct: {(sw,port,ip) :(ip, mac)}
        """
        if access_table_distinct:
            if isinstance(access_table_distinct.values()[0], tuple):
                for key in access_table_distinct.keys():
                    if dst_ip == access_table_distinct[key][0]:
                        dst_port = key[1]
                        return dst_port
        return None
        
    def get_port_pair_from_link(self, link_to_port, src_dpid, dst_dpid):
        """
            Get port pair of link, so that controller can install flow entry.
        """
        if (src_dpid, dst_dpid) in link_to_port:
            return link_to_port[(src_dpid, dst_dpid)]
        else:
            self.logger.info("dpid:%s->dpid:%s is not in links" % (src_dpid, dst_dpid))
            return None
            
    def send_flow_mod(self, datapath, flow_info, src_port, dst_port):
        """
            Build flow entry, and send it to datapath.
        """
        parser = datapath.ofproto_parser
        actions = []
        actions.append(parser.OFPActionOutput(dst_port))

        match = parser.OFPMatch(
            in_port=src_port, eth_type=flow_info[0],
            ipv4_src=flow_info[1], ipv4_dst=flow_info[2])

        self.add_flow(datapath, 2, match, actions)
                      
    def _build_packet_out(self, datapath, buffer_id, src_port, dst_port, data):
        """
            Build packet out object.
        """
        actions = []
        if dst_port:
            actions.append(datapath.ofproto_parser.OFPActionOutput(dst_port))

        msg_data = None
        if buffer_id == datapath.ofproto.OFP_NO_BUFFER:
            if data is None:
                return None
            msg_data = data

        out = datapath.ofproto_parser.OFPPacketOut(
            datapath=datapath, buffer_id=buffer_id,
            data=msg_data, in_port=src_port, actions=actions)
        return out

    def send_packet_out(self, datapath, buffer_id, src_port, dst_port, data):
        """
            Send packet out packet to assigned datapath.
        """
        out = self._build_packet_out(datapath, buffer_id,
                                     src_port, dst_port, data)
        if out:
            datapath.send_msg(out)
            
    def install_flow(self, datapaths, link_to_port, access_table_distinct, path,
                     flow_info, buffer_id, data=None):
        ''' 
            Install flow entires for roundtrip: go and back.
            @parameter: path=[dpid1, dpid2...]
                        flow_info=(eth_type, src_ip, dst_ip)
        '''
        if path is None or len(path) == 0:
            self.logger.info("Path error!")
            return

        first_dp = datapaths[path[0]]
        out_port = first_dp.ofproto.OFPP_LOCAL
        back_info = (flow_info[0], flow_info[2], flow_info[1])

        # inter_link
        if len(path) > 2:
            port_pair = self.get_port_pair_from_link(link_to_port,
                                                     path[0], path[1])
#            print "path[0]:%r, path[1]:%r" % (path[0], path[1])    #cx                                  
            if port_pair is None:
                self.logger.info("Port is not found")
                return
            # the first switch flow entry
            dst_port = port_pair[0]  # src_sw -> out_port
            src_port = self.get_port(flow_info[1], access_table_distinct) 
            self.send_flow_mod(first_dp, flow_info, src_port, dst_port)
            self.send_flow_mod(first_dp, back_info, dst_port, src_port)
            self.send_packet_out(first_dp, buffer_id, src_port, dst_port, data)
#            print "src_port:%r, dst_port:%r" % (src_port, dst_port)  #cx           
            
            for i in xrange(1, len(path)-1):
                port = self.get_port_pair_from_link(link_to_port,
                                                    path[i-1], path[i])
                port_next = self.get_port_pair_from_link(link_to_port,
                                                         path[i], path[i+1])
                if port and port_next:
                    src_port, dst_port = port[1], port_next[0]   # src_port->in_port, dst_port->out_port
                    datapath = datapaths[path[i]]
                    self.send_flow_mod(datapath, flow_info, src_port, dst_port)
                    self.send_flow_mod(datapath, back_info, dst_port, src_port)
                    self.logger.debug("inter_link flow install")
                    
            port_pair = self.get_port_pair_from_link(link_to_port,
                                                     path[-2], path[-1])                                 
            if port_pair is None:
                self.logger.info("Port is not found")
                return                    
            # the last switch flow entry
            src_port = port_pair[1]  # dst_sw -> in_port
            dst_port = self.get_port(flow_info[2], access_table_distinct)  # dst_ip -> sw_port
            if dst_port is None:
                self.logger.info("Last port is not found.")
                return
#            print "src_port:%r, dst_port:%r" % (src_port, dst_port)  #cx   
            last_dp = datapaths[path[-1]]
            self.send_flow_mod(last_dp, flow_info, src_port, dst_port)
            self.send_flow_mod(last_dp, back_info, dst_port, src_port)
            
        elif len(path) > 1:
            port_pair = self.get_port_pair_from_link(link_to_port,
                                                     path[0], path[1])
#            print "path[0]:%r, path[1]:%r" % (path[0], path[1])    #cx                                  
            if port_pair is None:
                self.logger.info("Port is not found")
                return
            
            # the first switch flow entry
            dst_port = port_pair[0]  # src_sw -> out_port
            src_port = self.get_port(flow_info[1], access_table_distinct) 
            self.send_flow_mod(first_dp, flow_info, src_port, dst_port)
            self.send_flow_mod(first_dp, back_info, dst_port, src_port)
            self.send_packet_out(first_dp, buffer_id, src_port, dst_port, data)
#            print "src_port:%r, dst_port:%r" % (src_port, dst_port)  #cx
            
            # the last switch flow entry
            src_port = port_pair[1]  # dst_sw -> in_port
            dst_port = self.get_port(flow_info[2], access_table_distinct)  # dst_ip -> sw_port
            if dst_port is None:
                self.logger.info("Last port is not found.")
                return
#            print "src_port:%r, dst_port:%r" % (src_port, dst_port)  #cx   
            last_dp = datapaths[path[1]]
            self.send_flow_mod(last_dp, flow_info, src_port, dst_port)
            self.send_flow_mod(last_dp, back_info, dst_port, src_port)

        # src and dst on the same datapath
        else:
            in_port = self.get_port(flow_info[1], access_table_distinct) 
            if in_port is None:
                self.logger.info("In_port is None in same dp")
                return            
            out_port = self.get_port(flow_info[2], access_table_distinct)
            if out_port is None:
                self.logger.info("Out_port is None in same dp")
                return
            self.send_flow_mod(first_dp, flow_info, in_port, out_port)
            self.send_flow_mod(first_dp, back_info, out_port, in_port)
            self.send_packet_out(first_dp, buffer_id, in_port, out_port, data)

    def shortest_forwarding(self, msg, eth_type, ip_src, ip_dst):  # 前提是已经发现了这两台主机的位置和IP信息，才会下发流表
        """
            To calculate shortest forwarding path and install them into datapaths.
        """
        result = self.get_sw(ip_src, ip_dst)
        if result:  # get host information
            src_sw, dst_sw = result[0], result[1]
            if src_sw and dst_sw:
                # Path has already calculated, just get it.
                path = self.get_path(src_sw, dst_sw, weight=self.weight)
                self.logger.debug("src_sw:%r, dst_sw:%r" % (src_sw, dst_sw))
                self.logger.debug("pre_path: %r", self.pre_path)
                self.logger.debug("path: %r", path)
                if path != self.pre_path:
                    self.logger.info("dijkstra_path>>> PATH[%s --> %s]: %s" % (ip_src, ip_dst, path))
                    self.pre_path = path
                    setting.write_to_database_pre_path(self.pre_path)
                    
                    flow_info = (eth_type, ip_src, ip_dst)
                    # install flow entries to datapath along side the path.
                    # only execute on first datapath
                    self.install_flow(self.datapaths,
                                      self.awareness.link_to_port,
                                      self.awareness.access_table_distinct, path,
                                      flow_info, msg.buffer_id, msg.data)
            return True  # successful
        else:   # not found host information
            self.logger.info('Host information is not found')
            return False # failure
            
            
    def update_mac_to_port(self, src_mac, dst_mac, src_ip, dst_ip, path):
        '''
            update mac_to_port from self.pre_path, self.link_to_port, self.awareness.access_table_distinct
            src_port -> in_port, dst_port -> out_port
        '''
        if path is None or len(path) == 0:
            self.logger.info("Path error!")
            return
            
        link_to_port = self.link_to_port
        access_table_distinct = self.awareness.access_table_distinct
        # inter_link
        if len(path) > 2:
            port_pair = self.get_port_pair_from_link(link_to_port,
                                                     path[0], path[1])                                
            if port_pair is None:
                self.logger.info("Port is not found")
                return
            # the first switch
            dpid = path[0]
            src_port = self.get_port(src_ip, access_table_distinct) # in_port
            dst_port = port_pair[0]  # out_port
            self.mac_to_port[dpid][src_mac] = src_port
            self.mac_to_port[dpid][dst_mac] = dst_port
            
            for i in xrange(1, len(path)-1):
                port = self.get_port_pair_from_link(link_to_port,
                                                    path[i-1], path[i])
                port_next = self.get_port_pair_from_link(link_to_port,
                                                         path[i], path[i+1])
                if port and port_next:
                    src_port, dst_port = port[1], port_next[0]   # src_port->in_port, dst_port->out_port
                    dpid = path[i]
                    self.mac_to_port[dpid][src_mac] = src_port
                    self.mac_to_port[dpid][dst_mac] = dst_port
                    
            port_pair = self.get_port_pair_from_link(link_to_port,
                                                     path[-2], path[-1])                                 
            if port_pair is None:
                self.logger.info("Port is not found")
                return                    
            # the last switch
            src_port = port_pair[1]  # in_port
            dst_port = self.get_port(dst_ip, access_table_distinct)  # out_port
            if dst_port is None:
                self.logger.info("Last port is not found.")
                return
            dpid = path[-1]
            self.mac_to_port[dpid][src_mac] = src_port
            self.mac_to_port[dpid][dst_mac] = dst_port
            
        elif len(path) > 1:
            port_pair = self.get_port_pair_from_link(link_to_port,
                                                     path[0], path[1])                                 
            if port_pair is None:
                self.logger.info("Port is not found")
                return      
            # the first switch
            dst_port = port_pair[0]  # out_port
            src_port = self.get_port(src_ip, access_table_distinct) 
            dpid = path[0]
            self.mac_to_port[dpid][src_mac] = src_port
            self.mac_to_port[dpid][dst_mac] = dst_port            
            
            # the last switch
            src_port = port_pair[1]  # in_port
            dst_port = self.get_port(dst_ip, access_table_distinct) # out_port
            if dst_port is None:
                self.logger.info("Last port is not found.")
                return
            dpid = path[1]
            self.mac_to_port[dpid][src_mac] = src_port
            self.mac_to_port[dpid][dst_mac] = dst_port              

        # src and dst are on the same datapath
        else:
            in_port = self.get_port(src_ip, access_table_distinct) 
            if in_port is None:
                self.logger.info("In_port is None in same dp")
                return            
            out_port = self.get_port(dst_ip, access_table_distinct)
            if out_port is None:
                self.logger.info("Out_port is None in same dp")
                return
            dpid = path[0]
            self.mac_to_port[dpid][src_mac] = in_port
            self.mac_to_port[dpid][dst_mac] = out_port              
            
    def update_mac_to_port_all(self):
        '''
            update all mac_to_port from database <access_table_distinct> table
            traverse all hosts
        '''
        conn = sqlite3.connect('sfc_db.sqlite')   # open database
        cur = conn.cursor()
        cur.execute('SELECT ip_dup,mac from access_table_distinct')
        access_table_distinct_items = cur.fetchall()  # access_table_distinct_items:list
        conn.commit()    #提交，如果不提交，关闭连接后所有更改都会丢失
        conn.close() 
        
        access_table_distinct_items.sort()
#        print 'access_table_distinct_items:', access_table_distinct_items  # access_table_distinct_items: [(u'192.168.20.21', u'00:00:00:00:00:01'), (u'192.168.20.51', u'00:00:00:00:00:09'), (u'192.168.20.22', u'00:00:00:00:00:02'), (u'192.168.20.41', u'00:00:00:00:00:06'), (u'192.168.20.31', u'00:00:00:00:00:03'), (u'192.168.20.42', u'00:00:00:00:00:07'), (u'192.168.20.33', u'00:00:00:00:00:05'), (u'192.168.20.43', u'00:00:00:00:00:08'), (u'192.168.20.32', u'00:00:00:00:00:04')]        
        length = len(access_table_distinct_items)  
        self.logger.debug('access_table_distinct_items length: %s', length)
        
        count = 0
        if length > 1:
            for i in range(0, length-1):
                src_ip  = access_table_distinct_items[i][0]
                src_mac = access_table_distinct_items[i][1]
                for j in range(i+1, length):
                    dst_ip  = access_table_distinct_items[j][0]
                    dst_mac = access_table_distinct_items[j][1]
                    count = count + 1
                    
                    result = self.get_sw(src_ip, dst_ip)
                    if result:  # get host and switch information
                        src_sw, dst_sw = result[0], result[1]
                        if src_sw and dst_sw:
                            # Path has already calculated, just get it.
                            path = self.get_path(src_sw, dst_sw, weight=self.weight)
                            self.update_mac_to_port(src_mac, dst_mac, src_ip, dst_ip, path)
                    else:
                        self.logger.info('Not found switch')
            self.logger.debug('update_mac_to_port_all count: %s', count)
        else:
            self.logger.info("Don't need to update mac_to_port")
          
        
    # arp_proxy --------------------------------------------------------------
    def arp_handler(self, header_list, datapath, in_port, msg_buffer_id):
        header_list = header_list
        datapath = datapath
        in_port = in_port

        if ETHERNET in header_list:
            eth_dst = header_list[ETHERNET].dst
            eth_src = header_list[ETHERNET].src


        # drop arp request unicast------
        '''
        奇怪的现象：如果源主机已经有了目的主机的arp缓存，那么按理来说ping的时候不需要发送arp，
                   但在mininet上ping完之后等2秒左右就会发送一个arp请求单播，而且arp的目的mac是'00:00:00:00:00:00',
                   ethernet的目的mac是目的主机。
        在实际系统中还没测试过
        对于这样的包，直接丢弃，然后在packet_in中返回
        '''
        arp_eth_dst = header_list[ARP].dst_mac
        if arp_eth_dst == ETHERNET_ZERO and eth_dst != ETHERNET_MULTICAST:
            out = datapath.ofproto_parser.OFPPacketOut(             
                    datapath=datapath,
                    buffer_id=datapath.ofproto.OFP_NO_BUFFER,           
                    in_port=in_port,
                    actions=[], data=None)
            datapath.send_msg(out)
            self.logger.info('ARP_PROXY: Drop arp request unicast')
            return 1  # drop
        # drop arp request unicast------


        if eth_dst == ETHERNET_MULTICAST and ARP in header_list: # arp广播包
            arp_dst_ip = header_list[ARP].dst_ip
            if (datapath.id, eth_src, arp_dst_ip) in self.sw_dict:  # Break the loop  # 该交换机之前见过这个arp广播包，丢弃
#                if self.sw_dict[(datapath.id, eth_src, arp_dst_ip)] != in_port:  # 这一次的in_port跟第一次记录的in_port不一致
                out = datapath.ofproto_parser.OFPPacketOut(             # 说明是环路广播回来的，丢弃
                    datapath=datapath,                                  # 如果全是ovs的话没问题，但是如果有传统交换机的话，它会一直广播，广播包就可能从同一个入端口进来
                    buffer_id=datapath.ofproto.OFP_NO_BUFFER,           # 解决办法：sw_dict不要写入数据库，并且定时清空sw_dict
                    in_port=in_port,
                    actions=[], data=None)
                datapath.send_msg(out)
                self.logger.info("ARP_PROXY: Drop arp broadcast")
                return 1   # drop
            else:  # 该交换机第一次见这个广播包，记录in_port
                self.sw_dict[(datapath.id, eth_src, arp_dst_ip)] = in_port
                self.logger.info('First see the broadcast packet. self.sw_dict: %r', self.sw_dict)

        if ARP in header_list:  # arp
#            hwtype = header_list[ARP].hwtype
#            proto = header_list[ARP].proto
#            hlen = header_list[ARP].hlen
#            plen = header_list[ARP].plen
            opcode = header_list[ARP].opcode

            arp_src_ip = header_list[ARP].src_ip
            arp_dst_ip = header_list[ARP].dst_ip

            actions = []

            if opcode == arp.ARP_REQUEST:
                if arp_dst_ip in self.arp_table:  # arp reply  # 目的ip和mac已经有记录，则不必广播，直接构造arp_reply包
                    actions.append(datapath.ofproto_parser.OFPActionOutput(in_port))

                    ARP_Reply = packet.Packet()
                    ARP_Reply.add_protocol(ethernet.ethernet(
                        ethertype=header_list[ETHERNET].ethertype,
                        dst=eth_src,
                        src=self.arp_table[arp_dst_ip]))
                    ARP_Reply.add_protocol(arp.arp(
                        opcode=arp.ARP_REPLY,
                        src_mac=self.arp_table[arp_dst_ip],
                        src_ip=arp_dst_ip,
                        dst_mac=eth_src,
                        dst_ip=arp_src_ip))

                    ARP_Reply.serialize()

                    out = datapath.ofproto_parser.OFPPacketOut(
                        datapath=datapath,
                        buffer_id=datapath.ofproto.OFP_NO_BUFFER,
                        in_port=datapath.ofproto.OFPP_CONTROLLER,
                        actions=actions, data=ARP_Reply.data)
                    datapath.send_msg(out)
                    self.logger.info("ARP_PROXY: Arp reply")
                    return 1  # arp_reply
            else:
                self.logger.info("ARP_PROXY: Normal arp reply or other arp packet")
                return 2  # other arp packet
 
        self.logger.info('ARP_PROXY: Arp flood')
        return 0
    # arp_proxy --------------------------------------------------------------
                                  
app_manager.require_app('ryu.app.rest_topology')
app_manager.require_app('ryu.app.ws_topology')
app_manager.require_app('ryu.app.ofctl_rest')
        