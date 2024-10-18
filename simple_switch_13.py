# Copyright (C) 2011 Nippon Telegraph and Telephone Corporation.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types
from ryu.topology import switches,event
from ryu.topology.api import get_switch, get_link,get_all_host
import time


class SimpleSwitch13(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SimpleSwitch13, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.topology={}
        self.all_paths=[]
        self.hosts={}
        
    
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        """
        Handles the switch features event.

        This function is triggered when a switch connects to the controller. It installs a table-miss flow entry on the switch.

        Parameters:
            ev: The event object, containing information such as the switch's features.

        Returns:
            None
        """
        # Get the datapath object, which represents the connection to the switch.
        datapath = ev.msg.datapath
        # Get the OpenFlow protocol object, used to access protocol-specific constants and methods.
        ofproto = datapath.ofproto
        # Get the OpenFlow parser object, used to construct flow rules and other messages.
        parser = datapath.ofproto_parser

        # install table-miss flow entry
        #
        # We specify NO BUFFER to max_len of the output action due to
        # OVS bug. At this moment, if we specify a lesser number, e.g.,
        # 128, OVS will send Packet-In with invalid buffer_id and
        # truncated packet data. In that case, we cannot output packets
        # correctly.  The bug has been fixed in OVS v2.1.0.
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match,
                                    instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst)
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]
        
        # 忽略 LLDP 包
        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return
        
        src = eth.src
        dst = eth.dst
        dpid = datapath.id
        
        # 获取源IP和目的IP
        ipv4_pkt = pkt.get_protocol(ipv4.ipv4)
        if ipv4_pkt:
            src_ip = ipv4_pkt.src
            dst_ip = ipv4_pkt.dst
            
            # 查找源主机和目标主机对应的DPID
            src_dpid = self.hosts.get(src_ip)
            dst_dpid = self.hosts.get(dst_ip)
            
            if src_dpid and dst_dpid:
                # 使用DFS查找路径
                paths = self.DFS(self.topology, src_dpid, dst_dpid)
                if paths:
                    # 找到最短路径和最长路径
                    shortest_path = min(paths, key=len)
                    longest_path = max(paths, key=len)
                    self.logger.info("Shortest Path: %s", shortest_path)
                    self.logger.info("Longest Path: %s", longest_path)
                    
                    # 使用最长路径下发流表规则
                    self.install_path(longest_path, src_ip, dst_ip, datapath)
                    return  # 下发后可以直接返回，避免重复处理

        # 如果没有找到路径或者没有IP地址关联时，使用默认的FLOOD处理
        self.mac_to_port.setdefault(dpid, {})
        self.mac_to_port[dpid][src] = in_port
        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD
        actions = [parser.OFPActionOutput(out_port)]
        data = msg.data if msg.buffer_id == ofproto.OFP_NO_BUFFER else None
        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)


    def install_path(self, path, src_ip, dst_ip, datapath):
        parser = datapath.ofproto_parser
        for i in range(len(path) - 1):
            dpid = path[i]
            next_dpid = path[i + 1]
            out_port = self.get_port(dpid, next_dpid)  # 获取端口信息
            match = parser.OFPMatch(eth_type=0x0800, ipv4_src=src_ip, ipv4_dst=dst_ip)
            actions = [parser.OFPActionOutput(out_port)]
            self.add_flow(datapath, 1, match, actions)


    @set_ev_cls(event.EventSwitchEnter)
    def get_topology(self, ev):
        time.sleep(1)
        
        # 获取交换机和链路信息
        switches = get_switch(self, None)
        switch_list = [switch.dp.id for switch in switches]
        links = get_link(self, None)
        
        # 打印交换机和链路信息
        self.logger.info("Switches: %s", switch_list)
        self.logger.info("Links: %s", links)
        
        # 遍历链路并建立拓扑
        for link in links:
            src = link.src.dpid
            dst = link.dst.dpid
            
            if dst not in self.topology.get(src, []):
                self.topology.setdefault(src, []).append(dst)
            if src not in self.topology.get(dst, []):
                self.topology.setdefault(dst, []).append(src)
        
        self.logger.info("Topology: %s", self.topology)
        
        # 获取主机信息并建立 IP 与 DPID 的关联
        hosts = get_all_host(self, None)
        for host in hosts:
            if host.ipv4:  # 检查主机是否有 IPv4 地址
                self.hosts[host.ipv4[0]] = host.port.dpid  # 关联主机的IP与其连接的交换机DPID
                self.logger.info("Host: %s, DPID: %s", host.ipv4[0], host.port.dpid)



    
    def DFS(self,graph, src, dst, path=None):
        if path is None:
            path = []
        
        # 检查图中是否存在 src 和 dst 节点
        if src not in graph or dst not in graph:
            return []
        
        path = path + [src]
        if src == dst:
            return [path]  # 返回包含路径的列表
        
        paths = []
        for node in graph.get(src, []):
            if node not in path:
                new_paths = self.DFS(graph, node, dst, path)
                for new_path in new_paths:
                    paths.append(new_path)  # 将整个路径作为一个整体添加
        
        return paths