from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types,lldp
from ryu.topology import switches, event
from ryu.topology.api import get_switch, get_link, get_all_host
import time
from ryu.lib.packet import arp


class SimpleSwitch13(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SimpleSwitch13, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.topology = {}
        self.all_paths = []
        self.hosts = {}

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # install table-miss flow entry
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

        # 如果不是 ARP 数据包，直接忽略
        if eth.ethertype != ether_types.ETH_TYPE_ARP:
            self.logger.info("Non-ARP packet received, ethertype: %s", eth.ethertype)
            return

        # 处理 ARP 数据包
        arp_pkt = pkt.get_protocol(arp.arp)
        if arp_pkt:
            src_mac = arp_pkt.src_mac
            src_ip = arp_pkt.src_ip
            dst_ip = arp_pkt.dst_ip

            self.logger.info("ARP packet received: src_mac=%s, src_ip=%s, dst_ip=%s", src_mac, src_ip, dst_ip)

            # 更新 MAC 到端口的映射
            dpid = datapath.id
            self.mac_to_port.setdefault(dpid, {})
            self.mac_to_port[dpid][src_mac] = in_port

            # 查找目标 IP 对应的 MAC 地址，如果知道目的 MAC 地址，转发包
            if dst_ip in self.hosts:
                dst_mac = self.hosts[dst_ip]
                out_port = self.mac_to_port[dpid].get(dst_mac)

                if out_port:
                    actions = [parser.OFPActionOutput(out_port)]
                    data = msg.data if msg.buffer_id == ofproto.OFP_NO_BUFFER else None
                    out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                            in_port=in_port, actions=actions, data=data)
                    datapath.send_msg(out)
                    return

        # 如果目的 MAC 不在表中，使用 FLOOD 泛洪
            actions = [parser.OFPActionOutput(ofproto.OFPP_FLOOD)]
            data = msg.data if msg.buffer_id == ofproto.OFP_NO_BUFFER else None
            out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                    in_port=in_port, actions=actions, data=data)
            datapath.send_msg(out)


    def install_path(self, path, src_ip, dst_ip):
        for i in range(len(path) - 1):
            datapath = self.get_datapath(path[i])
            next_dpid = path[i + 1]
            out_port = self.get_port(path[i], next_dpid)
            parser = datapath.ofproto_parser

            match = parser.OFPMatch(eth_type=0x0800, ipv4_src=src_ip, ipv4_dst=dst_ip)
            actions = [parser.OFPActionOutput(out_port)]
            self.add_flow(datapath, 1, match, actions)

    @set_ev_cls(event.EventSwitchEnter)
    def get_topology(self, ev):
        time.sleep(3)  # 增加等待时间，确保链路信息已经准备好

        switches = get_switch(self, None)
        switch_list = [switch.dp.id for switch in switches]
        links = get_link(self, None)

        self.logger.info("Switches: %s", switch_list)
        self.logger.info("Links: %s", links)

        if not links:
            self.logger.warning("No links found. Is the topology setup correctly?")
        else:
            self.logger.info("Links successfully retrieved")

        for link in links:
            src = link.src.dpid
            dst = link.dst.dpid

            if dst not in self.topology.get(src, []):
                self.topology.setdefault(src, []).append(dst)
            if src not in self.topology.get(dst, []):
                self.topology.setdefault(dst, []).append(src)

        self.logger.info("Topology: %s", self.topology)

        hosts = get_all_host(self)
        if not hosts:
            self.logger.warning("No hosts found. Is host discovery enabled?")
        else:
            for host in hosts:
                if host.ipv4:
                    self.hosts[host.ipv4[0]] = host.port.dpid
                    self.logger.info("Host: %s, DPID: %s", host.ipv4[0], host.port.dpid)

    def DFS(self, graph, src, dst, path=None):
        if path is None:
            path = []

        if src not in graph or dst not in graph:
            return []

        path = path + [src]
        if src == dst:
            return [path]

        paths = []
        for node in graph.get(src, []):
            if node not in path:
                new_paths = self.DFS(graph, node, dst, path)
                for new_path in new_paths:
                    paths.append(new_path)

        return paths