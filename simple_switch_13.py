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
        # If you hit this you might want to increase
        # the "miss_send_length" of your switch
        if ev.msg.msg_len < ev.msg.total_len:
            self.logger.debug("packet truncated: only %s of %s bytes",
                              ev.msg.msg_len, ev.msg.total_len)
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            # ignore lldp packet
            return
        dst = eth.dst
        src = eth.src

        dpid = format(datapath.id, "d").zfill(16)
        self.mac_to_port.setdefault(dpid, {})

        self.logger.info("packet in %s %s %s %s", dpid, src, dst, in_port)

        # learn a mac address to avoid FLOOD next time.
        self.mac_to_port[dpid][src] = in_port

        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]

        # install a flow to avoid packet_in next time
        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src)
            # verify if we have a valid buffer_id, if yes avoid to send both
            # flow_mod & packet_out
            if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                self.add_flow(datapath, 1, match, actions, msg.buffer_id)
                return
            else:
                self.add_flow(datapath, 1, match, actions)
        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)


    '''def install_path(self, path, src_ip, dst_ip):
        for i in range(len(path) - 1):
            datapath = self.get_datapath(path[i])
            next_dpid = path[i + 1]
            out_port = self.get_port(path[i], next_dpid)
            parser = datapath.ofproto_parser

            match = parser.OFPMatch(eth_type=0x0800, ipv4_src=src_ip, ipv4_dst=dst_ip)
            actions = [parser.OFPActionOutput(out_port)]
            self.add_flow(datapath, 1, match, actions)'''

    @set_ev_cls(event.EventSwitchEnter)
    def get_topology(self, ev):
        time.sleep(1)  # 增加等待时间，确保链路信息已经准备好

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