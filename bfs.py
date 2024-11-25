from collections import defaultdict
import collections
from math import fabs
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.topology import event
from ryu.controller.handler import MAIN_DISPATCHER, CONFIG_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types
from ryu.topology.api import get_switch, get_all_link, get_link
import copy
from ryu.lib.packet import arp
import networkx as nx

import matplotlib.pyplot as plt
from ryu.lib import mac


class Topo(object):
    # 初始化Topo类
    def __init__(self, logger):
        # logger: 用于记录日志的对象
        self.adjacent = defaultdict(lambda s1s2: None)  # 用于存储交换机之间的相邻关系及端口信息的字典
        self.switches = None  # 存储交换机的信息
        self.logger = logger  # 记录日志的对象
        self.graph = {}  # 用于表示交换机之间连接关系的字典

        
    # 重置类的状态
    def reset(self):
        self.adjacent = defaultdict(lambda s1s2: None)
        self.switches = None
    # 获取两个交换机之间的相邻关系及端口信息
    def get_adjacent(self, s1, s2):
        return self.adjacent.get((s1, s2))
    # 设置两个交换机链接的端口
    def set_adjacent(self, s1, s2, port):
        self.adjacent[(s1, s2)] = port
    
    def shortest_path(self, src_sw, dst_sw, first_port, last_port):

        # self.logger.info("、、、、、、、、{}".format(self.graph[src_sw]))
        queue = []
        result = []
       
        result.append(dst_sw)
        queue.append(self.graph[src_sw])
        # queue.append(x)
        flag = [0] * 14
        flag[src_sw] = 1
        path = [0] * 14
        parent = []
        parent.append(src_sw)
        while len(queue):
            g = []
            g = queue.pop(0)
            for x in g:
                if x == dst_sw:
                    path[x] = parent[0]
                    queue.clear()
                    break
                if not flag[x]:
                    path[x] = parent[0]
                    flag[x] = 1
                    queue.append(self.graph[x])
                    parent.append(x)
            parent.pop(0)
            # self.logger.info("result000000")
        # self.logger.info("、、、、、、、、{}".format(result))
        # self.logger.info("、、、、、、、、{}".format(path))
       
        while result[-1] != src_sw:
            a = path[result[-1]]
            # self.logger.info("、、、、、、、、{}".format(path))
            result.append(a)
        result=list(reversed(result))
        self.logger.info("result{}".format(result))

        
        if src_sw == dst_sw:
            paths = [src_sw]
        else:
            paths = result
        record = []
        inport = first_port

        # s1 s2; s2:s3, sn-1  sn
        for s1, s2 in zip(paths[:-1], paths[1:]):
            # s1--outport-->s2
            outport = self.get_adjacent(s1, s2)
            record.append((s1, inport, outport))
            inport = self.get_adjacent(s2, s1)
        record.append((dst_sw, inport, last_port))
        return record, paths
    

# TODO Port status monitor


# 定义BFS类，继承父类 app_manager.RyuApp
class BFSController(app_manager.RyuApp):
    # 确定of的版本信息
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    # 初始化BFS类的构造函数
    def __init__(self, *args, **kwargs):
        # 调用父类的构造函数
        super(BFSController, self).__init__(*args, **kwargs)
        # 初始化MAC位址表
        self.mac_to_port = {}
        # logical switches
        self.datapaths = []

        self.arp_table = {} #知道目标设备的IP地址，查询目标设备的MAC地址
        self.arp_history = {}
        self.rarp_table = {}#Reverse Address Resolution Protocol
        # 创建对象topo
        self.topo = Topo(self.logger)
        self.flood_history = {}
        self.switch_num = 0
        # self.is_learning={}
        self.graph = collections.defaultdict(set)
        self.initshow = 0
        self.index = 1
        self.lp_path = []
        self.falg = False

        self.shortest_history = {}  # 用于记录寻找过的最短路(src_mac,dst_mac)

    # 设置s1 和 s2 的连接关系
    def set_adj(self,s1,s2):
        self.graph[s1].add(s2)
        self.graph[s2].add(s1)
    # 在 datapaths 中查找与给定 dpid 匹配的数据路径
    def _find_dp(self, dpid):
        for dp in self.datapaths:
            if dp.id == dpid:
                return dp
        return None
    #OpenFlow交换机上线并向控制器发送其特征信息的事件，事件处理程序会在配置阶段执行
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    # 处理交换机特征事件
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.logger.info("add_flow--dpid:{}".format(datapath.id) )
        self.add_flow(datapath, 0, match, actions)
    # 为交换机添加流表
    def add_flow(self, datapath, priority, match, actions, buffer_id=None): 
        # 传递OpenFlow协议版本
        ofproto = datapath.ofproto
        # 传递OpenFlow消息解析器
        parser = datapath.ofproto_parser
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        # 数据包已经缓存在交换机中
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match,
                                    instructions=inst)
        # 假定数据包是通过控制器直接发送的
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst)
        # 使用datapath.send_msg方法将构建的OFPFlowMod消息对象发送到交换机
        datapath.send_msg(mod)
    def configure_path(self, longest_path, event, src_mac, dst_mac):
        # 配置最短路径到交换机
        # 获取事件中的消息对象和数据路径对象
        msg = event.msg
        datapath = msg.datapath
        # 获取数据路径的OpenFlow协议和解析器
        ofproto = datapath.ofproto

        parser = datapath.ofproto_parser

        # 枚举计算出的路径
        # (s1, inport, outport) -> (s2, inport, outport) -> ... -> (dest_switch, inport, outport)
        for switch, inport, outport in longest_path:
            # 创建匹配条件，用于匹配流量
            match = parser.OFPMatch(in_port=inport, eth_src=src_mac, eth_dst=dst_mac)
            # 定义动作，将匹配的流量从一个端口输出到另一个端口
            actions = [parser.OFPActionOutput(outport)]
            # 查找特定数据路径ID（switch对应的交换机）的数据路径对象
            datapath = self._find_dp(int(switch))
            # 打印数据路径ID与数据路径对象的映射关系
            #self.logger.info("dpid:{} is:{}".format(datapath, int(switch)))
            # 确保找到了数据路径对象
            assert datapath is not None

            inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
            # 创建流表规则（OFPFlowMod），将其发送到交换机
            mod = datapath.ofproto_parser.OFPFlowMod(
                datapath=datapath,
                match=match,
                idle_timeout=0,
                hard_timeout=0,
                priority=1,
                instructions=inst
            )
            datapath.send_msg(mod)
    
    #OpenFlow交换机接收到数据包并不知道如何处理它，事件处理程序会在主事件循环中执行
    # msg 是一个对象，用来描述对应的OpenFlow消息。
    # 在Ryu控制器中，当控制器接收到来自OpenFlow交换机的消息时，
    # 这些消息通常是以 msg 的形式表示的。msg 对象包含了与该消息相关的信息
    # 例如消息的数据、数据路径（datapath）、协议版本、消息类型、消息头等。
    # 通过访问 msg 对象的不同属性和方法，控制器可以获取有关接收到的OpenFlow消息的各种信息，
    # 从而根据消息内容采取适当的操作。
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, event):
        # 获取事件中的消息对象
        msg = event.msg
        # 获取消息所属的数据路径（交换机）
        datapath = msg.datapath
        # Openflow 版本
        ofproto = datapath.ofproto
        # 获取OpenFlow协议解析器
        parser = datapath.ofproto_parser
        # 获取数据包进入交换机的端口
        in_port = msg.match['in_port']
      
        # 解析数据包
        # get src_mac and dest mac
        pkt = packet.Packet(msg.data)
        # 获取以太网帧协议头
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        
        # drop lldpobserve-links命令会导致控制器在运行期间 会不间断地发送LLDP数据包进行链路探测
        #而simple_switch_stp_13中对于lldp包，依然会当做packetin信息处理  ，因此只需要添加以下代码去忽略lldp包就可以了
        # 检查是否为LLDP数据包（链路层发现协议），如果是则忽略
        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            # self.logger.info("LLDP")
            return

        # 获取源MAC地址和目标MAC地址
        dst_mac = eth.dst
        src_mac = eth.src
        # 获取ARP协议包（如果存在）
        arp_pkt = pkt.get_protocol(arp.arp)

        # if this is an arp packet,we remember "ip---mac"
        # we learn ip---mac mapping from arp reply and request
        if arp_pkt:
            self.arp_table[arp_pkt.src_ip] = src_mac


        # 获取数据路径的ID（dpid）
        dpid = datapath.id

 

        # 洪泛
        # 洪泛（Flood）是一种网络通信方式，它是一种广播数据包的方法，通过向网络中的所有接口发送数据包来实现。
        # 洪泛用于在网络中找到目标设备的位置，因为它确保了数据包会传递到网络中的每个节点，直到达到目标设备为止。
        # 在上下文中，代码中的洪泛是指当控制器收到一个数据包并且不知道如何将其传送到目标设备时，
        # 它将数据包发送到所有的端口，以确保数据包最终到达目标设备。
        # 这是一种通常用于处理未知目标的数据包的策略，但它可能会导致网络中的大量冗余数据传输。
        # 初始化防洪（flood）历史记录
        self.flood_history.setdefault(dpid, [])
        #self.shortest_history.setdefault(dpid, [])

        # 如果目标MAC地址前5个字节为'33:33'，说明这是一个组播（multicast）包
        if '33:33' in dst_mac[:5]:
            # the controller has not flooded this packet before
            if (src_mac, dst_mac) not in self.flood_history[dpid]:
                # we remember this packet
                self.flood_history[dpid].append((src_mac, dst_mac))
            else:
                # the controller have flooded this packet before,we do nothing and return
                return
        
        # 记录源MAC地址和其对应的交换机和端口
        if src_mac not in self.mac_to_port.keys():
            self.mac_to_port[src_mac] = (dpid, in_port)
        # self.logger.info("src_mac{}".format(src_mac))
        # self.logger.info("dst_mac{}".format(dst_mac))

        # 如果目标MAC地址在mac_to_port字典中
        if dst_mac in self.mac_to_port.keys():
            all_links = copy.copy(get_all_link(self))

            all_link_stats = [(l.src.dpid, l.dst.dpid, l.src.port_no, l.dst.port_no) for l in all_links]

            self.logger.info("all_link_stats:{}".format(all_link_stats))

            for s1, s2, p1, p2 in all_link_stats:
                # weight = random.randint(1, 10)
                # 更新拓扑结构中的邻接信息
                self.topo.set_adjacent(s1, s2, p1)
                self.topo.set_adjacent(s2, s1, p2)
                self.set_adj(s1, s2)
                # 更新拓扑结构中的图信息

            self.topo.graph = self.graph
            self.logger.info("graph:   {}".format(self.graph))
            # if (src_mac, dst_mac) not in self.shortest_history[1]:
            #     self.shortest_history[1].append((src_mac, dst_mac))
            #     self.logger.info("shortest_history{}".format(self.shortest_history))
            
            final_port = self.mac_to_port[dst_mac][1]

            # the first switc
            src_switch = self.mac_to_port[src_mac][0]

            # the final switch
            dst_switch = self.mac_to_port[dst_mac][0]


            # 打印日志，显示数据包的流向

            self.logger.info("src{},,mac{}in第一{} out{}".format(src_switch,dst_switch,in_port,final_port))
            
            # 计算最短路径

            result,a= self.topo.shortest_path(src_switch,dst_switch,in_port,final_port)
            self.falg = True
            #self.logger.info("最短路:{}".format(a))
            self.logger.info("从{}到{}最短路{}".format(src_switch,dst_switch,result))
            # calculate the longest path
            #self.logger.info("src{},,mac{}in第二{} out{}".format(src_switch,dst_switch,in_port,final_port))
            
            # 配置最短路径规则
            self.configure_path(result, event, src_mac, dst_mac)

            self.logger.info("Configure done\n")

            # current_switch=None
            out_port = None
            for s, _, op in result:
                # print(s,dpid)
                if s == dpid:
                    out_port = op
            # assert out_port is not None
        # 如果目标MAC地址不在mac_to_port字典中，执行ARP处理
        else:
            if self.arp_handler(msg):
                return
            # 如果目标MAC地址未知，将数据包洪泛
            out_port = ofproto.OFPP_FLOOD

        # actions= flood or some port
        # 设置输出动作
        actions = [parser.OFPActionOutput(out_port)]

        data = None
        # 如果消息中有数据缓冲区，使用数据缓冲区
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data
        # 发送数据包到交换机，避免数据包丢失
        out = parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=msg.buffer_id,
            in_port=in_port,
            actions=actions,
            data=data
        )
        datapath.send_msg(out)
    # 新的交换机进入网络
    @set_ev_cls(event.EventSwitchEnter)
    def switch_enter_handler(self, event):
        self.logger.info("A switch entered.Topology rediscovery...")
        # 调用的另一个函数，处理交换机的状态
        self.switch_status_handler(event)
        self.logger.info('Topology rediscovery done')

    #交换机离开网络
    @set_ev_cls(event.EventSwitchLeave)
    def switch_leave_handler(self,event):
        self.logger.info("A switch leaved.Topology rediscovery...")
        self.switch_status_handler(event)
        self.logger.info('Topology rediscovery done')

    def switch_status_handler(self, event):
        # 跟踪已连接到网络的交换机数量
        self.switch_num += 1
        # 打印了一个日志消息
        self.logger.info("SwNum:{} /4".format(self.switch_num))
        if(4 == self.switch_num):
            # 获取所有已连接的交换机的信息并保存到all_switches
            all_switches = copy.copy(get_switch(self, None))
            # 获取交换机的ID值
            # 提取所有已连接交换机的数据通路 ID（dpid）并存储在拓扑结构中
            self.topo.switches = [s.dp.id for s in all_switches]
            self.logger.info("switches {}".format(self.topo.switches))
            self.datapaths = [s.dp for s in all_switches]
            # get link and get port
            #all_links = copy.copy(get_link(self, None))
            all_links = copy.copy(get_all_link(self))
            all_link_stats = [(l.src.dpid, l.dst.dpid, l.src.port_no, l.dst.port_no) for l in all_links]
            # self.logger.info("all_link_stats:{}".format(all_link_stats))
            for s1, s2, p1, p2 in all_link_stats:
                # weight = random.randint(1, 10)
                # 更新拓扑结构中的邻接信息
                self.topo.set_adjacent(s1, s2, p1)
                self.topo.set_adjacent(s2, s1, p2)
                self.set_adj(s1, s2)
            # 更新拓扑结构中的图信息

            self.topo.graph = self.graph
            # self.logger.info("graph:   {}".format(self.graph))
            #-------------------


    def arp_handler(self, msg): #ip->mac
        # 处理 ARP 请求和回复的函数
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        # 解析数据包
        pkt = packet.Packet(msg.data)
        # 从数据包中提取以太网协议头
        eth = pkt.get_protocols(ethernet.ethernet)[0]
        # 从数据包中提取 ARP 协议头
        arp_pkt = pkt.get_protocol(arp.arp)

        if eth:
            # 获取数据包中的MAC地址
            eth_dst = eth.dst
            eth_src = eth.src

        if eth_dst == mac.BROADCAST_STR and arp_pkt:
            # 如果目标 MAC 地址是广播地址，并且数据包包含 ARP 协议头
            # 获取 ARP 请求的目标 IP 地址
            arp_dst_ip = arp_pkt.dst_ip

            # 如果之前已经处理过这个 ARP 请求
            if (datapath.id, eth_src, arp_dst_ip) in self.arp_history:
                if self.arp_history[(datapath.id, eth_src, arp_dst_ip)] != in_port:
                    return True
            # 第一次遇到这个 ARP 请求，记录下来
            else:
                self.arp_history[(datapath.id, eth_src, arp_dst_ip)] = in_port
        # 如果数据包包含 ARP 协议头
        if arp_pkt:
            
            hwtype = arp_pkt.hwtype
            # protocol type
            proto = arp_pkt.proto
            # hardware address length
            hlen = arp_pkt.hlen
            # protocol address length
            plen = arp_pkt.plen

            # specify the operation that the sender is performing:1 for request,2 for reply
            opcode = arp_pkt.opcode

            # src ip
            arp_src_ip = arp_pkt.src_ip
            # dst ip
            arp_dst_ip = arp_pkt.dst_ip

            # 如果 ARP 类型是请求
            if opcode == arp.ARP_REQUEST:

                # 检查目标 IP 地址是否在 ARP 表中（是否已知）
                if arp_dst_ip in self.arp_table:
                    # 构建 ARP 回复
                    actions = [parser.OFPActionOutput(in_port)]
                    arp_reply = packet.Packet()
                    # 添加以太网头部
                    arp_reply.add_protocol(ethernet.ethernet(
                        ethertype=eth.ethertype,
                        dst=eth_src,
                        src=self.arp_table[arp_dst_ip]))

                    # 添加 ARP 协议头部，将操作码设置为 ARP 回复
                    arp_reply.add_protocol(arp.arp(
                        opcode=arp.ARP_REPLY,
                        src_mac=self.arp_table[arp_dst_ip],
                        src_ip=arp_dst_ip,
                        dst_mac=eth_src,
                        dst_ip=arp_src_ip))

                    # serialize the packet to binary format 0101010101
                    # 序列化数据包为二进制格式
                    arp_reply.serialize()
                    # 发送 ARP 回复消息到交换机
                    out = parser.OFPPacketOut(
                        datapath=datapath,
                        buffer_id=ofproto.OFP_NO_BUFFER,
                        in_port=ofproto.OFPP_CONTROLLER,
                        actions=actions, data=arp_reply.data)
                    datapath.send_msg(out)

                    return True
        return False        

