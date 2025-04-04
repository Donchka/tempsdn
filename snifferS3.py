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
from ryu.lib.packet import ipv4
# import json
# import boto3
# from botocore.exceptions import NoCredentialsError

import mysql.connector

class SimpleSwitch13(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SimpleSwitch13, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        # self.s3 = boto3.client('s3')
        # self.bucket_name = "your-s3-bucket-name"  # Replace with your bucket name
        # self.object_name = "path/to/uploaded_file.json"  # The desired S3 key (path + filename)

        self.db_connection = mysql.connector.connect(
            host="sdn-db.ctmg0o4y2obu.us-east-2.rds.amazonaws.com",
            user="admin",
            password="Humbersdn1",
            database="sdn-db"
        )
        self.db_cursor = self.db_connection.cursor()

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
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

        # Extract Ethernet header
        eth = pkt.get_protocol(ethernet.ethernet)
        eth_src = eth.src if eth else None #source MAC
        eth_dst = eth.dst if eth else None #destination MAC
        eth_type = eth.ethertype if eth else None #types of protocol(IPv4,IPv6)

        # Extract IP header
        ip_pkt = pkt.get_protocol(ipv4.ipv4)
        ip_src = ip_pkt.src if ip_pkt else None #source IP
        ip_dst = ip_pkt.dst if ip_pkt else None #destination IP
        ip_protocol = ip_pkt.proto if ip_pkt else None #protocol for the IP packet (TCP,UDP,ICMP)

        # Extract TCP/UDP headers
        src_port = dst_port = None
        if ip_protocol == 6:  # TCP
            tcp_pkt = pkt.get_protocol(tcp.tcp)
            src_port = tcp_pkt.src_port if tcp_pkt else None #source port
            dst_port = tcp_pkt.dst_port if tcp_pkt else None #detination port
        elif ip_protocol == 17:  # UDP
            udp_pkt = pkt.get_protocol(udp.udp)
            src_port = udp_pkt.src_port if udp_pkt else None
            dst_port = udp_pkt.dst_port if udp_pkt else None

        # Get packet length
        packet_length = len(msg.data)

        packet_log = (eth_src, eth_dst, eth_type, ip_src, ip_dst, ip_protocol, src_port, dst_port, packet_length)
        self.send_log_2RDS(packet_log)

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            # ignore lldp packet
            return
        dst = eth.dst
        src = eth.src

        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})

        self.logger.info("packet in %s %s %s %s", dpid, src, dst, in_port)

        # log = {
        #     "dpid":dpid,
        #     "src":src,
        #     "dst":dst,
        #     "in_port":in_port,
        #     "EtherType":hex(eth.ethertype)
        #     }

        # self.send_log_2S3(log, self.bucket_name, self.object_name)

        # learn a mac address to avoid FLOOD next time.
        self.mac_to_port[dpid][src] = in_port

        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]

        ip_pkt = pkt.get_protocol(ipv4.ipv4)
        # if ip_pkt:
        #     log = {
        #         "Source IP":ip_pkt.src,
        #         "Destination IP":ip_pkt.dst,
        #         "Protocol":ip_pkt.proto,
        #         "TTL":ip_pkt.ttl
        #     }
        #     self.send_log_2S3(log, self.bucket_name, self.object_name)


        # install a flow to avoid packet_in next time
        if out_port != ofproto.OFPP_FLOOD:

            # check IP Protocol and create a match for IP
            if eth.ethertype == ether_types.ETH_TYPE_IP:
                ip = pkt.get_protocol(ipv4.ipv4)
                srcip = ip.src
                dstip = ip.dst
                match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP,
                                        ipv4_src=srcip,
                                        ipv4_dst=dstip
                                        )
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

    # def send_log_2S3(self, log, bucket_name, bucket_object):
    #     try:
    #         # Convert Python dictionary to JSON string
    #         json_log = json.dumps(log)
            
    #         # Upload the JSON string as an object to S3
    #         self.s3.put_object(Body=json_log, Bucket=bucket_name, Key=bucket_object)
    #         print(f"JSON data uploaded to {bucket_name}/{bucket_object}")
    #     except NoCredentialsError:
    #         print("Error: AWS credentials not found.")
    #     except Exception as e:
    #         print(f"Error: {e}")

    def send_log_2RDS(self, packet_log):
        insert_query = """
            INSERT INTO packet_info (eth_src, eth_dst, eth_type, ip_src, ip_dst, ip_protocol, src_port, dst_port, packet_length)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
        """
        self.db_cursor.execute(insert_query, packet_log)
        self.db_connection.commit()
