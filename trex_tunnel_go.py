from trex_stl_lib.api import *
from prettytable import PrettyTable
import sys
import time
import json
sys.path.append("../../../external_libs/scapy-2.4.3")
from scapy.contrib.geneve import GENEVE


TUNNEL_MAC_OFFSET = {
    "vxlan": 58,
    "gre": 50,
    "geneve": 58

}

TUNNEL_HEADER_LENGTH = {
    "vxlan": 92,
    "gre": 84,
    "geneve": 84
}

# RFC 7348 - Virtual eXtensible Local Area Network (VXLAN):
# A Framework for Overlaying Virtualized Layer 2 Networks over Layer 3 Networks
# http://tools.ietf.org/html/rfc7348
# https://www.sdnlab.com/16914.html
_VXLAN_FLAGS = ['R' for i in range(0, 24)] + ['R', 'R', 'R', 'I', 'R', 'R', 'R', 'R', 'R']
class VXLAN(Packet):
    name = "VXLAN"
    fields_desc = [FlagsField("flags", 0x08000000, 32, _VXLAN_FLAGS),
                   ThreeBytesField("vni", 0x00),
                   XByteField("reserved", 0x00)]
    def mysummary(self):
        return self.sprintf("VXLAN (vni=%VXLAN.vni%)")

class Address():

    def __init__(self):
        self._src = ""
        self._dst = ""

    @property
    def src(self):
        return self._src
    @src.setter
    def src(self, value):
        self._src = value
    
    @property
    def dst(self):
        return self._dst
    @dst.setter
    def dst(self, value):
        self._dst = value
    

class Streamer(STLClient):
    def __init__(self):
        super().__init__()
        # -----------------------
        # :: stream properties ::
        # -----------------------
        # default tunnel type is Vxlan
        self.tunnel_type = ""
        # default port usage percentage is 100%
        self.port_usage_percent = "100%"
        # default flow amount is 1k
        self.flow_amount = 1024
        self.frame_size = 128

        # ------------------------
        # :: packets properties ::
        # ------------------------
        # default vni is 100
        self.vni = 100
        # no default address for address
        self.outer_Ether = Address()
        self.outer_IP = Address()
        self.inner_Ether = Address() # this will be incremented by trex to create different flow
        self.inner_IP = Address()

        self.results = None
    
    def _get_padding_size(self):
        header_length = TUNNEL_HEADER_LENGTH[self.tunnel_type]
        return self.frame_size - header_length

    def _build_pkt(self):
        pkt = None
        if self.tunnel_type == "vxlan":
            bind_layers(UDP, VXLAN, dport=4789)
            bind_layers(VXLAN, Ether)
            pkt = (Ether(src=self.outer_Ether.src, dst=self.outer_Ether.dst)/
                    IP(src=self.outer_IP.src, dst=self.outer_IP.dst)/
                    UDP(sport=57025, dport=4789)/
                    VXLAN(vni=self.vni)/
                    Ether(src=self.inner_Ether.src, dst=self.inner_Ether.dst)/
                    IP(src=self.inner_IP.src, dst=self.inner_IP.dst)/
                    UDP(sport=100, dport=44)/
                    ('x'*self._get_padding_size())
                )
        elif self.tunnel_type == "gre":
            # for forwarding reason, we actually use ethernet pkt inside gre tunnel, also called gretap
            pkt = (Ether(src=self.outer_Ether.src, dst=self.outer_Ether.dst)/
                    IP(src=self.outer_IP.src, dst=self.outer_IP.dst, proto=47)/
                    GRE(flags=0x2000, proto=0x6558, key=100, key_present=1)/
                    Ether(src=self.inner_Ether.src, dst=self.inner_Ether.dst)/
                    IP(src=self.inner_IP.src, dst=self.inner_IP.dst)/
                    UDP(sport=100, dport=44)/
                    ('x'*self._get_padding_size()) 
                )
        elif self.tunnel_type == "geneve":
            bind_layers(UDP, GENEVE, dport=6081)
            bind_layers(GENEVE, Ether, proto=0x6558)
            bind_layers(GENEVE, IP, proto=0x0800)
            pkt = (Ether(src=self.outer_Ether.src, dst=self.outer_Ether.dst)/
                    IP(src=self.outer_IP.src, dst=self.outer_IP.dst, proto=17)/
                    UDP(sport=57025, dport=6081)/
                    GENEVE(proto=0x6558, vni=100)/
                    Ether(src=self.inner_Ether.src, dst=self.inner_Ether.dst)/
                    IP(src=self.inner_IP.src, dst=self.inner_IP.dst)/
                    UDP(sport=100, dport=44)/
                    ('x'*self._get_padding_size()) 
                )
        else:
            print("ERROR: The {} type of tunnel has not been supported!".format(self.tunnel_type))
            sys.exit(1)
        return pkt

    def _build_stream(self):
        flow_var_and_wr_list = []
        flow_var_and_wr_list.append(
            STLVmFlowVar(name="mac_src", min_value=1, max_value=int(self.flow_amount/2), size=4, op="inc", step=1),
        )
        flow_var_and_wr_list.append(
            STLVmWrFlowVar(fv_name="mac_src", pkt_offset=TUNNEL_MAC_OFFSET[self.tunnel_type]),
        )
        if self.tunnel_type == 'vxlan' or self.tunnel_type == 'geneve':
            flow_var_and_wr_list.append(
                STLVmFixChecksumHw(l3_offset="IP", l4_offset="UDP", l4_type=CTRexVmInsFixHwCs.L4_TYPE_UDP)
            )
        return STLScVmRaw(flow_var_and_wr_list)

    def run(self, traffic_time=60):
        client = STLClient(server = '127.0.0.1')
        try:
            client.connect()
            stream = STLStream(packet = STLPktBuilder(pkt = self._build_pkt(), vm = self._build_stream()))
            client.reset(ports=0)
            client.add_streams(ports=0, streams = [stream])
            client.start(ports=0, mult=self.port_usage_percent)
            time.sleep(traffic_time)
            client.stop()
            client.wait_on_traffic(ports=0)
            self.results = client.get_stats()
            client.reset(ports=0)
        except Exception as E:
            print(E)
            print("ERROR")
        finally:
            client.disconnect()


    def get_results(self, fmt='json'):
        # item can be all, latency, throughput
        result = {
            "total_tx_l1_gbps": round(self.results[0]['tx_bps_L1']/1000000000, 4) ,
            "total_rx_gbps": round(self.results[0]['rx_bps']/1000000000, 4),
            "total_tx_rate_mpps": round(self.results[0]['tx_pps']/1000000, 4),
            "total_rx_rate_mpps": round(self.results[0]['rx_pps']/1000000, 4),
        }
        if fmt == 'table':
            table = PrettyTable(['Metrics', 'Statistics'])
            table.title = 'Test Results'
            table.add_row(['Total TX L1', str(result['total_tx_l1_gbps'])+' Gbps'])
            table.add_row(['Total Rx', str(result['total_rx_gbps'])+' Gbps'])
            table.add_row(['Total Tx Rate', str(result['total_tx_rate_mpps'])+' Mpps'])
            table.add_row(['Total Rx Rate', str(result['total_rx_rate_mpps'])+' Mpps'])
            return table
        else:
            return json.dumps(result)

    def write_to_file(self, file_name):
        if file_name != None:
            with open(file_name, 'w+') as f:
                f.write(self.get_results())

    def print_traffic_info(self):
        table = PrettyTable(['Field', 'Value'])
        table.title = "Packets Information"
        table.add_row(["Tunnel Type", self.tunnel_type])
        table.add_row(["Number of Flows", self.flow_amount])
        table.add_row(["Frame Size", str(self.frame_size)+' Bytes'])
        table.add_row(["Port Usage (Limited in 100G)", self.port_usage_percent])
        table.add_row(["Tunnel VNI", self.vni])
        table.add_row(["Outer Src MAC Add", self.outer_Ether.src])
        table.add_row(["Outer Dst MAC Add", self.outer_Ether.dst])
        table.add_row(["Outer Src IP Add", self.outer_IP.src])
        table.add_row(["Outer Dst IP Add", self.outer_IP.dst])
        table.add_row(["Inner Src MAC Add (start from)", self.inner_Ether.src])
        table.add_row(["Inner Dst MAC Add", self.inner_Ether.dst])
        table.add_row(["Inner Src IP Add", self.inner_IP.src])
        table.add_row(["Inner Dst IP Add", self.inner_IP.dst])
        return table


def main():
    import logging
    import argparse
    


    LOG_FORMAT = "%(asctime)s - %(message)s"
    logging.basicConfig(level=logging.INFO, format=LOG_FORMAT)


    parser = argparse.ArgumentParser(
        description="A Tunnel Traffic Generator of Trex",
        epilog='''
        Example of Usage:

        python3 trex_test.py -tt vxlan -oeths 04:3f:72:b2:c0:ac -oethd 0c:42:a1:9d:04:52 -oips 1.1.1.2 -oipd 1.1.1.1 -iethd e4:11:22:33:44:60 -iips 2.2.2.1 -iipd 2.2.2.2 -f 10240
        ''',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("-tt", "--tunnel_type", help="gre, vxlan, and geneve are valid options", required=True)
    parser.add_argument("-t", "--time", help="the traffic run time in seconds, default is 60", default=60, type=int)
    parser.add_argument("-f", "--flow_amount", help="The number of flows, default is 1024", default=1024, type=int)
    parser.add_argument("-s", "--frame_size", help="the frame size of the traffic, default is 128Bytes", default=128, type=int)
    parser.add_argument("-pu", "--port_usage", help="the line rate of the port, default is 100 percent", default="100%", type=str)
    parser.add_argument("-v", "--vni", help="the vni of the tunnel, default is 100", default=100, type=int)
    parser.add_argument("-oeths", "--outer_eth_src", help="the outer ethernet source address", required=True)
    parser.add_argument("-oethd", "--outer_eth_dst", help="the outer ethernet destination address", required=True)
    parser.add_argument("-oips", "--outer_ip_src", help="the outer ip source address", required=True)
    parser.add_argument("-oipd", "--outer_ip_dst", help="the outer ip destination address", required=True)
    parser.add_argument("-ieths", "--inner_eth_src", help="the inner ethernet source address, this will normally used as trex source server, which will be increaced to create many flows, default:00:00:00:00:00:01", default="00:00:00:00:00:01", type=str)
    parser.add_argument("-iethd", "--inner_eth_dst", help="the inner ethernet destination address, notmally this will be the VM's address", required=True)
    parser.add_argument("-iips", "--inner_ip_src", help="the inner IP source address, which will normally be Trex's IP, should be in the same subnet as inner dst ip", required=True)
    parser.add_argument("-iipd", "--inner_ip_dst", help="the inner IP destination address, which will normally be VM's IP", required=True)
    parser.add_argument("-w", "--write", help="write the results to a file", default=None)
    args = parser.parse_args()

    try:
        logging.info("Start to build packets.")

        # Build Streamer object and assign the properties
        traffic = Streamer()
        traffic.tunnel_type = args.tunnel_type.lower()
        traffic.flow_amount = args.flow_amount
        traffic.port_usage_percent = args.port_usage
        traffic.frame_size = args.frame_size
        traffic.vni = args.vni
        traffic.outer_Ether.src = args.outer_eth_src
        traffic.outer_Ether.dst = args.outer_eth_dst
        traffic.outer_IP.src = args.outer_ip_src
        traffic.outer_IP.dst = args.outer_ip_dst
        traffic.inner_Ether.src = args.inner_eth_src
        traffic.inner_Ether.dst = args.inner_eth_dst
        traffic.inner_IP.src = args.inner_ip_src
        traffic.inner_IP.dst = args.inner_ip_dst

        logging.info("Complete building packets.")
        logging.info("Ready to run the traffic.")
        print(traffic.print_traffic_info())
        logging.info("Running traffic...")

        # run the traffic
        traffic.run(traffic_time=args.time)
    
        print(traffic.get_results('table'))

        traffic.write_to_file(args.write)
    except Exception as E:
        print(E)



if __name__ == "__main__":
    main()
