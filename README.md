# trex_tunnel_traffic_generator
A Trex script that can generate tunnel traffic, including VXLAN/GRE/Geneve

# Dependencies

When using this as a script, you need to `pip install prettytable argparse`.

# How can I use it?

You could save this file to the trex path `automation/trex_control_plane/interactive` and start it.

- Note: The version of Trex should be v2.87 or above!

# CLI Options 
```shell
usage: trex_test.py [-h] -tt TUNNEL_TYPE [-t TIME] [-f FLOW_AMOUNT] [-s FRAME_SIZE] [-pu PORT_USAGE] [-v VNI] -oeths OUTER_ETH_SRC
                    -oethd OUTER_ETH_DST -oips OUTER_IP_SRC -oipd OUTER_IP_DST [-ieths INNER_ETH_SRC] -iethd INNER_ETH_DST -iips
                    INNER_IP_SRC -iipd INNER_IP_DST [-w WRITE]

A Tunnel Traffic Generator of Trex

optional arguments:
  -h, --help            show this help message and exit
  -tt TUNNEL_TYPE, --tunnel_type TUNNEL_TYPE
                        gre, vxlan, and geneve are valid options
  -t TIME, --time TIME  the traffic run time in seconds, default is 60
  -f FLOW_AMOUNT, --flow_amount FLOW_AMOUNT
                        The number of flows, default is 1024
  -s FRAME_SIZE, --frame_size FRAME_SIZE
                        the frame size of the traffic, default is 128Bytes
  -pu PORT_USAGE, --port_usage PORT_USAGE
                        the line rate of the port, default is 100 percent
  -v VNI, --vni VNI     the vni of the tunnel, default is 100
  -oeths OUTER_ETH_SRC, --outer_eth_src OUTER_ETH_SRC
                        the outer ethernet source address
  -oethd OUTER_ETH_DST, --outer_eth_dst OUTER_ETH_DST
                        the outer ethernet destination address
  -oips OUTER_IP_SRC, --outer_ip_src OUTER_IP_SRC
                        the outer ip source address
  -oipd OUTER_IP_DST, --outer_ip_dst OUTER_IP_DST
                        the outer ip destination address
  -ieths INNER_ETH_SRC, --inner_eth_src INNER_ETH_SRC
                        the inner ethernet source address, this will normally used as trex source server, which will be increaced to
                        create many flows, default:00:00:00:00:00:01
  -iethd INNER_ETH_DST, --inner_eth_dst INNER_ETH_DST
                        the inner ethernet destination address, notmally this will be the VM's address
  -iips INNER_IP_SRC, --inner_ip_src INNER_IP_SRC
                        the inner IP source address, which will normally be Trex's IP, should be in the same subnet as inner dst ip
  -iipd INNER_IP_DST, --inner_ip_dst INNER_IP_DST
                        the inner IP destination address, which will normally be VM's IP
  -w WRITE, --write WRITE
                        write the results to a file

        Example of Usage:

        python3 trex_test.py -tt vxlan -oeths 04:3f:72:b2:c0:ac -oethd 0c:42:a1:9d:04:52 -oips 1.1.1.2 -oipd 1.1.1.1 -iethd e4:11:22:33:44:60 -iips 2.2.2.1 -iipd 2.2.2.2 -f 10240
```
