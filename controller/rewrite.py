#!/usr/bin/env python
import struct

from core import eBPFCoreApplication, set_event_handler, FLOOD
from core.packets import *

class SimpleSwitchApplication(eBPFCoreApplication):
    @set_event_handler(Header.HELLO)
    def hello(self, connection, pkt):
        server_list = ["0a00020a", "0a00030a"]
        switches = [1]
        if (pkt.dpid in switches):
            with open('../examples/rewrite.o', 'rb') as f:
                print("Installing the eBPF ELF")
                connection.send(InstallRequest(elf=f.read()))
            for i in range(len(server_list)):
                connection.send(TableEntryInsertRequest(table_name="servers", key=struct.pack('<I', i+1), value=server_list[i].decode('hex')))

        else:
            with open('../examples/learningswitch.o', 'rb') as f:
                print("Installing the eBPF ELF")
                connection.send(InstallRequest(elf=f.read()))

    @set_event_handler(Header.PACKET_IN)
    def packet_in(self, connection, pkt):
        metadatahdr_fmt = 'I10x'
        ethhdr_fmt = '>6s6sH'

        in_port, = struct.unpack_from(metadatahdr_fmt, pkt.data, 0)
        eth_dst, eth_src, eth_type = struct.unpack_from(ethhdr_fmt, pkt.data, struct.calcsize(metadatahdr_fmt))

        print in_port, eth_dst.encode('hex'), eth_src.encode('hex'), hex(eth_type)

        self.mac_to_port.setdefault(connection.dpid, {})

        if ord(eth_src[0]) & 1 == 0:
            self.mac_to_port[connection.dpid][eth_src] = in_port
            print 'Inserting entry in switch {}  {} {}'.format(connection.dpid, eth_src.encode('hex'), in_port)
            connection.send(TableEntryInsertRequest(table_name="inports", key=eth_src, value=struct.pack('I', in_port)))

        if ord(eth_dst[0]) & 1 == 1:
            out_port = FLOOD
        else:
            out_port = self.mac_to_port[connection.dpid].get(eth_dst, FLOOD)

        connection.send(PacketOut(data=pkt.data, out_port=out_port))

if __name__ == '__main__':
    SimpleSwitchApplication().run()
