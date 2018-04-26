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

if __name__ == '__main__':
    SimpleSwitchApplication().run()
