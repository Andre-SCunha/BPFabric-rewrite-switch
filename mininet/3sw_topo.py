#!/usr/bin/env python

from mininet.net import Mininet
from mininet.topo import Topo
from mininet.link import TCIntf, TCLink
from mininet.cli import CLI

from eBPFSwitch import eBPFSwitch, eBPFHost

from time import sleep

class SingleSwitchTopo(Topo):
    def __init__(self, **opts):
        # Initialize topology and default options
        Topo.__init__(self, **opts)

        coreSwitch = self.addSwitch('s1', switch_path="../softswitch/softswitch")
        aggSwitch1 = self.addSwitch('s2', switch_path="../softswitch/softswitch")
        aggSwitch2 = self.addSwitch('s3', switch_path="../softswitch/softswitch")

        self.addLink(aggSwitch1, coreSwitch, bw=10)
        self.addLink(aggSwitch2, coreSwitch, bw=10)

        for h in xrange(4):
            host = self.addHost('h%d' % (h + 1),
                                ip = "10.0.%d.10/24" % h,
                                mac = '00:04:00:00:00:%02x' %h)

            switch = aggSwitch1 if h < 2 else aggSwitch2
            self.addLink(host, switch, bw=2)

def main():
    topo = SingleSwitchTopo()
    net = Mininet(topo = topo, host = eBPFHost, switch = eBPFSwitch, controller = None, link = TCLink, intf = TCIntf)

    net.start()
    CLI(net)
    net.stop()

if __name__ == '__main__':
    main()
