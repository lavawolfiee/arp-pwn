import argparse
from typing import List, Tuple

import mac_vendor_lookup
from mac_vendor_lookup import MacLookup
from scapy.layers.l2 import ARP, Ether
from scapy.sendrecv import srp


def scan_hosts(network_range: str, inter: float = 0.2, timeout: float = 10.) -> List[Tuple[str, str]]:
    arp_request = ARP(pdst=network_range)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether / arp_request

    result = srp(packet, timeout=timeout, inter=inter)
    hosts: List = []

    for _, received in result[0]:
        hosts.append((received.psrc, received.hwsrc))

    return hosts


def main(network_range: str, inter: float, timeout: float) -> None:
    hosts = scan_hosts(network_range, inter, timeout)
    mac_lookup = MacLookup()

    print()
    print('-' * 60)
    print(f' {"   IP":<15}  {"At MAC Address":<17}  MAC Vendor')
    print('-' * 60)

    for ip, mac in hosts:
        mac_vendor = ""

        try:
            mac_vendor = mac_lookup.lookup(mac)
        except mac_vendor_lookup.VendorNotFoundError:
            pass

        print(f' {ip:<15}  {mac:<17}  {mac_vendor}')


if __name__ == "__main__":
    parser = argparse.ArgumentParser(prog='ARP network scanner')
    parser.add_argument('-r', '--range', type=str, help='IP range to scan', required=True)
    parser.add_argument('-s', '--sleep', type=float,
                        help='time to sleep between each ARP request (milliseconds)', default=1. / 3)
    parser.add_argument('-t', '--timeout', type=float, default=10.,
                        help='how much time to wait for answers (seconds)')
    args = parser.parse_args()

    main(args.range, args.sleep, args.timeout)
