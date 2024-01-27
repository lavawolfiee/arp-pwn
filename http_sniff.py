import argparse
import functools

import colorama
import scapy.packet
from colorama import Fore, Style

from scapy.layers.http import HTTPRequest, HTTPResponse, HTTP
from scapy.layers.inet import IP
from scapy.packet import Raw
from scapy.sendrecv import sniff

colorama.init()

GREEN = Fore.GREEN
RED = Fore.RED
RESET = Style.RESET_ALL
BRIGHT = Style.BRIGHT


def sniff_packets(iface: str | None = None, show_raw: bool = True) -> None:
    """
    Sniff http packets on 80 port with `iface`, if None (default), then the
    Scapy's default interface is used
    """

    # `process_packet` is the callback
    sniff(filter="port 80", prn=functools.partial(process_packet, show_raw=show_raw), iface=iface, store=False)


def process_packet(packet: scapy.packet.Packet, show_raw=True):
    """
    This function is executed whenever a packet is sniffed
    """

    if packet.haslayer(HTTPRequest):
        # if this packet is an HTTP Request
        # get the requested URL
        url = packet[HTTPRequest].Host.decode() + packet[HTTPRequest].Path.decode()
        # get the requester's IP Address
        ip = packet[IP].src
        method = packet[HTTPRequest].Method.decode()
        print(f"{GREEN}[+]{RESET} {BRIGHT}{ip}{RESET} requested {BRIGHT}{url}{RESET} with {BRIGHT}{method}{RESET}")

        if packet[HTTPRequest].Cookie is not None:
            print(f"{RED}[*] Cookie:{RESET} {packet[HTTPRequest].Cookie}{RESET}")
        if packet[HTTPRequest].Authorization is not None:
            print(f"{RED}[*] Authorization:{RESET} {packet[HTTPRequest].Authorization}{RESET}")

    if packet.haslayer(HTTPResponse):
        response = packet[HTTPResponse]
        src = packet[IP].src
        dst = packet[IP].dst
        status_code = response.Status_Code.decode()
        reason = response.Reason_Phrase.decode()

        print(f"{GREEN}[+]{RESET} {BRIGHT}{src}{RESET} responsed to {BRIGHT}{dst}{RESET} with "
              f"{BRIGHT}{status_code} {reason}{RESET}")

        if response.Set_Cookie is not None:
            print(f"{RED}[*] Set-Cookie:{RESET} {response.Set_Cookie}{RESET}")

    if show_raw and packet.haslayer(HTTP) and packet.haslayer(Raw):
        # then show raw
        print(f"{RED}[*] Some useful Raw data:{RESET} {packet[Raw].load}{RESET}")
        print()


def main(args: argparse.Namespace) -> None:
    sniff_packets(args.iface, show_raw=args.verbose)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(prog='HTTP packets sniffer')
    parser.add_argument('-i', '--iface', type=str, help='Interface to sniff on', default=None)
    parser.add_argument('-v', '--verbose', help='Show raw data in requests and responses',
                        action="store_true", default=False)
    args = parser.parse_args()

    main(args)
