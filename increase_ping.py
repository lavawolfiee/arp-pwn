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

import time


def process_packet(packet, increase_ping_by: float = 0.1):
    """
    This function is executed whenever a packet is sniffed
    """

    timestamp = packet.get_timestamp()

    if abs(timestamp - 0.0) >= 0.01:
        ping = time.time() - timestamp
        to_sleep = increase_ping_by - ping

        if to_sleep > 0.0:
            time.sleep(to_sleep)
    else:
        time.sleep(increase_ping_by)

    # accept all the packets
    packet.accept()


def set_iptables() -> None:
    """
    Sets iptables to jump all the forwarded tcp packets to NFQUEUE 0
    """
    os.system("sudo iptables -I FORWARD -j NFQUEUE --queue-num 0")


def unset_iptables() -> None:
    os.system("sudo iptables -F")


def main(args):
    queue = netfilterqueue.NetfilterQueue()

    try:
        print("[*] Creating nfqueue")
        set_iptables()
        queue.bind(0, functools.partial(process_packet, increase_ping_by=args.ping / 1000))
        print(f"{GREEN}[+]{RESET} Started")
        queue.run()
    except KeyboardInterrupt:
        pass
    finally:
        print(f"[*] Shutting down")
        unset_iptables()
        queue.unbind()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(prog='Script to increase ping of all forwarded traffic')
    parser.add_argument('-p', '--ping', type=float, help="Increase ping by this number of ms",
                        default=100.0)
    args = parser.parse_args()

    main(args)
