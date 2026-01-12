from scapy.all import rdpcap
from mac_vendor_lookup import MacLookup


class AnalyzeNetwork:
    def __init__(self, pcap_path):
        """
        pcap_path: path to a pcap file
        """
        self.pcap_path = pcap_path

    def get_ips(self):
        """
        returns a list of ip addresses (strings) that appear in the pcap
        """
        raise NotImplementedError

    def get_macs(self):
        """
        returns a list of MAC addresses (strings) that appear in the pcap
        """
        raise NotImplementedError

    def get_info_by_mac(self, mac):
        """
        returns a dict with all information about the device with given MAC address
        """
        raise NotImplementedError

    def get_info_by_ip(self, ip):
        """
        returns a dict with all information about the device with given IP address
        """
        raise NotImplementedError

    def get_info(self):
        """
        returns a list of dicts with information about every device in the pcap
        """
        packets = rdpcap(self.pcap_path)
        result = []
        for packet in packets:
            sender_info = {}
            receiver_info = {}

            if packet.haslayer("IP"):
                sender_info["IP"] = packet["IP"].src
                receiver_info["IP"] = packet["IP"].dst
            else:
                sender_info["IP"] = "Unknown"
                receiver_info["IP"] = "Unknown"

            if packet.haslayer("Ether"):
                # for sender
                sender_info["MAC"] = packet["Ether"].src
                try:
                    vendor = MacLookup().lookup(sender_info["MAC"])
                except Exception:
                    vendor = "Unknown"
                sender_info["Vendor"] = vendor

                # for receiver
                receiver_info["MAC"] = packet["Ether"].dst
                try:
                    vendor = MacLookup().lookup(receiver_info["MAC"])
                except Exception:
                    vendor = "Unknown"
                receiver_info["Vendor"] = vendor
            else:
                sender_info["MAC"] = "Unknown"
                sender_info["Vendor"] = "Unknown"
                receiver_info["MAC"] = "Unknown"
                receiver_info["Vendor"] = "Unknown"

            # check if sender_info is already in result
            if sender_info not in result:
                result.append(sender_info)
            if receiver_info not in result:
                result.append(receiver_info)
        return result

    def __repr__(self):
        raise NotImplementedError

    def __str__(self):
        raise NotImplementedError
