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
        info = {}
        packets = rdpcap(self.pcap_path)
        for packet in packets:
            if packet.haslayer("Ether"):
                if packet["Ether"].src == mac or packet["Ether"].dst == mac:
                    info["MAC"] = mac
                    try:
                        vendor = MacLookup().lookup(mac)
                    except Exception:
                        vendor = "Unknown"
                    info["Vendor"] = vendor
                    if packet.haslayer("IP"):
                        ip = (
                            packet["IP"].src
                            if packet["Ether"].src == mac
                            else packet["IP"].dst
                        )
                        info["IP"] = ip
                    else:
                        info["IP"] = "Unknown"

                    if packet.haslayer("IPv6"):
                        ipv6 = (
                            packet["IPv6"].src
                            if packet["IP"].src == ip
                            else packet["IPv6"].dst
                        )
                        info["IPv6"] = ipv6
                    else:
                        info["IPv6"] = "Unknown"

                    if packet.time:
                        info["Time"] = str(packet.time)

                    return info
        return None

    def get_info_by_ip(self, ip):
        """
        returns a dict with all information about the device with given IP address
        """
        info = {}
        packets = rdpcap(self.pcap_path)
        for packet in packets:
            if packet.haslayer("IP"):
                if packet["IP"].src == ip or packet["IP"].dst == ip:
                    if packet.haslayer("Ether"):
                        mac = (
                            packet["Ether"].src
                            if packet["IP"].src == ip
                            else packet["Ether"].dst
                        )
                        info["MAC"] = mac
                        try:
                            vendor = MacLookup().lookup(mac)
                        except Exception:
                            vendor = "Unknown"
                        info["Vendor"] = vendor
                    else:
                        info["MAC"] = "Unknown"
                        info["Vendor"] = "Unknown"

                    if packet.haslayer("IPv6"):
                        ipv6 = (
                            packet["IPv6"].src
                            if packet["IP"].src == ip
                            else packet["IPv6"].dst
                        )
                        info["IPv6"] = ipv6
                    else:
                        info["IPv6"] = "Unknown"

                    if packet.time:
                        info["Time"] = str(packet.time)

                    info["IP"] = ip
                    return info
        return None

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

                if packet.time:
                    sender_info["Time"] = str(packet.time)
                    receiver_info["Time"] = str(packet.time)

            else:
                sender_info["IP"] = "Unknown"
                receiver_info["IP"] = "Unknown"

            if packet.haslayer("IPv6"):
                sender_info["IPv6"] = packet["IPv6"].src
                receiver_info["IPv6"] = packet["IPv6"].dst
            else:
                sender_info["IPv6"] = "Unknown"
                receiver_info["IPv6"] = "Unknown"

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

    def guess_os(self, ip):
        """returns assumed operating system based on ttl value or data value of ping packets from the given ip address"""
        # ip is expected to be the return type of get_info_by_ip or similar
        ip = ip["IP"]
        packets = rdpcap(self.pcap_path)
        for packet in packets:
            if packet.haslayer("IP") and packet["IP"].src == ip:
                ttl = packet["IP"].ttl
                if 60 <= ttl <= 64:  # give some range for tolerance
                    return ["Linux", "Unix", "MacOS"]
                if 120 <= ttl <= 128:  # give some range for tolerance
                    return "Windows"
                if 251 <= ttl <= 255:  # give some range for tolerance
                    return ["Cisco", "Network Device"]
            if packet.haslayer("ICMP") and packet["IP"].src == ip:
                data = bytes(packet["ICMP"].payload)
                if data == b"abcdefghijklmnopqrstuvwabcdefghi":
                    return "Windows"
                elif (
                    data
                    == b"\x00\x887f\x00\x00\x00\x00\x19\x1d\n\x00\x00\x00\x00\x00\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f !\"#$%&'()*+,-./01234567"
                ):
                    return ["Linux", "Unix", "MacOS"]
        return "Unknown"

    def __repr__(self):
        raise NotImplementedError

    def __str__(self):
        raise NotImplementedError
