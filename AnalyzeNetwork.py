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
        count = 0
        packets = rdpcap(self.pcap_path)
        for packet in packets:
            if packet.haslayer("Ether"):
                if packet["Ether"].src == mac or packet["Ether"].dst == mac:
                    count += 1
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
                        info["First Seen"] = str(packet.time)

                    info["Count"] = count

                    if packet.haslayer("TCP"):
                        user_agent = self.get_user_agent(packet["TCP"])

                        if packet["IP"].src == ip and packet["TCP"].sport:
                            info["Open Ports"] = info.get("Open Ports", []) + [
                                packet["TCP"].sport
                            ]
                            if user_agent:
                                info["User Agent"] = user_agent
                        elif packet["IP"].dst == ip and packet["TCP"].dport:
                            info["Open Ports"] = info.get("Open Ports", []) + [
                                packet["TCP"].dport
                            ]
                            if user_agent:
                                info["http server"] = True

        return info if info else None

    def get_info_by_ip(self, ip):
        """
        returns a dict with all information about the device with given IP address
        """
        info = {}
        count = 0
        packets = rdpcap(self.pcap_path)
        for packet in packets:
            if packet.haslayer("IP"):
                if packet["IP"].src == ip or packet["IP"].dst == ip:
                    count += 1
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
                        info["First Seen"] = str(packet.time)

                    if packet.haslayer("TCP"):
                        user_agent = self.get_user_agent(packet["TCP"])

                        if packet["IP"].src == ip and packet["TCP"].sport:
                            info["Open Ports"] = info.get("Open Ports", []) + [
                                packet["TCP"].sport
                            ]
                            if user_agent:
                                info["User Agent"] = user_agent
                        elif packet["IP"].dst == ip and packet["TCP"].dport:
                            info["Open Ports"] = info.get("Open Ports", []) + [
                                packet["TCP"].dport
                            ]
                            if user_agent:
                                info["http server"] = True

                    info["IP"] = ip
                    info["Count"] = count
        return info if info else None

    def get_info(self):
        """
        returns a list of dicts with information about every device in the pcap
        """
        packets = rdpcap(self.pcap_path)
        result = []
        for packet in packets:
            sender_info = {}
            receiver_info = {}

            # this isn't in the definition because the IDE doesn't like it
            sender_info["Count"] = 1
            receiver_info["Count"] = 1

            if packet.haslayer("IP"):
                sender_info["IP"] = packet["IP"].src
                receiver_info["IP"] = packet["IP"].dst

                if packet.time:
                    sender_info["First Seen"] = str(packet.time)
                    receiver_info["First Seen"] = str(packet.time)

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

            if packet.haslayer("TCP"):
                user_agent = self.get_user_agent(packet["TCP"])
                if user_agent:
                    sender_info["User Agent"] = user_agent
                    receiver_info["http server"] = True

                if packet["IP"].src == sender_info["IP"] and packet["TCP"].sport:
                    sender_info["Open Ports"] = sender_info.get("Open Ports", []) + [
                        packet["TCP"].sport
                    ]

                if packet["IP"].dst == receiver_info["IP"] and packet["TCP"].dport:
                    receiver_info["Open Ports"] = receiver_info.get(
                        "Open Ports", []
                    ) + [packet["TCP"].dport]

            # check if mac is already in result
            existing_sender = next(
                (d for d in result if d.get("MAC") == sender_info.get("MAC")), None
            )
            if existing_sender:
                for key, value in sender_info.items():
                    if key == "Count":
                        existing_sender[key] += 1
                    if key not in existing_sender or existing_sender[key] == "Unknown":
                        existing_sender[key] = value
            else:
                result.append(sender_info)

            existing_receiver = next(
                (d for d in result if d.get("MAC") == receiver_info.get("MAC")), None
            )
            if existing_receiver:
                for key, value in receiver_info.items():
                    if key == "Count":
                        existing_receiver[key] += 1
                    if (
                        key not in existing_receiver
                        or existing_receiver[key] == "Unknown"
                    ):
                        existing_receiver[key] = value
            else:
                result.append(receiver_info)
        return result

    def get_user_agent(self, tcp):
        """returns user agent string from given tcp packet if exists, else None"""
        if tcp.haslayer("Raw"):
            raw = bytes(tcp["Raw"].load)
            marker = b"User-Agent:"
            start = raw.find(marker)
            if start != -1:
                end = raw.find(b"\r\n", start)
                if end == -1:
                    end = len(raw)
                user_agent = (
                    raw[start + len(marker) : end]
                    .decode("ascii", errors="ignore")
                    .strip()
                )
                return user_agent
        return None

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
