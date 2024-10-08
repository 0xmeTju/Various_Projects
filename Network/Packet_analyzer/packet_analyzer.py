from scapy.all import rdpcap
import ruamel.yaml
from ruamel.yaml.scalarstring import PreservedScalarString
import sys
import argparse

#Constants
INPUT_FILE = (
    "C:\\Users\\pc\\Downloads\\test_pcap_files\\vzorky_pcap_na_analyzu\\trace-12.pcap"
)
OUTPUT_FILE = "output.yaml"
PROTOCOL_CODES = "./protocols/protocols.yaml"
ISL_SIZE = 26

#Function that gets arguments from command line
def get_args(protocol_list):
    #Setups parser from argparse module
    parser = argparse.ArgumentParser(description='Protocol analyzer switch')
    parser.add_argument('-p', type=str, nargs='?', default='', help='protocol name')
    args = parser.parse_args()
    #Logic behind passing argument
    if args.p == '':
        print('No argument')
    elif args.p == None:
        print("No protocol specified")
        sys.exit(1)
    elif args.p not in protocol_list["arguments"].split():
        print('Protocol not found')
        sys.exit(1)
        
    SWITCH_P = args.p
    return SWITCH_P


# Returns byte array formatted in hex format
def fhex(byte_array):
    output = " ".join(f"{byte:02X}" for byte in byte_array)
    return output


# Returns byte array formatted in mac adress format
def mac(byte_array):
    output = ":".join(f"{byte:02X}" for byte in byte_array)
    return output


def ip(byte_array):
    output = ".".join(f"{byte}" for byte in byte_array)
    return output

#Checks frame type and then returns correct frame type
def check_frame(frame, header):
    if frame > b"\x06\x00":
        return "ETHERNET II"
    elif frame <= b"\x05\xDC":
        if header == b"\xAA\xAA":
            return "IEEE 802.3 LLC & SNAP"
        elif header == b"\xFF\xFF":
            return "IEEE 802.3 RAW"
        else:
            return "IEEE 802.3 LLC"


# Makes readable hexa_frame with 16 bytes on each line
def hex_dump(packet, size):
    hexa = ""
    x = 0
    y = 16
    while x < size:
        hexa += fhex(packet[x:y]) + "\n"
        x += 16
        y += 16
    return hexa


# Checks for potential ISL header and then removes it for easier work
def remove_ISL(packet):
    if packet[0:5] == b"\x01\x00\x0c\x00\x00" or packet[0:5] == b"\x03\x00\x0c\x00\x00":
        return packet[ISL_SIZE:]
    else:
        return packet

#Prints info about packet into console
#Not used in final version
def print_info(packet_info):
    print("NO.", packet_info["frame_number"])
    print(
        "Packet size:",
        packet_info["len_frame_pcap"],
        "bytes |",
        packet_info["len_frame_pcap"] * 8,
        "bits",
    )
    print(
        "Medium size:",
        packet_info["len_frame_medium"],
        "bytes |",
        packet_info["len_frame_medium"] * 8,
        "bits",
    )
    print("Frame type: " + packet_info["frame_type"])
    print("Src: " + packet_info["src_mac"], "\nDst: " + packet_info["dst_mac"])
    if "sap" in packet_info:
        print("Sap: " + packet_info["sap"])
    elif "pid" in packet_info:
        print("Pid: " + packet_info["pid"])
    print("Hex dump:")
    print(packet_info["hexa_frame"])


# Gets frame protocol info
def frame_protocol(frame_type, packet_info, packet, protocols):
    #Checking frame type and then searching for protocols from protocols.yaml
    if frame_type == "IEEE 802.3 LLC":
        sap_b = int.from_bytes(packet[14:15], byteorder="big")
        sap = protocols["sap"].get(sap_b, 0)
        packet_info["sap"] = sap
    elif frame_type == "IEEE 802.3 LLC & SNAP":
        pid_b = int.from_bytes(packet[20:22], byteorder="big")
        pid = protocols["pid"].get(pid_b, 0)
        packet_info["pid"] = pid
    elif frame_type == "ETHERNET II":
        prot_b = int.from_bytes(packet[12:14], byteorder="big")
        protocol = protocols["ether_type"].get(prot_b, 0)
        packet_info["ether_type"] = protocol

#Checks if ip address is associated with any trafic
def check_trafic(ip_adress, ip_trafic):
    #If ip_address was already found add 1 to its trafic
    if ip_adress in ip_trafic:
        ip_trafic[ip_adress] += 1
    #If it wasn't, add it and give it 1
    else:
        ip_trafic[ip_adress] = 1


# Gets ether protocol info
def ether_address(packet_info, packet, protocols, ip_trafic = None):
    #Choosing if we want to keep track of out ip_trafic or not
    if ip_trafic == None:
        #Match statement for ether_type
        match packet_info["ether_type"]:
            #Matching 4 most common ether_types for ETHERNET II
            case "IPv4":
                #Getting src and dst ip adresses from its bytes
                packet_info["src_ip"] = ip(packet[26:30])
                packet_info["dst_ip"] = ip(packet[30:34])
                #Getting IPv4 protocol info
                packet_info["protocol"] = IPv4_protocol(packet, protocols)
                #Getting port and app protocol info
                get_port(packet, protocols, packet_info)
            case "IPv6":
                ...
            case "ARP":
                packet_info["src_ip"] = ip(packet[28:32])
                packet_info["dst_ip"] = ip(packet[38:42])
            case "LLDP":
                ...
            case "ECTP":
                ...
    else:
        match packet_info["ether_type"]:
            case "IPv4":
                packet_info["src_ip"] = ip(packet[26:30])
                packet_info["dst_ip"] = ip(packet[30:34])
                packet_info["protocol"] = IPv4_protocol(packet, protocols)
                get_port(packet, protocols, packet_info)
                check_trafic(packet_info["src_ip"], ip_trafic)
            case "IPv6":
                ...
            case "ARP":
                packet_info["src_ip"] = ip(packet[28:32])
                packet_info["dst_ip"] = ip(packet[38:42])
            case "LLDP":
                ...
            case "ECTP":
                ...


# Gets IPv4 protocol info
def IPv4_protocol(packet, protocols):
    #Gets byte from packet and then searches for protocol in protocols.yaml
    protocol_b = int.from_bytes(packet[23:24], byteorder="big")
    protocol = protocols["ipv4_protocol"].get(protocol_b, 0)
    return protocol


# Gets IPv4 size(checks if options field is present)
def IPv4_size(packet):
    IHL = int.from_bytes(packet[14:15], byteorder="big")
    mask = 0x0F
    return IHL & mask


# Gets port and app protocol info
def get_port(packet, protocols, packet_info):
    #Gets offset by calculating IPv4 option header size
    offset = (IPv4_size(packet) * 4) - 20
    #Then adds offsets to out relative bytes to find correct port location
    src_port = int.from_bytes(packet[34 + offset : 36 + offset], byteorder="big")
    dst_port = int.from_bytes(packet[36 + offset : 38 + offset], byteorder="big")
    #Then it saves port info to packet_info dictionary
    packet_info["src_port"] = src_port
    packet_info["dst_port"] = dst_port

    #Then it searches for app protocol in protocols.yaml
    if protocols["udp_protocol"].get(src_port, 0) != 0:
        packet_info["app_protocol"] = protocols["udp_protocol"].get(src_port, 0)
    elif protocols["udp_protocol"].get(dst_port, 0) != 0:
        packet_info["app_protocol"] = protocols["udp_protocol"].get(dst_port, 0)
    elif protocols["tcp_protocol"].get(src_port, 0) != 0:
        packet_info["app_protocol"] = protocols["tcp_protocol"].get(src_port, 0)
    elif protocols["tcp_protocol"].get(dst_port, 0) != 0:
        packet_info["app_protocol"] = protocols["tcp_protocol"].get(dst_port, 0)

def get_flags(packet):
    #Gets flag byte from packet
    tcp_flag = int.from_bytes(packet[47:48], byteorder="big")
    #Creates dictionary for flags
    flags = {
        'fin': False,
        'syn': False,
        'rst': False,
        'psh': False,
        'ack': False,
        'urg': False
    }
    #Checks if flag is set and if it is it sets it to True
    #Using bitwise operators
    if (tcp_flag & 0b000001) == 0b000001: flags['fin'] = True
    if (tcp_flag & 0b000010) == 0b000010: flags['syn'] = True
    if (tcp_flag & 0b000100) == 0b000100: flags['rst'] = True
    if (tcp_flag & 0b001000) == 0b001000: flags['psh'] = True
    if (tcp_flag & 0b010000) == 0b010000: flags['ack'] = True
    if (tcp_flag & 0b100000) == 0b100000: flags['urg'] = True

    return flags

def three_way_handshake(packets):
    #Checks if there are 3 packets
    if len(packets) != 3:
        return False
    #Gets flags from each packet
    flags1 = get_flags(packets[0])
    flags2 = get_flags(packets[1])
    flags3 = get_flags(packets[2])
    
    #Gets payload length from each packet
    packet1_payload = get_payload_length(packets[0])
    packet2_payload = get_payload_length(packets[1])
    
    #Checks if flags are set correctly for 3-way handshake
    if flags1['syn'] and flags2['syn'] and flags2['ack'] and flags3['ack']:
        seq1 = int.from_bytes(packets[0][38:42], byteorder="big")
        seq2 = int.from_bytes(packets[1][38:42], byteorder="big")
        ack2 = int.from_bytes(packets[1][42:46], byteorder="big")
        seq3 = int.from_bytes(packets[2][38:42], byteorder="big")
        ack3 = int.from_bytes(packets[2][42:46], byteorder="big")
        
        #Checks if seq and ack numbers are correct
        if seq1 + packet1_payload + 1 == ack2 and seq2 + packet2_payload + 1 == ack3 and ack2 == seq3:
            #Connection successfully established
            return True 
        
    return False

def four_way_handshake(packets):
    #Same as 3-way handshake but with 4 packets
    if len(packets) != 4:
        return False
    
    flags1 = get_flags(packets[0])
    flags2 = get_flags(packets[1])
    flags3 = get_flags(packets[2])
    flags4 = get_flags(packets[3])
    
    packet1_payload = get_payload_length(packets[0])
    packet2_payload = get_payload_length(packets[1])
    
    if flags1["syn"] and flags2["syn"] and flags3["ack"] and flags3["ack"]:
        seq1 = int.from_bytes(packets[0][38:42], byteorder="big")
        seq2 = int.from_bytes(packets[1][38:42], byteorder="big")
        seq3 = int.from_bytes(packets[2][38:42], byteorder="big")
        ack3 = int.from_bytes(packets[2][42:46], byteorder="big")
        seq4 = int.from_bytes(packets[3][38:42], byteorder="big")
        ack4 = int.from_bytes(packets[3][42:46], byteorder="big")
        
        if (seq1 + 1 + packet1_payload == ack3 and seq2 + packet2_payload + 1 == ack4) or (seq1 + packet1_payload + 1 == ack4 and seq2 + packet2_payload + 1 == ack3):
            #Connection successfully established
            #print("Connection established via 4-way handshake")
            return True
    return False
#unused
def wants_to_close(packet):
    flags = get_flags(packet)
    if flags["fin"] or flags["rst"]:
        return True
    return False

def connection_termination_fin_rst(packets):
    #Checks if there are 2 packets
    if len(packets) != 2:
        return False
    #Gets flags from each packet
    flags1 = get_flags(packets[0])
    flags2 = get_flags(packets[1])
    #Checks if flags are set correctly for connection termination
    if flags1["fin"] and flags2["rst"]:
        #print("Connection terminated with FIN-RST flag")
        return True
    elif flags2["rst"]:
        #print("Connection terminated with RST flag")
        return True
    return False

def connection_termination_rst(packet):
    flags = get_flags(packet)
    if flags["rst"]:
        #print("Connection terminated with RST flag")
        return True
    return False

def tcp_header_length(packet):
    #Gets header length from packet
    HL = int.from_bytes(packet[46:47], byteorder="big")
    HL = HL >> 4
    mask = 0x0F
    return HL & mask

def get_payload_length(packet):
    if remove_padding(packet):
        return 0
    length = len(packet[54+((tcp_header_length(packet)*4)-20):])
    return length

def remove_padding(packet):
    padding = packet[54:]
    if padding == b"\x00\x00\x00\x00\x00\x00":
        return True
    elif padding[2:] == b"\x00\x00\x00\x00":
        return True
    elif padding[4:] == b"\x00\x00":
        return True
    return False
    
def connection_termination_ex(packets):
    #Same as 4-way handshake but with 5 packets
    if len(packets) != 5:
        return False
    
    flags1 = get_flags(packets[0])
    flags2 = get_flags(packets[1])
    flags3 = get_flags(packets[2])
    flags4 = get_flags(packets[3])
    flags5 = get_flags(packets[4])

    if flags1["fin"] and flags4["fin"] and flags4["ack"] and flags5["ack"]:
        #print("Connection terminated")
        return True
    return False



def connection_termination(packets):
    if len(packets) != 4:
        return False
    
    flags1 = get_flags(packets[0])
    flags2 = get_flags(packets[1])
    flags3 = get_flags(packets[2])
    flags4 = get_flags(packets[3])
    
    packet1_payload = get_payload_length(packets[0])
    packet2_payload = get_payload_length(packets[1])

    
    if flags1["fin"] and flags2["ack"] and flags3["fin"] and flags4["ack"]:
        seq1 = int.from_bytes(packets[0][38:42], byteorder="big")
        seq2 = int.from_bytes(packets[1][38:42], byteorder="big")
        seq3 = int.from_bytes(packets[2][38:42], byteorder="big")
        ack3 = int.from_bytes(packets[2][42:46], byteorder="big")
        seq4 = int.from_bytes(packets[3][38:42], byteorder="big")
        ack4 = int.from_bytes(packets[3][42:46], byteorder="big")
        
        if (seq1 + packet1_payload + 1 == ack3 and seq2 + packet2_payload + 1 == ack4) or (seq1 + packet1_payload + 1 == ack4 and seq2 + packet2_payload + 1 == ack3):
            #Connection successfully terminated
            #print("Connection terminated")
            return True
        
    elif flags1["fin"] and flags2["fin"] and flags2["ack"] and flags3["ack"]:
        #print("Connection terminated")
        return True
    
    elif flags2["fin"] and flags3["fin"] and flags3["ack"] and flags4["ack"]:
        #print("Connection terminated")
        return True
    
    return False

def get_opcode(packet):
    opcode = int.from_bytes(packet[20:22], byteorder="big")
    return opcode

def get_frame_number(packet):
    return packet["frame_number"]

def arp(pcap_file, protocols,arg):
    pcounter = 0
    arp_connections = {}
    arp_requests = {}
    arp_replies = {}

    # Main for loop that iterates through all packets in pcap
    # Same as in default
    for packet in pcap_file:
        pcounter += 1
        packet_size = len(packet)
        medium_size = max(packet_size + 4, 64)
        hexa_frame = hex_dump(bytes(packet), packet_size)
        packet = remove_ISL(bytes(packet))

        # Mac address
        dst_b = packet[0:6]
        src_b = packet[6:12]
        # Frame type data
        frame_b = packet[12:14]
        header_b = packet[14:16]
        frame_type = check_frame(frame_b, header_b)

        # Yaml output
        packet_info = {
            "frame_number": pcounter,
            "len_frame_pcap": packet_size,
            "len_frame_medium": medium_size,
            "frame_type": check_frame(frame_b, header_b),
            "src_mac": mac(src_b),
            "dst_mac": mac(dst_b),
        }

        # Frame info
        frame_protocol(frame_type, packet_info, packet, protocols)
        opcode = get_opcode(packet)
        if opcode == 1:
            packet_info["arp_opcode"] = "REQUEST"
        elif opcode == 2:
            packet_info["arp_opcode"] = "REPLY"

        #If frame type is ETHERNET II, we can continue with our ARP analysis
        if packet_info["frame_type"] == "ETHERNET II":
            ether_address(packet_info, packet, protocols)
        #If not we skip this packet
        else:
            packet_info = {}
            continue    
        #If ether_type is not ARP we skip this packet

        if packet_info["ether_type"] != "ARP":
            continue
        
        packet_info["hexa_frame"] = PreservedScalarString(hexa_frame)
        

        #Get all ARP requests and replies
        if packet_info["ether_type"] == "ARP":
            if packet_info["arp_opcode"] == "REQUEST":
                req_connection_key = (packet_info["src_ip"],packet_info["dst_ip"])
                if req_connection_key in arp_requests:
                    arp_requests[req_connection_key]["packets"].append( packet_info)
                else:
                    arp_requests[req_connection_key] = {"packets": [packet_info]}
            elif packet_info["arp_opcode"] == "REPLY":
                rep_connection_key = (packet_info["dst_ip"],packet_info["src_ip"])
                if rep_connection_key in arp_replies:
                    arp_replies[rep_connection_key]["packets"].append(packet_info)
                else:
                    arp_replies[rep_connection_key] = {"packets": [packet_info]}
        else:
            packet_info = {}
            continue

    #Work with each connection separately
    all_connections = {
        "name": "PKS2023/24",
        "pcap_name": INPUT_FILE,
        "filter_name": arg,
        "complete_comms": [],
        "partial_comms": {"number_comm": 1, "packets": []},
    }

    count = 1

    for req_connection_key, req_connection_data in arp_requests.items():
        pair = {
        "number_comm": count,
        "req_ip": req_connection_key[1],
        "mac_found": [],
        "packets": []
        }
        if req_connection_key in arp_replies:
            rep_packets = arp_replies[req_connection_key]
            last_req_packet = req_connection_data["packets"][-1]
            first_rep_packet = rep_packets["packets"][0]
            pair["mac_found"] = first_rep_packet["src_mac"]
            pair["packets"].append(last_req_packet)
            pair["packets"].append(first_rep_packet)
            all_connections["complete_comms"].append(pair)
            count += 1


        else:
            all_connections["partial_comms"]["packets"].extend(req_connection_data["packets"]) 

    for rep_connection_key, rep_connection_data in arp_replies.items():
        if rep_connection_key not in arp_requests:
            all_connections["partial_comms"]["packets"].extend(rep_connection_data["packets"])

    
    if all_connections["partial_comms"]["packets"] == []:
        all_connections.pop("partial_comms", None)
    if all_connections["complete_comms"] == []:
        all_connections.pop("complete_comms", None)

    if "partial_comms" in all_connections:
        all_connections["partial_comms"]["packets"].sort(key=get_frame_number)


    

    with open("output.yaml", "w") as output:
        yaml = ruamel.yaml.YAML()
        yaml.default_style = None
        yaml.dump(all_connections,output)
    print(f"Output file {OUTPUT_FILE} created.")

def tcp(pcap_file, protocols,arg):
    pcounter = 0
    tcp_connections = {}

    # Main for loop that iterates through all packets in pcap
    # Same as in default
    for packet in pcap_file:
        pcounter += 1
        packet_size = len(packet)
        medium_size = max(packet_size + 4, 64)
        hexa_frame = hex_dump(bytes(packet), packet_size)
        packet = remove_ISL(bytes(packet))

        # Mac address
        dst_b = packet[0:6]
        src_b = packet[6:12]
        # Frame type data
        frame_b = packet[12:14]
        header_b = packet[14:16]
        frame_type = check_frame(frame_b, header_b)

        # Yaml output
        packet_info = {
            "frame_number": pcounter,
            "len_frame_pcap": packet_size,
            "len_frame_medium": medium_size,
            "frame_type": check_frame(frame_b, header_b),
            "src_mac": mac(src_b),
            "dst_mac": mac(dst_b),
        }

        # Frame info
        frame_protocol(frame_type, packet_info, packet, protocols)
        #If frame type is ETHERNET II, we can continue with our TCP analysis
        if packet_info["frame_type"] == "ETHERNET II":
            ether_address(packet_info, packet, protocols)
        #If not we skip this packet
        else:
            packet_info = {}
            continue    
        #If ether_type is not IPv4 and there is no app_protocol we skip this packet
        if packet_info["ether_type"] != "IPv4" or "app_protocol" not in packet_info:
            continue
        
        packet_info["hexa_frame"] = PreservedScalarString(hexa_frame)
        
        #Makes dictionary of all TCP packets
        #If we find suitable transport protocol and app protocol we add it to our dictionary
        if packet_info["protocol"] == "TCP" and packet_info["app_protocol"] == arg:
            #We make connection key from src and dst ip and ports
            #We also make reverse connection key to also include replys
            nor_connection_key = (packet_info["src_ip"], packet_info["dst_ip"], packet_info["src_port"], packet_info["dst_port"])
            rev_connection_key = (packet_info["dst_ip"], packet_info["src_ip"], packet_info["dst_port"], packet_info["src_port"])

            #We decide which one should we use
            if rev_connection_key in tcp_connections:
                connection_key = rev_connection_key
            else:
                connection_key = nor_connection_key
            
            #If there is no connection key we make one
            if connection_key not in tcp_connections:
                tcp_connections[connection_key] = {"packets": []}
            #We add packet to our connection key
            tcp_connections[connection_key]["packets"].append({"packet_info": packet_info, "raw_packet": packet})
        #If not we skip this packet
        else:
            packet_info = {}
            continue
        
    #Make main dictionary for yaml output
    all_connections = {
        "name": "PKS2023/24",
        "pcap_name": INPUT_FILE,
        "filter_name": arg,
        "complete_comms": [],
        "partial_comms": [],
    }
    one_connection = []
    count = 1
    
    #Iterate through all connections that we found
    for connection_key, connection_data in tcp_connections.items():
        #Get all packets from one connection
        one_connection = connection_data.get("packets", [])
        #Get raw packets for testing
        raw_packets = [packet["raw_packet"] for packet in one_connection]
        #Make new dictionary for every connection
        new_packet_data = {
            "number_comm" : count,
            "src_comm": connection_key[0],
            "dst_comm": connection_key[1],
            "packets": []
            }
        #If we find 3-way or 4-way opening handshake we continue
        if three_way_handshake(raw_packets[:3]) or four_way_handshake(raw_packets[:4]):
            #Connection successfully established
            count += 1
            #If we find good connection termination we add it to our main dictionary
            if connection_termination_fin_rst(raw_packets[-2:]) or connection_termination(raw_packets[-4:]) or connection_termination_ex(raw_packets[-5:]):
                #Connection successfully terminated
                #We remove raw packets from our dictionary
                for packet in one_connection:
                    packet.pop("raw_packet", None)
                
                #We add our connection to our main dictionary
                new_packet_data["packets"] = []
                for packet in one_connection:
                        new_packet_data["packets"].append(packet["packet_info"])
                all_connections["complete_comms"].append(new_packet_data)
            #If we dont find good connection termination we add it to our partial connections if its empty
            elif all_connections["partial_comms"] == []:
                for packet in one_connection:
                    packet.pop("raw_packet", None)
                    
                new_packet_data["packets"] = []
                for packet in one_connection:
                    new_packet_data["packets"].append(packet["packet_info"])
                new_packet_data["number_comm"] = 1
                all_connections["partial_comms"].append(new_packet_data)
                count -= 1
            else:
                count -= 1
        #If we dont find 3-way or 4-way opening handshake we are looking for good connection termination
        elif connection_termination_fin_rst(raw_packets[-2:]) or connection_termination_rst(raw_packets[-1:]) or connection_termination(raw_packets[-4:]):
            #If its good we add it to our partial connections if its empty
            if all_connections["partial_comms"] == []:
                for packet in one_connection:
                    packet.pop("raw_packet", None)
                    
                new_packet_data["packets"] = one_connection
                new_packet_data["number_comm"] = 1
                all_connections["partial_comms"].append(new_packet_data)
            #If its not we skip this connection
            continue
    #If there are no partial connections or complete connections we remove them from our main dictionary 
    if all_connections["partial_comms"] == []:
        all_connections.pop("partial_comms", None)
    if all_connections["complete_comms"] == []:
        all_connections.pop("complete_comms", None)
    
    if "partial_comms" in all_connections:
        for connection in all_connections["partial_comms"]:
            connection.pop("src_comm", None)
            connection.pop("dst_comm", None)

    
    #Yaml output
    with open("output.yaml", "w") as output:
        yaml = ruamel.yaml.YAML()
        yaml.dump(all_connections,output)
    print(f"Output file {OUTPUT_FILE} created.")
    
def udp(pcap_file, protocols,arg):
    pcounter = 0
    udp_connections = {}
    new_port = 0

    # Main for loop that iterates through all packets in pcap
    # Same as in default
    for packet in pcap_file:
        pcounter += 1
        packet_size = len(packet)
        medium_size = max(packet_size + 4, 64)
        hexa_frame = hex_dump(bytes(packet), packet_size)
        packet = remove_ISL(bytes(packet))

        # Mac address
        dst_b = packet[0:6]
        src_b = packet[6:12]
        # Frame type data
        frame_b = packet[12:14]
        header_b = packet[14:16]
        frame_type = check_frame(frame_b, header_b)

        # Yaml output
        packet_info = {
            "frame_number": pcounter,
            "len_frame_pcap": packet_size,
            "len_frame_medium": medium_size,
            "frame_type": check_frame(frame_b, header_b),
            "src_mac": mac(src_b),
            "dst_mac": mac(dst_b),
        }

        # Frame info
        frame_protocol(frame_type, packet_info, packet, protocols)
        #If frame type is ETHERNET II, we can continue with our TCP analysis
        if packet_info["frame_type"] == "ETHERNET II":
            ether_address(packet_info, packet, protocols)
        #If not we skip this packet
        else:
            packet_info = {}
            continue    
        #If ether_type is not IPv4 and there is no app_protocol we skip this packet
        if packet_info["ether_type"] != "IPv4" or "app_protocol" not in packet_info:
            continue
        
        packet_info["hexa_frame"] = PreservedScalarString(hexa_frame)
        
        #Makes dictionary of all TCP packets
        #If we find suitable transport protocol and app protocol we add it to our dictionary

        if packet_info["protocol"] == "UDP" and packet_info["app_protocol"] == arg or packet_info["src_port"] == new_port or packet_info["dst_port"] == new_port:
            src_port = packet_info["src_port"] 
            src_ip = packet_info["src_ip"]
            dst_ip = packet_info["dst_ip"]
            if new_port == 0:
                for pack in pcap_file:
                    pack = remove_ISL(bytes(pack))
                    new_info = {"ether_type" : "IPv4"}
                    ether_address(new_info, pack, protocols)
                    if new_info["src_ip"] == dst_ip and new_info["dst_ip"] == src_ip and new_info["dst_port"] == src_port:
                        new_port = new_info["src_port"]
                        print(new_port)
                        break
            if new_port == 0:
                continue
                
            nor_connection_key = (packet_info["src_ip"], packet_info["dst_ip"], packet_info["src_port"], new_port)
            rev_connection_key = (packet_info["dst_ip"], packet_info["src_ip"], new_port, packet_info["src_port"])

            if rev_connection_key in udp_connections:
                connection_key = rev_connection_key
            else:
                connection_key = nor_connection_key
            
            #If there is no connection key we make one
            if connection_key not in udp_connections:
                udp_connections[connection_key] = {"packets": []}
            
            udp_connections[connection_key]["packets"].append({"packet_info": packet_info, "raw_packet": packet})
           

def icmp(packet):
    ...

def default(pcap_file, protocols):
    pcounter = 0 #Keeps track of frame number
    packet_data = [] #List of all packets
    ip_trafic = {} #Ip_adress trafic

    # Main for loop that iterates through all packets in pcap
    for packet in pcap_file:
        pcounter += 1
        sap = pid = 0  # Error checking
        packet_size = len(packet) #Getting packet size
        medium_size = max(packet_size + 4, 64)
        hexa_frame = hex_dump(bytes(packet), packet_size) #Making packet hexa_frame
        packet = remove_ISL(bytes(packet)) #Removing ISL if there is one present

        #Getting all neccessary bytes from packet
        # Mac address
        dst_b = packet[0:6]
        src_b = packet[6:12]
        # Frame type data
        frame_b = packet[12:14]
        header_b = packet[14:16]
        frame_type = check_frame(frame_b, header_b) #Checking frame type

        # Yaml output
        # Adding obtained info to packet_info dictionary
        packet_info = {
            "frame_number": pcounter,
            "len_frame_pcap": packet_size,
            "len_frame_medium": medium_size,
            "frame_type": check_frame(frame_b, header_b),
            "src_mac": mac(src_b),
            "dst_mac": mac(dst_b),
        }

        # Frame info
        frame_protocol(frame_type, packet_info, packet, protocols) #Getting frame protocol info
        #If frame type is ETHERNET II, get ether protocol info
        if packet_info["frame_type"] == "ETHERNET II":
            ether_address(packet_info, packet, protocols, ip_trafic)

        packet_info["hexa_frame"] = PreservedScalarString(hexa_frame)
        packet_data.append(packet_info)

        # Console output
        # print_info(packet_info)
        
    #Getting information about ip_trafic
    ip_info = []
    max_trafic = []
    #Getting info about each one of ip addresses
    for each in ip_trafic:
        ip_node = {"node": each, "number_of_sent_packets": ip_trafic[each]}
        ip_info.append(ip_node)
    #Finding the max value
    max_trafic_number = max(ip_trafic.values())
    for ip in ip_trafic:
        #If there is multiple a write them all
        if ip_trafic[ip] == max_trafic_number:
            max_trafic.append(ip)
    
    print("Number of packets:", pcounter)

    # Writing all info into output.yaml file
    with open(OUTPUT_FILE, "w") as output:
        yaml = ruamel.yaml.YAML()
        yaml.dump(
            {
                "name": "PKS2023/24",
                "pcap_name": INPUT_FILE,
                "packets": packet_data,
                "ipv4_senders": ip_info,
                "max_send_packets_by": max_trafic,
            },
            output,
        )
    print(f"Output file {OUTPUT_FILE} created.")

# Main part of the code
def main():
    # Opening necessary files
    try:
        pcap_file = rdpcap(INPUT_FILE)
    except FileNotFoundError:
        print("Input file not found.")
        sys.exit(1)

    try:
        temp = open(PROTOCOL_CODES, "r")
        protocols = ruamel.yaml.YAML(typ="safe").load(temp)
    except FileNotFoundError:
        print("Protocols yaml not found.")
        sys.exit(1)

    arg = get_args(protocols)
    if arg: print("Protocol:",arg)
    
    # Main switch
    #Choosing which function to call depending on argument
    if arg == '':
        default(pcap_file, protocols)
    elif arg == 'HTTPS' or arg == 'HTTP' or arg == 'FTP-DATA' or arg == 'FTP-CONTROL' or arg == 'SSH' or arg == 'TELNET':
        tcp(pcap_file, protocols,arg)
    elif arg == 'ARP':
        arp(pcap_file, protocols,arg)
    else:
        print("Protocol not done.")
        return
    
    temp.close()

# Start of code
if __name__ == "__main__":
    main()
