import crcmod
from header import Header
from random import randint

PADDING_SIZE = 10
HIDE_KEEP_ALIVE = False

def raw_bytes(data):
    raw = ""
    for byte in data:
        raw += "\\x" + f"{byte:02x}"
    return raw


def get_checksum(data):
    checksum = int.from_bytes(data[6:8], byteorder="big")
    return checksum


def crc16_verify(data):
    crc16_func = crcmod.predefined.mkPredefinedCrcFun("crc-16")
    crc = crc16_func(data)
    return crc


def crc16_make(packet):
    crc16_func = crcmod.predefined.mkPredefinedCrcFun("crc-16")
    temp = packet.make_bytes()
    # Exclude checksum from calculation
    crc = crc16_func(temp[:6] + temp[8:])
    return crc

def hide_KA(packet):
    if get_type(packet) == 4 and HIDE_KEEP_ALIVE:
        return False
    else:
        return True

def verify_checksum(data):
    checksum = get_checksum(data)
    # Exclude checksum from calculation
    temp = data[:6] + data[8:]
    crc = crc16_verify(temp)
    if crc == checksum:
        if hide_KA(data):
            print("Checksum verified")
        return True
    else:
        if hide_KA(data):
            print("Checksum failed")
        return False


def get_seq_num(data):
    seq_num = int.from_bytes(data[0:2], byteorder="big")
    return seq_num


def assemble_packet(seq_num, payload, type, flags=0, f_size=0):
    packet = Header()
    packet.seq_num = seq_num
    packet.flags = flags
    packet.type = type
    packet.f_size = f_size
    packet.payload_len = len(payload)
    if packet.payload_len < PADDING_SIZE:
        payload = add_padding(payload)
    packet.payload = payload
    packet.checksum = crc16_make(packet)
    packet_b = packet.make_bytes()
    return packet_b

def assemble_packet_with_error(seq_num, payload, type, flags=0, f_size=0):
    chance = randint(0, 100)
    
    packet = Header()
    packet.seq_num = seq_num
    packet.flags = flags
    packet.type = type
    packet.f_size = f_size
    packet.payload_len = len(payload)
    if packet.payload_len < PADDING_SIZE:
        payload = add_padding(payload)
    packet.payload = payload
    packet.checksum = crc16_make(packet)
    if chance < 10:
        packet.checksum = randint(0, 65535)
        print("Made packet with checksum error")
    packet_b = packet.make_bytes()
    if chance < 20 and chance > 10:
        random_part = randint(0, 65535).to_bytes(2, byteorder="big")
        mod_payload = packet_b[:10] + random_part + packet_b[12:]
        packet_b = mod_payload
        print("Made packet with payload error")
    return packet_b

def make_error(packet):
    seq_num = get_seq_num(packet)
    chance = randint(0, 100)
    packet_b = packet
    if seq_num == 0 or seq_num == 1:
        return packet_b
    if seq_num == 2:
        random_checksum = randint(0, 65535).to_bytes(2, byteorder="big")
        packet_b = packet[:6] + random_checksum + packet[8:]
        print("Made packet with checksum error")
    elif seq_num == 3:
        random_part = randint(0, 65535).to_bytes(2, byteorder="big")
        packet_b = packet_b[:10] + random_part + packet_b[12:]
        print("Made packet with payload error")
    elif chance < 5:
        random_checksum = randint(0, 65535).to_bytes(2, byteorder="big")
        packet_b = packet[:6] + random_checksum + packet[8:]
        print("Made packet with checksum error")
    elif chance < 10 and chance > 5:
        random_part = randint(0, 65535).to_bytes(2, byteorder="big")
        packet_b = packet_b[:10] + random_part + packet_b[12:]
        print("Made packet with payload error")
    return packet_b

def add_padding(data):
    data += b"\x00" * (PADDING_SIZE - len(data))
    return data

def get_input():
    try:
        output = int(input(">"))
    except ValueError:
        print("Invalid input")
        return 0
    return output


def remove_padding(data, payload_len):
    data = data[: 8 + payload_len]
    if payload_len < PADDING_SIZE:
        if hide_KA(data):
            print("Padding length:", PADDING_SIZE - payload_len)
    return data


def get_flag(data):
    flag = int.from_bytes(data[2:3], byteorder="big")
    flag = (flag & 0b11000000) >> 6
    return flag


def get_payload_len(data):
    payload_len = int.from_bytes(data[4:6], byteorder="big")
    return payload_len


def get_type(data):
    packet_type = int.from_bytes(data[2:3], byteorder="big")
    packet_type = (packet_type & 0b00111000) >> 3
    return packet_type
