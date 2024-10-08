class Header:
    def __init__(self) -> None:
        self.seq_num = 0 # 16 bits
        self.flags = 0  # 2 bits
        self.type = 0 # 3 bits
        self.f_size = 0 # 11 bits
        self.payload_len = 0 # 16 bits
        self.checksum = 0 # 16 bits
        self.payload = None # Payload data of payload_len bytes
        
    def make_bytes(self):
        data = b'' # empty byte string
        
        data += self.seq_num.to_bytes(2, byteorder='big')
        ftp_bytes = self.flags<< 14 | self.type << 11 | self.f_size
        data += (ftp_bytes).to_bytes(2, byteorder='big')
        data += self.payload_len.to_bytes(2, byteorder='big')
        data += self.checksum.to_bytes(2, byteorder='big')
        if self.payload != None:
            data += self.payload
        
        return data