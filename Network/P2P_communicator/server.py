import socket
import sys
import os
from time import sleep
from shared import *

SERVER_IP = "127.0.0.1" # Server host ip (public IP) A.B.C.D., default is localhost
SERVER_PORT = 42069 # Server port for recieving communication
SOCKET_BUFFER_SIZE = 1518 # Max fragment size for Ethernet
SOCKET_TIMEOUT = 30 # 30 seconds waiting for response
FRAGMENT_SIZE = 0 
WINDOW_SIZE = 0
PATH = ""
MESSAGE_DATA = ""
FILE_NAME = ""
FILE_DATA = b""

class Server:

    def __init__(self, ip, port):
        self.sock = socket.socket(socket.AF_INET,socket.SOCK_DGRAM) # UDP socket creation
        self.sock.bind((ip, port))  #needs to be tuple (string,int)
        self.client = None
        self.state = "START"
        self.buffer = []
        

    def receive(self):
        data = None
        while data == None and self.state != "END":
            self.sock.settimeout(SOCKET_TIMEOUT)
            try:
                data, self.client= self.sock.recvfrom(SOCKET_BUFFER_SIZE) # buffer size is 1024 bytes
            except socket.timeout:
                print("No response from client")
                print("Server closing...")
                sys.exit()
                
        #if hide_KA(data):        
            #print("Received bytes: ", raw_bytes(data))
        return data

    def send_response(self,data):
        self.sock.sendto(data,self.client)

        
    def quit(self):
        self.sock.close() # correctly closing socket
        print("Server closed..")
        sys.exit()
    
    def start(self):
        global FILE_DATA, FILE_NAME, FRAGMENT_SIZE, MESSAGE_DATA
        
        print(f"Server started and listening on port {SERVER_PORT}")
        
        self.state = "IDLE"
        next_seq_num = 0
        #nack sent for specific frame
        nack_seq_num = -1
        while self.state != "END":
            
            print("\nListening...")
            packet = self.receive()
            
            checksum_bool = verify_checksum(packet)
            if not checksum_bool and next_seq_num != nack_seq_num:
                nack_seq_num = self.send_nack(packet, next_seq_num)
                continue
            
            payload_len = get_payload_len(packet)
            if hide_KA(packet):
                print(f"Packet payload length / data: {payload_len} bytes")
            packet = remove_padding(packet, payload_len)

            if self.state == "FILE":
                if get_type(packet) == 1:
                    print("Type: File fragment")
                    if get_seq_num(packet) == next_seq_num:
                        data = packet[8:]
                        FILE_DATA += data
                        self.send_ack(next_seq_num,packet)
                        next_seq_num += 1
                        print(f"Next expected seq_num: {next_seq_num}")
                        #sleep(0.5)
                    else:
                        print(f"Packet with seq_num: {get_seq_num(packet)} is not expected")
                        print(f"Expected seq_num: {next_seq_num} but got {get_seq_num(packet)}")
                        self.send_ack(next_seq_num - 1,packet)
                        continue
                    
                    if len(data) < FRAGMENT_SIZE:
                        print("\nFile data sucessfully received and saved")
                        print(f"Total number of packets received: {next_seq_num}")
                        save_file()
                        self.state = "IDLE"
                        next_seq_num = 0
                        
            elif self.state == "MESSAGE":
                if get_type(packet) == 3:
                    print("Type: Message fragment")
                    if get_seq_num(packet) == next_seq_num:
                        MESSAGE_DATA += get_message(packet)
                        self.send_ack(next_seq_num,packet)
                        next_seq_num += 1
                        
                        if len(packet[8:]) < FRAGMENT_SIZE:
                            print("\nMessage sucessfully received")
                            print(f"Message: {MESSAGE_DATA}")
                            self.state = "IDLE"
                            next_seq_num = 0
                    else:
                        print(f"Packet with seq_num: {get_seq_num(packet)} is not expected")
                        self.send_ack(next_seq_num - 1,packet)
                        continue
                        
            elif self.state == "FILE_NAME":
                if get_type(packet) == 2:
                    print("Type: File name fragment")
                    if get_seq_num(packet) == next_seq_num:
                        FILE_NAME += get_file_name(packet)
                        self.send_ack(next_seq_num,packet)
                        next_seq_num += 1
                        
                        if len(packet[8:]) < FRAGMENT_SIZE:
                            print("File name sucessfully received")
                            print(f"File name: {FILE_NAME}")
                            print(f"Fragment size: {FRAGMENT_SIZE}")
                            self.state = "FILE"
                            next_seq_num = 0
                    else:
                        print(f"Packet with seq_num: {get_seq_num(packet)} is not expected")
                        self.send_ack(next_seq_num - 1,packet)
                        continue
                        
            else:
                if get_type(packet) == 2:
                    print("Type: File name")
                    self.send_ack(next_seq_num,packet)
                    next_seq_num = get_seq_num(packet) + 1
                    print(f"Next expected seq_num: {next_seq_num}")
                    
                    FILE_NAME = get_file_name(packet)
                    FRAGMENT_SIZE = get_fragment_size(packet)
                    if get_payload_len(packet) < FRAGMENT_SIZE:
                        print("File name sucessfully received")
                        print(f"File name: {FILE_NAME}")
                        print(f"Fragment size: {FRAGMENT_SIZE}")
                        self.state = "FILE"
                        next_seq_num = 0
                    else:
                        self.state = "FILE_NAME"
                    
                elif get_type(packet) == 3:
                    print("Type: Message")
                    if get_seq_num(packet) == next_seq_num:
                        MESSAGE_DATA = get_message(packet)
                        FRAGMENT_SIZE = get_fragment_size(packet)
                        self.send_ack(next_seq_num, packet)
                        next_seq_num += 1
                        print(f"Next expected seq_num: {next_seq_num}")
                        #sleep(0.5)
                        
                        if len(packet[8:]) < FRAGMENT_SIZE:
                            print("\nMessage sucessfully received")
                            print(f"Message: {MESSAGE_DATA}")
                            self.state = "IDLE"
                            next_seq_num = 0
                        else:
                            self.state = "MESSAGE"
                    else:
                        print(f"Packet with seq_num: {get_seq_num(packet)} is not expected")
                        continue
                
                elif get_type(packet) == 5 and get_flag(packet) == 0:
                    print("Type: Roles switch")
                    assemble_packet(0, b"", 5, 0)
                    self.send_response(packet)
                    self.state = "END"
                    return 2
                
                elif get_type(packet) == 4:
                    if hide_KA(packet):
                        print("Type: Keep alive")
                    seq_num = get_seq_num(packet)
                    packet_b = assemble_packet(seq_num, b"", 4, 1)
                    self.send_response(packet_b)
                elif get_type(packet) == 0 and get_flag(packet) == 3:
                    print("End connection packet received")
                    self.state = "END"
                    self.quit()
                
                elif get_type(packet) == 6:
                    print("Recieved connection request")
                    seq_num = get_seq_num(packet)
                    packet_b = assemble_packet(seq_num + 1, b"", 6, 1)
                    self.send_response(packet_b)
                    print(f"\nClient connected with IP: {self.client[0]} and port: {self.client[1]}")
                    
                elif get_type(packet) == 7:
                    global PATH
                    print("Recieved path change request")
                    new_path = get_file_name(packet)
                    PATH = new_path
                    print(f"New path: {PATH}")
                    packet_b = assemble_packet(0, b"", 7, 1)
                    self.send_response(packet_b)
                    
                else:
                    print("Type: Unknown")
                    self.state = "IDLE"
            
        
        self.quit()
        
    def send_ack(self,seq_num,packet):
        if seq_num < 0:
            seq_num = 0
            
        packet_b = assemble_packet(seq_num, b"", 0, 1)
        self.sock.sendto(packet_b, self.client)
        print(f"Sent ACK for packet with seq_num: {get_seq_num(packet)}")

    def send_nack(self,packet,expected_seq_num):
        seq_num = expected_seq_num
        if seq_num < 0:
            seq_num = 0
        packet = assemble_packet(seq_num, b"", 0, 2)
        self.sock.sendto(packet, self.client)
        print(f"Sent NACK for packet with seq_num: {seq_num}")
        return seq_num

def get_file_name(data):
    name_bytes = data[8:]
    name = name_bytes.decode("utf-8")
    return name

def save_file():
    global FILE_DATA, FILE_NAME
    
    save_path = os.path.join(PATH, FILE_NAME)
    try:
        with open(save_path, "wb") as f:
            f.write(FILE_DATA)
            
        f_path = os.path.abspath(save_path)
        print(f"Saved file {FILE_NAME} with path {f_path}")
        print(f"File size: {len(FILE_DATA)} bytes\n")
        FILE_DATA = b""
        FILE_NAME = ""
    except:
        print("Error saving file")
        FILE_DATA = b""
        FILE_NAME = ""

def get_message(data):
    message_b = data[8:]
    message = message_b.decode("utf-8")
    return message

def get_fragment_size(data):
    fragment_b = data[2:4]
    fragment_size = int.from_bytes(fragment_b, byteorder='big')
    fragment_size = fragment_size & 2047
    return fragment_size

def run_server(server_ip,server_port):
    global SERVER_PORT, SERVER_IP, PATH
    SERVER_PORT = server_port
    SERVER_IP = server_ip
    server = Server(SERVER_IP, SERVER_PORT)
    
    print("Please enter path to save files or leave blank for default path: ")
    path_input = input(">")
    if path_input != "":
        PATH = path_input
    else:
        PATH = os.path.dirname(__file__)
        
    if server.state == "START":
        return server.start(), str(server.client[0])
    else:
        print("Server not started")
        sys.exit()
        
if __name__=="__main__":
    print("Enter server port: ")
    #SERVER_PORT = int(input(">"))
    server = Server(SERVER_IP, SERVER_PORT)
    if server.state == "START":
        server.start()
    else:
        print("Server not started")
        sys.exit()