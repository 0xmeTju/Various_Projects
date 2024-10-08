import socket
import sys
import threading
import os
from shared import *
from header import Header
from time import sleep

CLIENT_IP = "127.0.0.1" # client host ip A.B.C.D
CLIENT_PORT = 50602 # client port for recieving communication
SERVER_IP = "127.0.0.1" # Server host ip (public IP) A.B.C.D
SERVER_PORT = 42069
WINDOW_SIZE = 4
#Ethernet 2 1500B payload. 1500-20(IP)-8(UDP)-8(Protocol) = 1464
MAX_FRAGMENT_SIZE = 1464 # Max fragment size for that can fit in Ethernet II frame
CLIENT_SPEED = 0 # seconds between sending packets
ARQ_TIMEOUT = 3 # seconds between resending packets
TIMEOUT_TIME = 5 # seconds between sending keep alive packets
KEEP_ALIVE_RETRIES = 4 # number of times to retry sending keep alive packets

#Changes:
# Type: 1 = FILE, 2 = FILE NAME, 3 = MESSAGE, 4 = KEEP ALIVE, 5 = SWITCH, 6 = SYNCHRONIZE, 7 = PATH_CHANGE, 0 = CONTROL
# Flag: 1 = ACK, 2 = NACK, 3 = FIN

class Client:

    def __init__(self, ip, port, server_ip, server_port):
        self.sock = socket.socket(socket.AF_INET,
                    socket.SOCK_DGRAM) # UDP socket creation
        self.server = None
        self.server_ip = server_ip
        self.server_port = server_port
        self.state = "CONNECTING"

    def receive(self):
        data = None
        while data is None:
            self.sock.settimeout(TIMEOUT_TIME)
            try:
                data, self.client = self.sock.recvfrom(1024)
            except socket.timeout:
                break
            except ConnectionResetError:
                continue
                
        return data

            
    
    def keep_alive(self):
        #Working on thread
        retries = 0
        seq_num = 0
        
        while retries < KEEP_ALIVE_RETRIES and self.state != "END":

            if self.state == "FILE" or self.state == "MESSAGE" or self.state == "CONNECTING":
                sleep(0.5)
                continue

            packet_b = assemble_packet(seq_num, b"", 4)
        
            self.sock.sendto(packet_b, (self.server_ip, self.server_port))
            #print("Sent keep alive packet")
            
            # We set a timeout of 5 seconds to get a response from the server
            # If we don't get a response, we retry 3 times
            data = None
            try:
                #We are expecting a keep alive response from the server
                data = self.receive()
                if data is None:
                    raise socket.timeout

                if get_flag(data) == 1 and get_type(data) == 4 and get_seq_num(data) == seq_num:
                    # Second byte of header is flag, third is type
                    # 0b0001 is ACK flag and 0b1000 is keep alive type
                    #print(f"Received keep alive response for seq_num {seq_num}")
                    if retries > 0:
                        print("Connection re-established!\n")
                        menu()
                    retries = 0
                    seq_num += 1
                
            except socket.timeout:
                retries += 1
                print("\nNo response from server, retrying...")
                print("Retry num: ", retries)
                continue
                
            sleep(5)
        # If we don't get a response from the server, we quit
        # We do all necessary cleanup in the quit function
        #print("Change state to END")
        self.state = "END"
        if retries >= KEEP_ALIVE_RETRIES:
            print("Server timed out..")
            print("Enter 0 to quit\n>")


    def send_with_gbn(self, f_data, fragment_size, data_type,error=False):
        num_of_packets = len(f_data) // fragment_size
        buffer = []
        
        seq_base = 0
        seq_next = 0
        retries = 0
        
        #Go Back N
        while seq_base <= num_of_packets or len(buffer) != 0:
            
            if retries >= 5:
                print("Server timed out..")
                self.state = "END"
                self.quit()
                break
            
            while seq_next < (seq_base + WINDOW_SIZE) and seq_next <= num_of_packets and len(buffer) < WINDOW_SIZE:
                data = f_data[seq_next*fragment_size:(seq_next+1)*fragment_size]

                if data_type == "FILE":
                    packet_b = assemble_packet(seq_next, data, 1)
                elif data_type == "MESSAGE":
                    packet_b = assemble_packet(seq_next, data, 3, 0, fragment_size)
                elif data_type == "FILE_NAME":
                    packet_b = assemble_packet(seq_next, data, 2, 0, fragment_size)
                
                buffer.append(packet_b)
                
                if error:
                    packet_b = make_error(packet_b)
                    
                self.sock.sendto(packet_b, (SERVER_IP, SERVER_PORT))
                print(f"Sent packet fragment with seq_num: {seq_next}")
                print(f"Packet fragment size: {get_payload_len(packet_b)} bytes")
                #Adding packet to buffer
                sleep(CLIENT_SPEED)
                
                seq_next += 1
        
            #When we send whole window, we wait for ACK
            #If we get ACK, we remove packet from buffer
            #If we don't get ACK, we resend whole window
            try:
                ack_packet = self.receive()
                if ack_packet is None:
                    raise socket.timeout
                elif get_flag(ack_packet) == 1 and get_type(ack_packet) == 0:
                    ack_seq_num = get_seq_num(ack_packet)
                    print(f"\nReceived ACK for packet {ack_seq_num}\n")
                    #Removing all packets from buffer that have seq_num <= ack_seq_num
                    buffer = [packet for packet in buffer if get_seq_num(packet) > ack_seq_num]
                    seq_base = ack_seq_num + 1
                    retries = 0
                elif get_flag(ack_packet) == 2 and get_type(ack_packet) == 0:
                    print("\nReceived NACK for packet ", get_seq_num(ack_packet))
                    print("Resending requested window...")
                    self.resend_window(buffer)
                    
            except socket.timeout:
                print("No response from server, resending window...")
                self.resend_window(buffer)
                retries += 1
                
        if data_type == "FILE_NAME":
            print("File name sent successfully")
        elif data_type == "FILE":
            print("Data sent successfully")
            print(f"Total number of fragments sent: {num_of_packets + 1}")
        elif data_type == "MESSAGE":
            print("Message sent successfully")
        

    def quit(self):
        self.sock.close() # correctly closing socket
        print("Client closed..")
        sys.exit()

    def switch(self):
        packet_b = assemble_packet(0, b"", 5, 0)
        self.sock.sendto(packet_b, (SERVER_IP, SERVER_PORT))
        
        response = self.receive()
        if response is None:
            print("No response from server")
            return False
        elif get_flag(response) == 0 and get_type(response) == 5:
            print("Server accepted switch")
            self.state = "END"
            return True
        

    def start(self):
        
        if self.handshake():
            print(f"Client connected to server on IP: {SERVER_IP} and port: {SERVER_PORT}..\n")
            self.state = "IDLE"
        else:
            self.state = "END"
            self.quit()
            
        menu()
        mode = get_input()
        while mode != 0 and self.state != "END":
            if mode == 1:
                print("Enter message: ")
                message = input(">")
                print(f"Enter fragment size (max {MAX_FRAGMENT_SIZE}): ")
                fragment_size = get_input()
                if fragment_size > MAX_FRAGMENT_SIZE:
                    print("Fragment size too big. Using max fragment size.")
                    fragment_size = MAX_FRAGMENT_SIZE
                seq_num = 0
                print("Fragment size: ", fragment_size)
                
                message_b = message.encode("UTF-8")
                self.state = "MESSAGE"
                self.send_with_gbn(message_b, fragment_size, "MESSAGE")
                self.state = "IDLE"
                
                print("Sent message:")
                print(message + "\n")
            elif mode == 2:
                
                name_sent = False
                print("Enter file name or path: ")
                name = input(">")
                
                print(f"Enter fragment size (max {MAX_FRAGMENT_SIZE}): ")
                fragment_size = get_input()
                if fragment_size > MAX_FRAGMENT_SIZE:
                    print("Fragment size too big. Using max fragment size.")
                    fragment_size = MAX_FRAGMENT_SIZE
                seq_num = 0
                print("Fragment size: ", fragment_size)
                
                try:
                    with open(name, "rb") as file:
                        f_data = file.read()
                        f_path = os.path.abspath(name)
                except:
                    print("File not found")
                    self.state = "END"
                    sys.exit()
                
                self.state = "FILE"
                
                if not name_sent:
                    name_sent = True
                    
                    name = os.path.basename(name)
                    payload = name.encode("UTF-8")
                    print("\nSending file name...")
                    self.send_with_gbn(payload, fragment_size, "FILE_NAME")
                    print(f"Sent file name {name}\n")

                print("\nSending file data...")
                self.send_with_gbn(f_data, fragment_size, "FILE")

                print(f"\nSent file {name} with path {f_path}")
                print(f"File size: {len(f_data)} bytes\n")
                
                self.state = "IDLE"
                
            elif mode == 3:
                print("This mode will send a message and a file with an error in the communication")
                print("There is random chance that the packet will have a checksum error or a payload error")
                
                message = "This is a test message"
                print(f"\nMessage being sent: \"{message}\"")
                print(f"Enter fragment size (max {MAX_FRAGMENT_SIZE}): ")
                fragment_size = get_input()
                if fragment_size > MAX_FRAGMENT_SIZE:
                    print("Fragment size too big. Using max fragment size.")
                    fragment_size = MAX_FRAGMENT_SIZE
                seq_num = 0
                print("Fragment size: ", fragment_size)
                
                message_b = message.encode("UTF-8")
                self.state = "MESSAGE"
                self.send_with_gbn(message_b, fragment_size, "MESSAGE", True)
                self.state = "IDLE"
                
                print("Sent message with error:")
                print(message)
                
                #File Part
                name_sent = False
                print("\nEnter file name: ")
                name = input(">")
                
                print(f"Enter fragment size (max {MAX_FRAGMENT_SIZE}): ")
                fragment_size = get_input()
                if fragment_size > MAX_FRAGMENT_SIZE:
                    print("Fragment size too big. Using max fragment size.")
                    fragment_size = MAX_FRAGMENT_SIZE
                seq_num = 0
                print("Fragment size: ", fragment_size)
                
                try:
                    with open(name, "rb") as file:
                        f_data = file.read()
                        f_path = os.path.abspath(name)
                except:
                    print("File not found")
                    self.state = "END"
                    sys.exit()
                
                self.state = "FILE"
                
                if not name_sent:
                    name_sent = True
                    
                    name = os.path.basename(name)
                    payload = name.encode("UTF-8")
                    self.send_with_gbn(payload, fragment_size, "FILE_NAME", True)
                    print(f"Sent file name {name}\n")

                self.send_with_gbn(f_data, fragment_size, "FILE",True)

                print(f"\nSent file {name} with path {f_path}")
                print(f"File size: {len(f_data)} bytes\n")
                self.state = "IDLE"
            
            elif mode == 4:
                print("Switching roles...")
                answer = self.switch()
                if answer:
                    try:
                        KA_thread.join()
                    except:
                        pass
                        self.sock.close()
                        print("Client closed..")
                    return 1
                else:
                    print("Switch failed")
                    continue
                
            elif mode == 5:
                print("Enter new server save path: ")
                path = input(">")
                packet_b = assemble_packet(0, path.encode("UTF-8"), 7, 0)
                self.sock.sendto(packet_b, (SERVER_IP, SERVER_PORT))
                print("Sent a path change request to server")
                answer = self.receive()
                if answer is None:
                    print("No response from server")
                elif get_flag(answer) == 1 and get_type(answer) == 7:
                    print("Server accepted new save path")
                    
                   
            
            elif mode == 6:
                packet_b = assemble_packet(0, b"", 0, 3)
                self.sock.sendto(packet_b, (SERVER_IP, SERVER_PORT))
                print("Sent end connection packet")
                print("Closing connection...")
                self.state = "END"
                self.quit()
                break
            else:
                print("Invalid mode")
            
            menu()
            mode = get_input()
        self.state = "END"
        self.quit()
    
    def resend_window(self, buffer):
        for packet in buffer:
            self.sock.sendto(packet, (SERVER_IP, SERVER_PORT))
            print(f"Resent file data with sequence number {get_seq_num(packet)}\n")
            sleep(CLIENT_SPEED)
    
    def handshake(self):
        seq_num = 0
        packet_b = assemble_packet(seq_num, b"", 6, 0)
        self.sock.sendto(packet_b, (SERVER_IP, SERVER_PORT))
        print("Sent connection request to server")
        
        for i in range(3):
            answer = self.receive()
            if answer is None:
                print("No response from server")
                print("Retrying...")
            else:
                break
        
        if answer is None:
            return False
        
        if get_flag(answer) == 1 and get_type(answer) == 6 and get_seq_num(answer) == seq_num + 1:
            print("Received ACK for connection request")
            return True
        else:
            print("Received invalid packet")
            return False


def menu():
    print("Select mode of operation: ")
    print("(1)Send message")
    print("(2)Send file")
    print("(3)Simulate error in communication")
    print("(4)Switch roles")
    print("(5)Change server save path")
    print("(6)Close connection and server")
    print("(0)Quit client")

def run_client(c_server_ip, c_server_port):
    global SERVER_IP, SERVER_PORT
    SERVER_IP = c_server_ip
    SERVER_PORT = c_server_port
    
    client = Client(CLIENT_IP, CLIENT_PORT, SERVER_IP,
            SERVER_PORT)
    
    KA_thread = threading.Thread(target=client.keep_alive)
    KA_thread.start()
    return client.start()

if __name__=="__main__":
    print("Enter server IP: ")
    #SERVER_IP = input(">")
    print("Enter server port: ")
    #SERVER_PORT = int(input(">"))
    
    client = Client(CLIENT_IP, CLIENT_PORT, SERVER_IP,
            SERVER_PORT)
    
    KA_thread = threading.Thread(target=client.keep_alive)
    KA_thread.start()
    client.start()