import server
import client
from shared import get_input

MY_IP_ADDRESS = "" #Enter your IP adress here or you will be prompted in program

if __name__ == "__main__":
    server_port = 0
    server_ip = ""
    if MY_IP_ADDRESS == "":
        print("Please enter your IP adress")
        MY_IP_ADDRESS = input(">")

    print("Pick a mode: (1) Server (2) Client")
    mode = get_input()
    while True:
        if mode == 1:
            if server_port == 0:
                print("Enter server port: ")
                server_port = int(input(">"))
            mode, server_ip = server.run_server(MY_IP_ADDRESS,server_port)
            print("\nSwitching to client mode")
            continue
        elif mode == 2:
            if server_ip == "":
                print("Enter server IP: ")
                server_ip = input(">")
            if server_port == 0:
                print("Enter server port: ")
                server_port = int(input(">"))
            mode = client.run_client(server_ip, server_port)
            print("\nSwitching to server mode")
            continue
        else:
            print("Invalid input")