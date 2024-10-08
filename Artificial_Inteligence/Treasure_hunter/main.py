import json
from tester import Tester

def main():
    #Opening config file
    try:
        with open("config.json", "r") as file:
            config = json.load(file)
    except:
        print("Error: config.json not found")
        exit(1)
    
    #Initializing and starting tester
    tester = Tester(config)
    tester.start(config)
    
if __name__ == '__main__':
    main()