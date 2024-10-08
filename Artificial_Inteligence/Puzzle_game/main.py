import time
import argparse
import sys
from time import sleep
from collections import deque
from matrix import *
from operators import *
from shared import *

#Argument parser
parser = argparse.ArgumentParser(description='File parser')
parser.add_argument('state_path', type=str, nargs='?', default='./states/state.txt', help='path to state file')
STATE_FILE = parser.parse_args().state_path

#Explained in documentation
class Node:
    def __init__(self, state, parent, operator, depth):
        self.state = state
        self.parent = parent
        self.operator = operator
        self.depth = depth


def generate_children(parent, explored):
    state = parent.state
    children = []

    for car in state:
        if car.orientation == "H":
            for amount in range(1, 5):
                new_state = vlavo(state, car.color, amount)
                hash = hash_state(new_state)
                if new_state != state and hash not in explored:
                    children.append(
                        Node(new_state, parent, f"{car.color}->Vlavo", parent.depth + 1)
                    )
                    explored.add(hash)
                    continue

                new_state = vpravo(state, car.color, amount)
                hash = hash_state(new_state)
                if new_state != state and hash not in explored:
                    children.append(
                        Node(
                            new_state, parent, f"{car.color}->Vpravo", parent.depth + 1
                        )
                    )
                    explored.add(hash)
                    continue

                break
        elif car.orientation == "V":
            for amount in range(1, 5):
                new_state = dole(state, car.color, amount)
                hash = hash_state(new_state)
                if new_state != state and hash not in explored:
                    children.append(
                        Node(new_state, parent, f"{car.color}->Dole", parent.depth + 1)
                    )
                    explored.add(hash)
                    continue

                new_state = hore(state, car.color, amount)
                hash = hash_state(new_state)
                if new_state != state and hash not in explored:
                    children.append(
                        Node(new_state, parent, f"{car.color}->Hore", parent.depth + 1)
                    )
                    explored.add(hash)
                    continue

                break
    return children


def bfs_algorithm(root):
    explored = set()
    queue = deque()
    queue.append(root)
    count = 0

    while queue:
        node = queue.popleft()

        condition, depth = check_for_win(node)
        if condition:
            print("\nSolution found")
            print("Nodes count:", count)
            return count, depth
        
        comp = tuple(node.state)
        if comp not in explored:
            explored.add(comp)
            count += 1

            queue.extend(generate_children(node, explored))

    print("No solution found")
    return 0, 0


def dfs_algorithm(root):
    explored = set()
    stack = deque()
    stack.append(root)
    count = 0

    while stack:
        node = stack.pop()

        condition, depth = check_for_win(node)
        if condition:
            print("\nSolution found!")
            print("Nodes count:", count)
            return count, depth

        comp = tuple(node.state)
        if comp not in explored:
            explored.add(comp)
            count += 1

            children = generate_children(node, explored)
            stack.extend(children)

    print("No solution found")
    return 0, 0

#Reads state from file and creates car objects
def read_car_data(filename):
    #Empty list for cars
    cars = []
    try:
        with open(filename, "r") as file:
            for line in file:
                parts = line.strip().split()
                #Checks if the line is valid
                if len(parts) == 6:
                    #Creates car object from line
                    color, size, x, y, orientation, coment = parts
                    car = Car(color, int(size), int(x), int(y), orientation)
                    cars.append(car)
                else:
                    #If the line is not valid, exit the program
                    print(f"Invalid line: {line}")
                    sys.exit(1)
        return cars
    except FileNotFoundError:
        print(f"File {filename} not found")
        sys.exit(1)


def main():
    print("############## BLAZNIVA KRIZOVATKA ##############")
    print(
        "Choose algorithm:" "\n1 -> BFS" "\n2 -> DFS" "\n3 -> BFS vs DFS" "\n4 -> Exit"
    )

    option = int(input("Enter option: "))
    starting_state = read_car_data(STATE_FILE)
    bfs_time = 0
    bfs_count = 0
    bfs_depth = 0
    dfs_time = 0
    dfs_count = 0
    dfs_depth = 0
    
    #Main loop that acts as a menu
    while option != 4:
        #BFS
        if option == 1:
            print("-----------BFS-----------")
            print("Starting state:")
            print(print_matrix(starting_state))
            sleep(1)
            root = Node(starting_state, None, None, 0)
            print("Starting...")
            start_time = time.time()
            bfs_depth ,bfs_count = bfs_algorithm(root)
            end_time = time.time()
            bfs_time = round(end_time - start_time, 5)
            print("-----------------------------")
            print("Steps taken:", bfs_count)
            print("Time taken:", bfs_time, "seconds")

        #DFS
        elif option == 2:
            print("-----------DFS-----------")
            print("Starting state:")
            print(print_matrix(starting_state))
            sleep(1)
            root = Node(starting_state, None, None, 0)
            print("Starting...")
            start_time = time.time()
            dfs_depth,dfs_count = dfs_algorithm(root)
            end_time = time.time()
            dfs_time = round(end_time - start_time, 5)
            print("-----------------------------")
            print("Steps taken:", dfs_count)
            print("Time taken:", dfs_time, "seconds")
        #BFS vs DFS comparison
        elif option == 3:
            print("-----------BFS vs DFS-----------")
            print("Starting state:")
            print(print_matrix(starting_state))
            sleep(1)
            root = Node(starting_state, None, None, 0)
            print("Starting...")
            start_time = time.time()
            bfs_count,bfs_depth  = bfs_algorithm(root)
            end_time = time.time()
            bfs_time = round(end_time - start_time, 5)
            start_time = time.time()
            dfs_count, dfs_depth = dfs_algorithm(root)
            end_time = time.time()
            dfs_time = round(end_time - start_time, 5)
            print("-----------------------------")
            if bfs_time < dfs_time:
                print("BFS is faster")
            elif bfs_time > dfs_time:
                print("DFS is faster")

            print(f"BFS time: {bfs_time} seconds | DFS time: {dfs_time} seconds")
            print("Time difference:", round(abs(bfs_time - dfs_time), 5), "seconds")
            print(f"BFS created nodes: {bfs_count} | DFS created nodes: {dfs_count}")
            print("Created nodes difference:", abs(bfs_count - dfs_count))
            print(f"BFS steps: {bfs_depth} | DFS steps: {dfs_depth}")
            print("Steps difference:", abs(bfs_depth - dfs_depth))
            print("-----------------------------")
        #Wrong option
        else:
            print("Wrong option")
            option = int(input("Enter option: "))
            continue

        option = int(input("Enter option(4 -> exit): "))

    print("Exiting...")
    sleep(0.5)

#Main function call
if __name__ == "__main__":
    main()
