from matrix import Car, print_matrix

#Makes a deepcopy of state and returns it
def copy_state(state):
    new_state = []
    for car in state:
        new_car = Car(car.color, car.size, car.x, car.y, car.orientation)
        new_state.append(new_car)
    return new_state

#Checks if the car is not in out of bounds
#Explained in documentation 
def out_of_bounds(car):
    if car.orientation == "H":
        if car.x < 1 or (car.x - 1 + car.size) > 6:
            return True
        return False
    elif car.orientation == "V":
        if car.y < 1 or (car.y - 1 + car.size) > 6:
            return True
        return False

#Checks if there is a collision between cars
#Explained in documentation
def collision(state):
    used = set()
    for car in state:
        if car.orientation == "H":
            for i in range(car.size):
                if (car.y, car.x + i) in used:
                    return True
                used.add((car.y, car.x + i))
        else:
            for i in range(car.size):
                if (car.y + i, car.x) in used:
                    return True
                used.add((car.y + i, car.x))
    return False

#Prints the path from the root to the node, also writes it to output.txt
def print_path(node):
    path = []
    #Parent of root is None so we can stop there
    while node.parent != None:
        path.append("")
        path.append(print_matrix(node.state).rstrip())
        path.append(f"{node.operator} Depth: {node.depth}")
        node = node.parent
    path.reverse()
    output = "\n".join(path)
    print(output)
    with open("output.txt", "w") as file:
        file.write(output)


#Tests if the red car is in the winning position
#If it is, prints the path from the root to the node
def check_for_win(node):
    state = node.state
    # State[0] is the red car
    if state[0].x + state[0].size == 7:
        
        print_path(node)
        return True , node.depth
    return False , None

#Creates "hash" format from state to check if the state has already been explored
def hash_state(state):
    state_tuple = tuple(
        (car.color, car.size, car.x, car.y, car.orientation) for car in state
    )
    return state_tuple
