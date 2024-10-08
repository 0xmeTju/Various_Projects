# Description: This file contains the functions that are used to create the matrix and move the player
# in the matrix. The matrix is a 2D array of size n x n. The player is represented by the letter P and
# the treasures are represented by the letter T. 
# I'm using index 0 for the x axis and index 1 for the y axis
from sys import exit
import sys

#Creates the matrix from the config file
def create_matrix(config,player_position):
    size = config.get("dimensions", 0)
    matrix = [["." for _ in range(size)] for _ in range(size)]
    treasures = config.get("treasures", {})
    for key, treasure in treasures.items():
        try: 
            matrix[treasure[1] - 1][treasure[0]- 1] = "T"
        except: 
                print(f"Error: Treasure {key} is out of bounds")
                sys.exit(1)
        
    
    try :
        matrix[player_position[1] - 1][player_position[0] - 1] = "P"
    except: 
        print(f"Error: Player position is bad: {player_position}")
        sys.exit(1)

    return matrix

#Prints the matrix
def print_matrix(matrix):
    string = ""
    for row in matrix:
        string += " ".join(row) + "\n"
    print(string)

#Checks if the player has found a treasure
def check_treasure(player_position, config):
    treasures = config.get("treasures", {})
    for key, treasure in treasures.items():
        if treasure[0] == player_position[0] and treasure[1] == player_position[1]:
            #Removes the treasure from the config file
            config["treasures"].pop(key)
            return True
    return False

#Checks if the player is out of bounds
def out_of_bound(player_position,config):
    max_size = config.get("dimensions", 0)
    if player_position[0] < 1 or player_position[0] > max_size:
        return True
    elif player_position[1] < 1 or player_position[1] > max_size:
        return True
    else:
        return False

#Moves the player in the matrix depending on the direction
def move(player_position, direction, config):
    if direction == 'H':
        player_position[1] -= 1
    elif direction == 'P':
        player_position[0] += 1
    elif direction == 'L':
        player_position[0] -= 1
    elif direction == 'D':
        player_position[1] += 1
    else:
        print("Error: Invalid direction")
        
    if out_of_bound(player_position, config):
        #print("Error: Out of bound")
        return True
    else:
        return False

