class Car:
    def __init__(self, color, size, x, y, orientation):
        self.color = color
        self.size = size
        self.x = x
        self.y = y
        self.orientation = orientation

#Creates visual representation of matrix with cars in it
def create_matrix(cars):
    matrix = [["." for _ in range(6)] for _ in range(6)]
    #Place cars in matrix
    for car in cars:
        place_car(matrix, car)

    return matrix

#Logic for placing cars in matrix
def place_car(matrix, car):
    x, y = car.x, car.y
    size = car.size
    orientation = car.orientation

    #Checks if the car is oriented horizontally or vertically
    if orientation == "H":
        for i in range(size):
            #Checks if there is a collision when placing the car
            if matrix[y - 1][x - 1 + i] != ".":
                print(f"Collision detected for car '{car.color}' at ({x}, {y}).")
            else:
                #Places the car in the matrix if there is no collision
                matrix[y - 1][x - 1 + i] = car.color
    elif orientation == "V":
        for i in range(size):
            if matrix[y - 1 + i][x - 1] != ".":
                print(f"Collision detected for car '{car.color}' at ({x}, {y}).")
            else:
                matrix[y - 1 + i][x - 1] = car.color

#Prints the matrix
def print_matrix(state):
    matrix = create_matrix(state)
    string = ""
    for row in matrix:
        string += " ".join(row) + "\n"
    return string
