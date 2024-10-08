from shared import *

#Explained in documentation
def vpravo(state, color, amount):
    new_state = copy_state(state)
    for car in new_state:
        if car.color == color:
            if car.orientation == "H":
                car.x += amount
                if out_of_bounds(car) or collision(new_state):
                    return state
                return new_state
            else:
                print(f"Car '{car.color}' is not oriented horizontally.")
                return state


def vlavo(state, color, amount):
    new_state = copy_state(state)
    for car in new_state:
        if car.color == color:
            if car.orientation == "H":
                car.x -= amount
                if out_of_bounds(car) or collision(new_state):
                    return state
                return new_state
            else:
                print(f"Car '{car.color}' is not oriented horizontally.")
                return state


def dole(state, color, amount):
    new_state = copy_state(state)
    for car in new_state:
        if car.color == color:
            if car.orientation == "V":
                car.y += amount
                if out_of_bounds(car) or collision(new_state):
                    return state
                return new_state
            else:
                print(f"Car '{car.color}' is not oriented vertically.")
                return state


def hore(state, color, amount):
    new_state = copy_state(state)
    for car in new_state:
        if car.color == color:
            if car.orientation == "V":
                car.y -= amount
                if out_of_bounds(car) or collision(new_state):
                    return state
                return new_state
            else:
                print(f"Car '{car.color}' is not oriented vertically.")
                return state
