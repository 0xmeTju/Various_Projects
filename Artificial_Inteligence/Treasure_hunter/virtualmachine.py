from matrix import *
import copy 

MACHINE_SIZE = 64
MAX_BYTE = 0b11111111
BYTE = 8
MAX_STEPS = 500

class Cell:
    def __init__(self,byte):
        self.__byte = byte & MAX_BYTE
        
    def set_bit(self, position, value):
        if value == 1:
            self.__byte |= 1 << position
        else:
            self.__byte &= ~(1 << position)
    
    #Sets byte to value and makes sure that it is in range
    def set_byte(self, byte):
        self.__byte = byte & MAX_BYTE
    
    def get_byte(self):
        return self.__byte
    
    def get_bit(self, position):
        return (self.__byte >> position) & 1
    
    def get_instruction(self):
        return self.__byte >> 6 
    
    def get_address(self):
        return self.__byte & 0b111111
    
    
    
class VirtualMachine:
    def __init__(self,config):
        self.cells = [Cell(0) for i in range(64)] #Creates 64 cells
        self.pc = 0 #Program counter
        self.moves = 0 #Number of moves
        self.moveset = [] #List of moves
        self.config = copy.deepcopy(config)
        self.player_position = self.config.get('starting_position',0) #Player position
        self.matrix = create_matrix(self.config,self.player_position) #Creates matrix with treasures
        self.treasure_count = self.config.get("treasure_count",0) #Number of treasures in matrix
       
    def exec_instruction(self,cell_index):
        #Getting instruction from cell
        instruction = self.cells[cell_index].get_instruction()
        #Checking the instruction code
        if instruction == 0b00:
            #Increment instruction
            addr_index = self.cells[cell_index].get_address()
            self.cells[addr_index].set_byte(self.incrementation(addr_index))
            self.pc += 1
            return False

        elif instruction == 0b01:
            #Decrement instruction
            addr_index = self.cells[cell_index].get_address()
            self.cells[addr_index].set_byte(self.decrementation(addr_index))
            self.pc += 1
            return False
            
        elif instruction == 0b10:
            #Jump instruction
            self.pc = self.cells[cell_index].get_address()
            return False
        elif instruction == 0b11:
            #Print instruction
            addr = self.cells[cell_index].get_address()
            output = self.get_direction(addr)
            
            #Tries to move player in matrix
            if move(self.player_position, output, self.config):
                #print("Error: Out of bound")
                return True
            self.moveset.append(output)
            
            self.moves += 1
            #Checks if player found treasure
            if check_treasure(self.player_position,self.config):
                self.treasure_count -= 1
            
            #Checks if player has found all treasures
            if self.treasure_count == 0:
                self.matrix = create_matrix(self.config, self.player_position)
                return True
            
            #Increment program counter
            self.pc += 1
        else:
            #Error
            print("Error: Invalid instruction")
            
    #Gets the sum of ones in byte
    def __get_sum_of_ones(self, cell_index):
        sum = 0
        temp_cell = copy.deepcopy(self.cells[cell_index])
        
        for i in range(BYTE):
            if temp_cell._Cell__byte & 0b1 == 1:
                sum += 1
            temp_cell._Cell__byte >>= 1
            
        return sum
    
    #Gets the direction from byte depending on the number of ones
    def get_direction(self, cell_index):
        num_of_ones = self.__get_sum_of_ones(cell_index)
        if num_of_ones <= 2:
            #print("H")
            return 'H'
        elif num_of_ones == 3 or num_of_ones == 4:
            #print("D")
            return 'D'
        elif num_of_ones == 5 or num_of_ones == 6:
            #print("P")
            return 'P'
        elif num_of_ones >= 7:
            #print("L")
            return 'L'
        
    def incrementation(self, cell_index):
        return self.cells[cell_index]._Cell__byte + 1
       
    def decrementation(self ,cell_index):
        return self.cells[cell_index]._Cell__byte - 1
    
    #Resets the virtual machine
    def reset(self,config):
        #print("----Resetting virtual machine----")
        self.cells = []
        self.moveset = []
        self.pc = 0
        self.moves = 0
        self.config = copy.deepcopy(config)
        self.player_position = self.config.get('starting_position',0)
        self.treasure_count = self.config.get("treasure_count",0)
        self.matrix = create_matrix(self.config, self.player_position)
    
    #Loads individual into virtual machine
    def load(self, individual, moveset):
        #Load individual into virtual machine
        self.cells = individual
        self.moveset = moveset
    
    def print_info(self,step_counter):
        #print("Steps: ", step_counter)
        #print("Moves: ", self.moves)
        #print("Treasures left: ", self.treasure_count)
        #print("Player position: ", self.player_position)
        #print("Program counter: ", self.pc)
        #print("Matrix: ")
        #print_matrix(self.matrix)
        ...

    #Checks if we have reached the limits of the machine
    def check_limits(self,step_counter, pc):
        if step_counter >= MAX_STEPS:
            #print("Max steps limit reached!")
            return False
        if pc >= MACHINE_SIZE:
            #print("PC reached limit of machine!")
            return False
        return True

    #Helper function for testing and debugging
    def execute_moveset(self,moveset):
        output = ""
        output += "Starting matrix:\n" + "\n".join(" ".join(str(cell) for cell in row) for row in self.matrix) + "\n"
        moves = 1
        for dir in moveset:
            if move(self.player_position, dir, self.config):
                #print("Error: Out of bound")
                ...

            if check_treasure(self.player_position,self.config):
                self.treasure_count -= 1

            #print("Move: ", moves)
            #print("Direction: ", dir)
            self.matrix = create_matrix(self.config, self.player_position)
            output += "Move: " + str(moves) + "\n" 
            output += "Direction: " + str(dir) + "\n"
            output += "\n".join(" ".join(str(cell) for cell in row) for row in self.matrix) + "\n"
            moves += 1
        with open("output.txt", "w") as file:
            file.write(output)

    #Starts the virtual machine
    def start(self, output):
        #Starts the machine
        step_counter = 0
        
        #Checks the limits of the machine
        while self.check_limits(step_counter, self.pc):
            step_counter += 1
            
            #Executes instruction that is pointed by pc
            if self.exec_instruction(self.pc):
                if out_of_bound(self.player_position, self.config):
                    break
                
                #If we have found all treasures, we end the program
                if self.treasure_count == 0:
                    output[0] = self.moves
                    output[1] = self.treasure_count
                    return True #Ends the program if we have found all treasures
                #break #Breaks loop if we have found all treasures or if we are out of bounds
            
            self.matrix = create_matrix(self.config, self.player_position)
        
        output[0] = self.moves
        output[1] = self.treasure_count