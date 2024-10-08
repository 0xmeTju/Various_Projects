from virtualmachine import *
import random

MAX_STEPS = 500

class Individual:
    def __init__(self, amount):
        #Initializing attributes
        self.cells = [Cell(0) for i in range(MACHINE_SIZE)]
        self.treasures_left = 0
        self.fitness = 0
        self.moveset = []
        #Randomizing genes in cells
        for i in range(min(amount, MACHINE_SIZE)):
            self.cells[i].set_byte(random.randint(0, 255))

class Tester:
    def __init__(self, config):
        #Creating virtual machine
        self.vm = VirtualMachine(config)
        #Initializing attributes
        self.config = config
        self.pop_size = config.get("population_size", 50)
        self.pop_count = config.get("population_count", 500)
        self.amount = config.get("random_genes", 32)
        self.selection_method = config.get("selection_method", "roulette")
        self.mutation_chance = config.get("mutation_chance", 4)
        self.average_fitness = 0
        self.population = []
        #Creating random individuals and adding them to population
        for i in range(self.pop_size):
            self.population.append(Individual(self.amount))

    #Roulette selection
    def roulette(self):
        fitness_sum = 0
        #Calculating sum of all fitnesses
        for individual in self.population:
            fitness_sum += individual.fitness
        
        #Randomly choosing individual
        random_val = random.uniform(0, fitness_sum)
        roulette_sum = 0
        #Looping through population and returning individual
        for individual in self.population:
            roulette_sum += individual.fitness
            if roulette_sum >= random_val:
                return individual
    
    #Elitism selection
    def elitism(self, elite_count):
        elites = copy.deepcopy(sorted(self.population, key=lambda x: x.fitness, reverse=True))
        return elites[:elite_count]

    #Tournament selection
    def tournament(self, amount):
        pick = random.sample(self.population, amount)
        pick.sort(key=lambda x: x.fitness, reverse=True)
        return pick[0]
    
    #Crossover
    def crossover(self, parent1, parent2):
        #Randomly choosing crossover point
        x = random.randint(0, self.amount - 1)
        #Creating child and copying genes from parents
        child = Individual(self.amount)
        child.cells = parent1.cells[:x] + parent2.cells[x:]
        return child

    #Fitness function
    def get_fitness(self, input):
        steps = input[0]
        collected_treasures = input[1]
        
        treasure_weight = 1
        #step_weight = -0.001
        fitness = 0
        
        
        all_treasures = self.config.get("treasure_count",0)
        treasure_score = treasure_weight * (all_treasures - collected_treasures)
        #steps_score = step_weight * steps
        
        fitness = treasure_score
        return fitness
    
    #Calculating average fitness of the population
    def calc_average_fitness(self):
        fitness_sum = 0
        for individual in self.population:
            fitness_sum += individual.fitness
        self.average_fitness = fitness_sum / self.pop_size
    
    def mutation(self, population):
        #Mutation chance from config
        mutation_chance = self.mutation_chance
        for individual in population:
            for i in range(self.amount):
                #Randomly choosing mutation type
                chance = random.randint(0, 100)
                if chance < mutation_chance // 2:
                    individual.cells[i].set_byte(random.randint(0, 255))
                if chance < mutation_chance:
                    byte = individual.cells[i].get_byte()
                    byte = byte ^ (1 << random.randint(0,7))
                    individual.cells[i].set_byte(byte)
                if chance < (mutation_chance // 3):
                    individual.cells[i].set_byte(individual.cells[i + 1].get_byte())

    #Creating new individuals
    def new_blood(self, count):
        population = []
        for i in range(count):
            population.append(Individual(self.amount))
        return population

    def evolution(self, elite_count):
        new_pop = []

        #Elitism
        elites = self.elitism(elite_count)
        #New blood
        new_blood = self.new_blood(elite_count)
        #Adding elites and new blood to new population
        new_pop += elites
        new_pop += new_blood
        amount = self.pop_size - len(elites) - len(new_blood)

        #Selection of parents and crossover
        pick_method = self.selection_method
        if pick_method == "roulette":
            for i in range(amount):
                parent1 = self.roulette()
                parent2 = self.roulette()
                child = self.crossover(parent1, parent2)
                new_pop.append(child)
        elif pick_method == "tournament":
            for i in range(amount):
                parent1 = self.tournament(4)
                parent2 = self.tournament(4)
                child = self.crossover(parent1, parent2)
                new_pop.append(child)
        return new_pop

    #Writing moveset to file
    def write_to_file(self,moveset):
        self.vm.reset(self.config)
        self.vm.execute_moveset(moveset)

    def start(self , config):
        #Initializing variables
        found_all_treasures = False
        elite_count = self.pop_size // self.config.get("elite_ratio", 4)
        best_individual = None

        #Main loop that goes through all generations
        for pop_num in range(self.pop_count):
            if best_individual != None:
                best_individual.moveset = []
            #Loop that goes through all individuals in population
            for i in range(self.pop_size):
                output = [0, 0]
                #Loads new individual to virtual machine and executes it
                self.vm.load(copy.deepcopy(self.population[i].cells), self.population[i].moveset)
                if self.vm.start(output):
                    #Start function returns True if all treasures are found
                    print("##########################################################################################")
                    print(f"Generation {pop_num + 1} individual {i} found all treasures!")
                    self.population[i].fitness = self.get_fitness(output)
                    print(f"Solution individual fitness: {self.population[i].fitness}")
                    print(f"Solution individual moveset: {' '.join(self.population[i].moveset)}")
                    print(f"Visual representation of the solution in file output.txt")
                    self.write_to_file(self.population[i].moveset)
                    print("##########################################################################################")
                    found_all_treasures = True
                    break
                #If not all treasures are found, calculate fitness of the individual
                self.population[i].fitness = self.get_fitness(output)
                #self.population[i].treasures_left = output[1]
                #Reset virtual machine
                self.vm.reset(config)
            #If all treasures are found, break the loop
            if found_all_treasures:
                break
            #Sort population by fitness
            self.population.sort(key=lambda x: x.fitness, reverse=True)
            best_individual = self.population[0]
            #Print information about the generation
            if pop_num % 10 == 0:
                top5_fitness = self.population[:self.pop_size // 10]
                print("----------------------------------")
                print(f"Best 10% fitness of the generation {pop_num} are:")
                i = 1
                for pop in top5_fitness:
                    print(f"Fitness {i}: {pop.fitness}")
                    i += 1
                print("Average fitness: ", round(self.average_fitness, 2))

            self.calc_average_fitness()
            #Create new population with evolution and mutation
            self.population = self.evolution(elite_count)
            self.mutation(self.population[elite_count // 3:])

        #If all generations were unsuccessful, ask user if he wants to retry
        #or print the best individual so far
        if not found_all_treasures:
            print("##########################################################################################")
            print("All generations were unsuccessful!")
            print(f"Best individual fitness: {best_individual.fitness}")
            print(f"Average fitness in last generation: {self.average_fitness}")
            print("Do you want to retry? (y/n)")
            answer = input()
            if answer == "y":
                self.__init__(config)
                self.start(config)
            else:
                print("Printing the best individual so far:")
                print(f"Moveset: {' '.join(best_individual.moveset)}")
                exit(0)
        
             