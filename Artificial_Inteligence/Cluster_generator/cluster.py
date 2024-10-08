import math
class Cluster:
    def __init__(self):
        self.points = [] #List of points in cluster
        self.centre = [0,0] #Centre of cluster
        self.centre_point = None #Centre point of cluster
        self.average_distance = 0 #Average distance of points to centre
    
    def set_centre(self, centre):
        self.centre = centre

    def set_centre_point(self, centre_point):
        self.centre_point = centre_point
        self.centre = [centre_point.x, centre_point.y]

    def set_points(self, points):     
        self.points = points

    #Calculate total distance of points to centre
    def get_total_distance(self, centre):
        total_distance = 0
        cluster_centre_cords = centre #Cluster coordinates

        for point in self.points: #Cycle through points
            point_cords = [point.x, point.y]
            #Calculate distance between point and cluster centre using pythagoras theorem
            distance = math.sqrt(math.pow((point_cords[0] - cluster_centre_cords[0]), 2) + math.pow((point_cords[1] - cluster_centre_cords[1]), 2))
            total_distance += distance #Add distance to total distance

        return total_distance

    #Calculate average distance of points to centre
    def calculate_average(self):
        if self.points == []:
            print(f"Cluster has no points")
            return

        total_distance = 0
        cluster_centre_cords = [self.centre[0], self.centre[1]] #Cluster coordinates

        for point in self.points: #Cycle through points
            point_cords = [point.x, point.y] #Point coordinates
            #Calculate distance between point and cluster centre using pythagoras theorem
            distance = math.sqrt(math.pow((point_cords[0] - cluster_centre_cords[0]), 2) + math.pow((point_cords[1] - cluster_centre_cords[1]), 2))
            total_distance += distance #Add distance to total distance

        #Calculate average distance
        average_distance = total_distance/len(self.points)
        self.average_distance = average_distance

    #Calculate centre of centroid
    def calculate_centre_centroid(self):
        if self.points == []:
            print(f"Cluster has no points")
            return
        
        len_points = len(self.points) #Number of points in cluster

        sum_x = 0 
        sum_y = 0
        for point in self.points: #Cycle through points and add x and y to sum
            sum_x += point.x
            sum_y += point.y

        new_centre = [sum_x/len_points, sum_y/len_points] #Calculate new centre

        if new_centre == self.centre: #If new centre is the same as old centre, return false
            print(f"Cluster centre is the same")
            return False
        else: #Else set new centre and return true
            self.centre = new_centre
            print(f"Cluster centre is now {self.centre}")
            return True
  
    #Calculate centre of medoid
    def calculate_centre_medoid(self):
        if not self.points:
            print("Cluster has no points")
            return False
        
        current_centre = self.centre #Current centre
        current_distance = self.get_total_distance(self.centre) #Current distance

        for point in self.points: #Cycle through points
            temp_distance = self.get_total_distance([point.x, point.y]) #Calculate distance of point to other points
            if temp_distance < current_distance: #If distance is smaller than current distance, set new centre
                self.centre = [point.x, point.y] #Set new centre
                current_distance = temp_distance #Set current distance to new distance

        if current_centre == self.centre: #If new centre is the same as old centre, return false
            print(f"Cluster centre is the same")
            return False
        #Else return true
        print(f"Cluster centre is now {self.centre}")
        return True