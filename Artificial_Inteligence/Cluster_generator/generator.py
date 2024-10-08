import random
from time import sleep

class Generator:

    map_coords = {"x":0,"y":0}
    points = []

    def make_new_point(self,point):
        #Calculate offset
        x_off = self.get_offset_x(point.x)
        y_off = self.get_offset_y(point.y)

        #Make new point based on offset and old point
        new_x = point.x + random.randint(-x_off,x_off)
        new_y = point.y + random.randint(-y_off,y_off)

        return self.Point(new_x, new_y)

    def get_offset_x(self,x):
        #If x close to map edge, return offset
        x_offset = max(0,abs(5000 - abs(x)))
        return min(100, x_offset)

    def get_offset_y(self,y):
        #If y close to map edge, return offset
        y_offset = max(0,abs(5000 - abs(y)))
        return min(100, y_offset)
        

    class Point:
        def __init__(self, x, y):
            self.x = x
            self.y = y

    def make_points(self,):
        #Set map coords
        self.map_coords["x"] = 10000
        self.map_coords["y"] = 10000

        points = []
        #Make 20 random starter points
        for i in range(20):
            points.append(self.Point(random.randint(-5000,5000), random.randint(-5000,5000)))

        #Make 40000 new points dependant on the created points
        for j in range(40000):
            parent = random.choice(points)
            new_point = self.make_new_point(parent)
            points.append(new_point)
        #Return all points
        return points
