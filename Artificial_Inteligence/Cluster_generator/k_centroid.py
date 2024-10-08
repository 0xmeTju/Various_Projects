from cluster import Cluster
import random
import math

MAX_ITERATIONS = 200

class Kmeans_Centroid:
    def __init__(self) -> None:
        self.k = 0 #Number of clusters
        self.clusters = [] #List of clusters

    def set_k(self, k):
        self.k = k

    #Returns the closest cluster to a point
    def get_closest_cluster(self, point):
        closest_cluster = None
        closest_distance = 0
        point_cords = [point.x, point.y] #Point coordinates

        for cluster in self.clusters: #Cycle through clusters
            cluster_centre_cords = cluster.centre #Cluster coordinates
            if cluster_centre_cords == point_cords: #If cluster centre is the same as point, return cluster
                return cluster

            #Calculate distance between point and cluster centre using pythagoras theorem
            distance = math.sqrt(math.pow((point_cords[0] - cluster_centre_cords[0]), 2) + math.pow((point_cords[1] - cluster_centre_cords[1]), 2))

            #If distance is smaller than the closest distance, set closest cluster to current cluster
            if closest_distance == 0 or distance < closest_distance:
                closest_cluster = cluster
                closest_distance = distance
            else:
                continue
        #Return the closest found cluster
        return closest_cluster

        
    #Cluster points using k-means
    def cluster_points(self, points):
        #Making initial k clusters
        for i in range(self.k):
            self.clusters.append(Cluster())
        
        print(f"Made {self.k} clusters")

        #If there are less points than clusters, return a cluster with all points
        #Used for error handling
        if len(points) < self.k or len(points) == 1:
            print(f"ValueError: Sample larger than population")
            print(f"Points: {len(points)}")
            self.clusters[0].set_points(points)
            return self.clusters

        #Get k random points from the list of points
        try:
            temp_points = random.sample(points, self.k)
        except ValueError:
            print(f"ValueError: Sample larger than population")
            return Cluster().set_points(points)

        #Set the centre of each cluster to the random points
        #Using points as initial centres to avoid empty clusters
        for cluster in self.clusters:
            temp_point = temp_points.pop(0)
            cluster.set_centre([temp_point.x, temp_point.y])
            print(f"Cluster centre: {cluster.centre}")

        
        changed = True
        iterations = 0

        #While clusters are changing and iterations are less than max iterations
        while changed and iterations < MAX_ITERATIONS:
            print(f"\nIteration {iterations + 1}")
            changed = False

            for cluster in self.clusters:
                cluster.points = [] #Clear points in cluster

            for point in points: #Cycle through points and add them to the closest cluster
                    closest_cluster = self.get_closest_cluster(point)
                    closest_cluster.points.append(point)

            for i,cluster in enumerate(self.clusters):
                #Calculate new centre for each cluster based on the points in the cluster
                print(f"Cluster {i + 1} has {len(cluster.points)} points")
                #If the centre has changed, set changed to true
                if cluster.calculate_centre_centroid():
                    changed = True

            iterations += 1
        
        #Calculate average distance for each cluster
        for cluster in self.clusters:
            cluster.calculate_average()

        return self.clusters
