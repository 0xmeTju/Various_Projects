from k_centroid import Kmeans_Centroid

class Division_centroid:
    def __init__(self):
        self.clusters = [] #List of clusters
        self.k = 0 #Number of clusters
        self.K_means = Kmeans_Centroid() #K-means object used for clustering
    

    def set_k(self, k):
        self.k = k

    #Start division clustering
    def start(self, points):
        self.K_means.set_k(self.k) #Set k for k-means
        #First clustering with k-means to make initial clusters
        self.clusters = self.K_means.cluster_points(points)
        #Division clustering until all clusters are successful(average distance < 500)
        print("\nDivision of clusters")
        #While loop to keep dividing clusters until all clusters are successful
        while True:
            success = True
            new_clusters = [] #List of new clusters
            for cluster in self.clusters: #Cycle through clusters
                if cluster.average_distance > 500: #If cluster is unsuccessful
                    print(f"Cluster has average distance {cluster.average_distance}")
                    print(f"Dividing cluster")
                    self.K_means.set_k(2) #Set k to 2 for division
                    self.K_means.clusters = [] #Clear clusters
                    new_clusters = self.K_means.cluster_points(cluster.points) #Divide cluster
                    self.clusters.remove(cluster) #Remove old cluster
                    self.clusters.extend(new_clusters) #Add new clusters
                    success = False #Set success to false
                else:
                    #If cluster is successful, print info
                    print(f"Cluster has average distance {cluster.average_distance}")
                    print(f"Cluster is successful")
            #If all clusters are successful, return clusters        
            if success:
                print(f"All clusters are successful")
                return self.clusters
