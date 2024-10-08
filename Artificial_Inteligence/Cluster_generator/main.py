from generator import Generator
from k_centroid import Kmeans_Centroid
from k_medoid import Kmeans_Medoid
from d_centroid import Division_centroid
import pickle


def print_info(clusters):
    colors = ['red', 'green', 'blue', 'yellow', 'magenta', 'cyan', 'maroon', 'darkgreen',
                'navy', 'gray', 'purple', 'olive', 'teal', 'silver', 'orange', 'brown', 
                'pink', 'springgreen', 'orchid', 'lightcoral']
    count = 0
    print("\nCluster info")
    for i,cluster in enumerate(clusters):
                if cluster.average_distance <= 500:
                    print("Successfull cluster")
                    print(f"Cluster {i+1} color [{colors[i % len(colors)]}] with centre {round(cluster.centre[0], 3), round(cluster.centre[1], 3)} has average distance {round(cluster.average_distance,3)}")
                    count += 1
                else:
                    print("Failed cluster")
                    print(f"Cluster {i+1} color[{colors[i % len(colors)]}] with centre {round(cluster.centre[0], 3), round(cluster.centre[1], 3)} has average distance {round(cluster.average_distance,3)}")
    print(f"\nTotal clusters: {len(clusters)}")
    print(f"Total successful clusters: {count}")
    print(f"Success rate: {round(count/len(clusters)*100, 3)}%")

if __name__ == "__main__":
    mode = int(input("(1) K-means (2) K-medoid (3) Division (0) Quit\n"))
    points = Generator().make_points()
    k = 0

    while mode != 0:
        if mode == 1:
            cluster_alg = Kmeans_Centroid()
            k = int(input("Enter k: "))
            cluster_alg.set_k(k)
            cluster_alg.cluster_points(points)
            print("\nClustering done")
            print_info(cluster_alg.clusters)
            break
        elif mode == 2:
            cluster_alg = Kmeans_Medoid()
            k = int(input("Enter k: "))
            cluster_alg.set_k(k)
            cluster_alg.cluster_points(points)
            print("\nClustering done")
            print_info(cluster_alg.clusters)
            break
        elif mode == 3:
            cluster_alg = Division_centroid()
            k = int(input("Enter k for initial clusters: "))
            cluster_alg.set_k(k)
            cluster_alg.start(points)
            print_info(cluster_alg.clusters)
            print(f"Added clusters in division clustering: {len(cluster_alg.clusters) - k}")
            break
        elif mode == 0:
            print("Quitting")
            exit()
        else:
            print("Invalid input")
            mode = int(input("(1) K-means (2) K-medoid (3) Division (0) Quit\n"))
            continue
    try:
        with open("clusters.pkl", "wb") as f:
            pickle.dump(cluster_alg.clusters, f)
        print("Saved clusters as clusters.pkl")
    except:
        print("Could not save clusters")
        