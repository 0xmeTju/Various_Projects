import matplotlib.pyplot as plt
import pickle

def visualize_clusters(clusters):
    plt.figure(figsize=(10, 10))
    plt.xlim(-5000, 5000)
    plt.ylim(-5000, 5000)
    plt.xticks(range(-5000, 6000, 1000))
    plt.yticks(range(-5000, 6000, 1000))

    colors = ['red', 'green', 'blue', 'yellow', 'magenta', 'cyan', 'maroon', 'darkgreen',
                'navy', 'gray', 'purple', 'olive', 'teal', 'silver', 'orange', 'brown', 
                'pink', 'springgreen', 'orchid', 'lightcoral']

    # Plot each cluster's points with different colors
    for i , cluster in enumerate(clusters):
        cluster_points = cluster.points
        plt.scatter([point.x for point in cluster_points], [point.y for point in cluster_points], color=colors[i % len(colors)],s=2)

    # Plot cluster centers as red dots
    for cluster in clusters:
        plt.scatter(cluster.centre[0], cluster.centre[1], edgecolor='black',facecolor = 'none' , marker='o', s=50)

    plt.title('Visualization of Clusters')
    plt.xlabel('X-axis')
    plt.ylabel('Y-axis')
    plt.show()

if __name__ == "__main__":
    name = input("Enter name of file to load or leave blank for default(cluster.pkl): ")

    if name == "":
        name = "clusters.pkl"

    try:
        with open(name, "rb") as f:
            clusters = pickle.load(f)
        print(f"Loaded {name}")
    except:
        print(f"Could not load/find {name}")
        exit()

    visualize_clusters(clusters)        