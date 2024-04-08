import matplotlib.pyplot as plt

# Sample x data
x = [5, 10, 20]

# Sample y data for three lines
y1 = [2, 3, 5]
y2 = [1, 4, 9]
# y3 = [3, 6, 9, 12, 15]

# Plot the lines with custom styling
plt.plot(x, y1, linestyle='-', color='blue', marker='o', label='Throughput')
plt.plot(x, y2, linestyle='--', color='red', marker='s', label='Block time')
# plt.plot(x, y3, linestyle=':', color='green', marker='^', label='Line 3')

# Add labels and legend
plt.xlabel('X-axis', fontsize=12)
plt.ylabel('Y-axis', fontsize=12)
plt.title('System Performance for Different Capacitites', fontsize=14)
plt.legend()

# Customize grid
plt.grid(True, linestyle='--', alpha=0.5)
plt.xticks(x)

# Show the plot
plt.show()
