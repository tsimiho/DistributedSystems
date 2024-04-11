import matplotlib.pyplot as plt

#
x = [5, 10, 20]

y1_5 = [143.52, 134.99, 133.61]
y2_5 = [0.107, 0.135, 0.430]

fig, ax1 = plt.subplots()

color = "tab:red"
ax1.set_xlabel("X-axis")
ax1.set_ylabel("Throughput", color=color)
ax1.plot(x, y1_5, color=color)
ax1.tick_params(axis="y", labelcolor=color)

ax2 = ax1.twinx()
color = "tab:blue"
ax2.set_ylabel("Mean Block Time", color=color)
ax2.plot(x, y2_5, linestyle="dotted", color=color)
ax2.tick_params(axis="y", labelcolor=color)

plt.title("System Performance for Different Capacities")
plt.grid(True, linestyle="--", alpha=0.5)

plt.xticks(x_5)

plt.show()


y1_10 = [120.55, 134.99, 133.61]
y2_10 = [0.107, 0.135, 0.430]

fig, ax1 = plt.subplots()

color = "tab:red"
ax1.set_xlabel("X-axis")
ax1.set_ylabel("Throughput", color=color)
ax1.plot(x, y1, color=color)
ax1.tick_params(axis="y", labelcolor=color)

ax2 = ax1.twinx()
color = "tab:blue"
ax2.set_ylabel("Mean Block Time", color=color)
ax2.plot(x, y2, linestyle="dotted", color=color)
ax2.tick_params(axis="y", labelcolor=color)

plt.title("System Performance for Different Capacities")
plt.grid(True, linestyle="--", alpha=0.5)

plt.xticks(x)

# plt.savefig("performance.png")

plt.show()
