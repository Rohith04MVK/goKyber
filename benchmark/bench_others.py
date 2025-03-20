import time
import os
import subprocess
import matplotlib.pyplot as plt
import numpy as np
import re

from utils import format_time


# ---------------------------
# Run and parse Kyber benchmark output for two different implementations
# ---------------------------
def measure_kyber(exe_path, format_type=1):
    result = subprocess.run([exe_path], capture_output=True, text=True)  # Adjust the binary path
    output = result.stdout.splitlines()

    kyber_times = []

    if format_type == 1:
        for i in range(len(output)):
            if "Benchmarking Kyber" in output[i]:
                match = re.search(r"Total time:\s+([\d.]+)\u00b5s", output[i + 1])
                if match:
                    time_total = round(float(match.group(1)) / 1e6, 6)  # Convert µs to seconds
                    kyber_times.append(time_total)
    else:
        for line in output:
            match = re.search(r"Total time:\s+([\d.]+)\u00b5s", line)
            if match:
                time_total = round(float(match.group(1)) / 1e6, 6)  # Convert µs to seconds
                kyber_times.append(time_total)

    return kyber_times if len(kyber_times) == 3 else [0, 0, 0]  # Ensure 3 values

# ---------------------------
# Main benchmark function
# ---------------------------
def main():
    overall_start = time.time()

    print("Running Kyber benchmarks...")

    kyber1_times = measure_kyber("./src/bin/gokyber", format_type=1)  # First Kyber implementation
    kyber2_times = measure_kyber("./src/bin/test_mine", format_type=2)  # Second Kyber implementation

    overall_end = time.time()
    print(f"\nTotal benchmark process time: {round(overall_end - overall_start, 3)} seconds")

    # ---------------------------
    # Plotting
    # ---------------------------
    algorithms = ['Our Implementation', 'Original Kyber']
    times_data = [kyber1_times, kyber2_times]

    x = np.arange(len(algorithms))
    width = 0.3

    fig, ax = plt.subplots(figsize=(12, 8))
    bar1 = ax.bar(x - width, [t[0] for t in times_data], width, label='Kyber-512', color='skyblue')
    bar2 = ax.bar(x, [t[1] for t in times_data], width, label='Kyber-768', color='lightgreen')
    bar3 = ax.bar(x + width, [t[2] for t in times_data], width, label='Kyber-1024', color='lightcoral')

    ax.set_ylabel('Time (seconds)', fontsize=12)
    ax.set_title('Benchmark: Original Kyber vs Our Implementation', fontsize=14, fontweight='bold')
    ax.set_xticks(x)
    ax.set_xticklabels(algorithms, fontsize=12)
    ax.legend(fontsize=10)
    ax.grid(axis='y', linestyle='--')

    # Annotate bars with formatted times
    def autolabel(bars):
        for bar in bars:
            height = bar.get_height()
            if height > 0:  # Only label non-zero bars
                ax.annotate(format_time(height),
                            xy=(bar.get_x() + bar.get_width() / 2, height),
                            xytext=(0, 3),
                            textcoords="offset points",
                            ha='center', va='bottom', fontsize=9)

    autolabel(bar1)
    autolabel(bar2)
    autolabel(bar3)
    plt.ylim(bottom=0)

    plt.tight_layout(pad=2.0)
    plt.show()

if __name__ == "__main__":
    main()