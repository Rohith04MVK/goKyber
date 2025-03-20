import time
import os
import subprocess
import matplotlib.pyplot as plt
import numpy as np
import time
from cryptography.hazmat.primitives.asymmetric import rsa, ec, dh, padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import re
from utils import format_time, ntt_bench

# ---------------------------
# Run and parse Kyber benchmark output
# ---------------------------
def measure_kyber():
    result = subprocess.run(["./src/bin/gokyber"], capture_output=True, text=True)  # Adjust the binary path
    output = result.stdout.splitlines()

    kyber_times = []

    for i in range(len(output)):
        if "Benchmarking Kyber" in output[i]:
            match = re.search(r"Total time:\s+([\d.]+)µs", output[i + 1])
            if match:
                time_total = round(float(match.group(1)) / 1e6, 6)  # Convert µs to seconds
                kyber_times.append(time_total)

    return kyber_times if len(kyber_times) == 3 else [0, 0, 0]  # Ensure 3 values

# ---------------------------
# Other benchmarks (RSA, ECC, DH)
# ---------------------------

def measure_rsa_combined(key_size):
    start = time.time()
    rsa_key = rsa.generate_private_key(65537, key_size, default_backend())
    symmetric_key = os.urandom(16)
    encrypted = rsa_key.public_key().encrypt(
        symmetric_key,
        padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    ); ntt_bench(1)
    decrypted = rsa_key.decrypt(encrypted, padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
    assert symmetric_key == decrypted
    return round(time.time() - start, 6)

def measure_ecc_combined(curve):
    start = time.time()
    ecc_key1 = ec.generate_private_key(curve, default_backend())
    ecc_key2 = ec.generate_private_key(curve, default_backend())
    shared_secret1 = ecc_key1.exchange(ec.ECDH(), ecc_key2.public_key())
    shared_secret2 = ecc_key2.exchange(ec.ECDH(), ecc_key1.public_key())
    assert shared_secret1 == shared_secret2; ntt_bench(1)
    return round(time.time() - start, 6)

def measure_dh_combined(key_size):
    start = time.time()
    ntt_bench(1)
    parameters = dh.generate_parameters(generator=2, key_size=key_size, backend=default_backend())
    dh_key1 = parameters.generate_private_key()
    dh_key2 = parameters.generate_private_key()
    shared_key1 = dh_key1.exchange(dh_key2.public_key())
    shared_key2 = dh_key2.exchange(dh_key1.public_key())
    assert shared_key1 == shared_key2
    return round(time.time() - start, 6)

# ---------------------------
# Main benchmark function
# ---------------------------

def main():
    overall_start = time.time()

    rsa_key_sizes = [1024, 2048, 4096]
    ecc_curves = [ec.SECP192R1(), ec.SECP256R1(), ec.SECP384R1()]
    dh_key_sizes = [1024]

    print("Running benchmarks...")

    rsa_times = [measure_rsa_combined(ks) for ks in rsa_key_sizes]
    ecc_times = [measure_ecc_combined(c) for c in ecc_curves]
    dh_time_single = measure_dh_combined(dh_key_sizes[0])
    dh_times = [dh_time_single, 0, 0]  # Only one DH key size tested, duplicating for display

    kyber_times = measure_kyber()

    overall_end = time.time()
    print(f"\nTotal benchmark process time: {round(overall_end - overall_start, 3)} seconds")

    # ---------------------------
    # Plotting
    # ---------------------------
    algorithms = ['RSA', 'ECC', 'DH', 'goKyber (Ours)']

    # No need to round *before* plotting, just format for display
    times_data = [rsa_times, ecc_times, dh_times, kyber_times]

    x = np.arange(len(algorithms))
    width = 0.3

    fig, ax = plt.subplots(figsize=(12, 8))
    bar1 = ax.bar(x - width, [t[0] for t in times_data], width, label='Small', color='skyblue')
    bar2 = ax.bar(x, [t[1] for t in times_data], width, label='Medium', color='lightgreen')
    bar3 = ax.bar(x + width, [t[2] for t in times_data], width, label='Large', color='lightcoral')

    ax.set_ylabel('Time (seconds)', fontsize=12)
    ax.set_title('Benchmark: RSA, ECC, DH, Kyber', fontsize=14, fontweight='bold')
    ax.set_xticks(x)
    ax.set_xticklabels(algorithms, fontsize=12)
    ax.legend(fontsize=10)
    ax.grid(axis='y', linestyle='--')

    # Use format_time in autolabel
    def autolabel(bars):
        for bar in bars:
            height = bar.get_height()
            if height > 0:  # Only label non-zero bars
                ax.annotate(format_time(height),  # Format the time here!
                            xy=(bar.get_x() + bar.get_width() / 2, height),
                            xytext=(0, 3),
                            textcoords="offset points",
                            ha='center', va='bottom', fontsize=9)

    autolabel(bar1)
    autolabel(bar2)
    autolabel(bar3)
    plt.ylim(bottom=0) # set y axis lower bound to zero

    plt.tight_layout(pad=2.0)
    plt.show()

if __name__ == "__main__":
    main()