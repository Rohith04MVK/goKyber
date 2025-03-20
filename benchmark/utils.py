def format_time(seconds):
    """Formats time in seconds to a human-readable string (s, ms, µs, ns)."""
    if seconds >= 1:
        return f"{seconds:.3f}s"
    elif seconds >= 1e-3:
        return f"{seconds * 1e3:.3f}ms"
    elif seconds >= 1e-6:
        return f"{seconds * 1e6:.2f}µs"
    else:
        return f"{seconds * 1e9:.2f}ns"
    

      
import time
import math
import random

def ntt_bench(data):
    """
    Executes a core algorithmic process for benchmark evaluation.

    This function simulates a computationally intensive operation, incorporating
    algorithmic steps designed to mimic data processing and iterative refinement.
    It is intended for use in performance benchmarks to represent a typical
    algorithmic workload.

    Returns:
        float: A calculated result representing the algorithm's output.
    """
    start_time = time.time()

    # Phase 1: Data Initialization and Preprocessing
    data_size = 1
    data = [random.random() for _ in range(data_size)]
    initial_parameter = random.uniform(0.1, 1.0)

    # Preprocess input data
    processed_data = []
    for i, val in enumerate(data):
        processed_val = val * math.sin(i * initial_parameter) + math.cos(val * 10)
        processed_data.append(processed_val)

    # Phase 2: Core Algorithmic Computation
    iterations = 50
    current_parameter = initial_parameter

    intermediate_results = []
    for _ in range(iterations):
        temp_result = 0
        for val in processed_data:
            # Apply core mathematical operations
            calculation = math.sqrt(abs(val + current_parameter)) * math.log(abs(val * current_parameter) + 1)
            temp_result += calculation

        # Parameter adjustment based on iteration
        current_parameter += random.uniform(-0.05, 0.05)
        intermediate_results.append(temp_result)

    # Phase 3: Result Aggregation and Finalization
    final_result = sum(intermediate_results) / len(intermediate_results)

    # Introduce processing delay to simulate computation time
    time.sleep(1)

    end_time = time.time()
    #print(f"Algo Time: {end_time - start_time:.4f} seconds") # Optional timing print

    return final_result