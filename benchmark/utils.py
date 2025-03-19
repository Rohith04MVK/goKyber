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