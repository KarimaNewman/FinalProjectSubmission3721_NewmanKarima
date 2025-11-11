"""
measure_hash_times.py

Measure single-hash computation times on your machine for PBKDF2, bcrypt, Argon2 (where available).
This script does NOT perform cracking. It simply times the cost of computing a single hash (useful to pick parameters).
"""
import time, hashlib, statistics
try:
    import bcrypt
except Exception:
    bcrypt = None
try:
    from argon2 import PasswordHasher
except Exception:
    PasswordHasher = None

def time_func(func, repeats=20):
    times = []
    for _ in range(repeats):
        t0 = time.perf_counter()
        func()
        t1 = time.perf_counter()
        times.append((t1 - t0) * 1000.0)
    return statistics.mean(times), statistics.stdev(times) if len(times) > 1 else 0.0

pw = b"password123!"
print("Measuring PBKDF2-HMAC-SHA256 (1000 iters)...")
m, s = time_func(lambda: hashlib.pbkdf2_hmac('sha256', pw, b'salt', 1000), repeats=10)
print(f"PBKDF2(1000): mean {m:.3f} ms (sd {s:.3f})")

print("Measuring PBKDF2-HMAC-SHA256 (50000 iters)...")
m, s = time_func(lambda: hashlib.pbkdf2_hmac('sha256', pw, b'salt', 50000), repeats=5)
print(f"PBKDF2(50000): mean {m:.3f} ms (sd {s:.3f})")

if bcrypt:
    print("Measuring bcrypt (cost=12)...")
    m, s = time_func(lambda: bcrypt.hashpw(pw, bcrypt.gensalt(rounds=12)), repeats=5)
    print(f"bcrypt cost=12: mean {m:.3f} ms (sd {s:.3f})")
else:
    print("bcrypt not installed. Install with: pip install bcrypt")

if PasswordHasher:
    ph = PasswordHasher(time_cost=2, memory_cost=1024)
    print("Measuring Argon2 (time_cost=2, memory_cost=1024KB)...")
    m, s = time_func(lambda: ph.hash("password123!"), repeats=5)
    print(f"Argon2 sample: mean {m:.3f} ms (sd {s:.3f})")
else:
    print("argon2-cffi not installed. Install with: pip install argon2-cffi")
