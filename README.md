# FinalProjectSubmission3721_NewmanKarima
final project submission for comp 3721 - fall quarter 2025 - karima newman


# Password Hashing Security Simulation

## Overview
This project simulates offline dictionary attacks to evaluate how password-hashing algorithms perform under different configurations. It examines cracked rate and hash computation time for:

- **MD5**
- **SHA-1**
- **SHA-256**
- **PBKDF2**
- **bcrypt**
- **Argon2**

 test these algorithms with:
- Salt vs. no-salt
- Parameter tuning (iterations / cost / memory)
- Small vs. large dictionary attacks

---

## Goals
- Understand the impact of hashing algorithm choice
- Measure how much stronger passwords become with salting
- Evaluate cost-parameter tuning on crack rates
- Compare fast hashes vs memory-hard KDFs in security

---

## Architecture

### System Components
| Component | Description |
|----------|-------------|
| Password Generator | Produces 2000 passwords of mixed strengths |
| Dictionary Source | Two wordlists: small & large |
| Hash Engine | Hashes passwords w/ algorithm + parameters |
| Cracking Simulator | Offline dictionary attack model |
| Results Collector | Writes to CSV + summary stats |
| Visualization | Matplotlib graphs |

### Data Flow

Passwords -> Hash Engine (salt + params) -> Stored Hashes (DB)
Dictionary -> Cracking Simulator -> Compare -> Results -> CSV/Plots





## Tech Stack
- Language: **Python 3**  
- Libraries: `pandas`, `numpy`, `matplotlib`, `bcrypt`, `argon2-cffi`, `hashlib`  
- Environment: Local machine (VSCode recommended)

## Setup & Run Instructions

1. Create a project directory and save these files:
   - `simulate_hashing_project.py`
   - `measure_hash_times.py`
   - (optional) `report.md`

2. Create and activate a Python virtual environment:
   - macOS / Linux:
     ```bash
     python -m venv venv
     source venv/bin/activate
     ```
   - Windows (PowerShell):
     ```powershell
     python -m venv venv
     .\venv\Scripts\Activate.ps1
     ```

3. Install dependencies:
```bash
pip install pandas numpy matplotlib bcrypt argon2-cffi reportlab



To run in terminal - python simulate_hashing_project.py
To measure real hash times (no cracking) - python measure_hash_times.py


