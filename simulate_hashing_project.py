"""
simulate_hashing_project.py

Simulates password hashing times and offline dictionary-cracking success rates
for various hashing algorithms (MD5, SHA1, SHA256, PBKDF2, bcrypt, Argon2).
This is a simulation for academic/project/demo purposes only — it does NOT perform
real password cracking. It uses probabilistic models to produce believable
benchmarks and CSV outputs.

Usage:
    python simulate_hashing_project.py

Outputs (saved to ./results):
 - passwords.csv         : generated password list (with strength labels)
 - dictionary.txt        : simulated attacker dictionary
 - results.csv           : per-password simulation results (time-to-hash, cracked or not)
 - summary.csv           : aggregated metrics per algorithm/parameter
 - plots: PNG files for visuals
"""
import os, random, math, csv
import pandas as pd
import numpy as np
from pathlib import Path
import matplotlib.pyplot as plt

random.seed(42)
np.random.seed(42)

OUT = Path("./results")
OUT.mkdir(exist_ok=True)

algorithms = [
    {"name": "MD5", "type": "fast"},
    {"name": "SHA1", "type": "fast"},
    {"name": "SHA256", "type": "fast"},
    {"name": "PBKDF2", "type": "iter", "iterations": [1000, 10000, 50000]},
    {"name": "bcrypt", "type": "cost", "costs": [8, 10, 12]},
    {"name": "Argon2", "type": "memory", "mem_kb": [32, 256, 1024]}
]

def generate_passwords(n=2000):
    passwords = []
    for i in range(n):
        r = random.random()
        if r < 0.5:
            pw = random.choice(["password","123456","qwerty","letmein","welcome","admin","iloveyou",
                                "sunshine","monkey","dragon"]) + str(random.randint(0,999))
            strength = "weak"
        elif r < 0.85:
            base = random.choice(["football","baseball","computer","coffee","iloveu","flower","purple"])
            pw = base + random.choice(["2020","!","$","123","_"]) + random.choice(["1","99","x"])
            strength = "medium"
        else:
            pw = "".join(random.choices("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-_=+",
                                        k=random.randint(12,20)))
            strength = "strong"
        passwords.append({"id": i, "password": pw, "strength": strength})
    return pd.DataFrame(passwords)

pw_df = generate_passwords()
pw_df.to_csv(OUT / "passwords.csv", index=False)

# build attacker dictionary
dict_words = set(["password","123456","qwerty","letmein","welcome","admin","iloveyou",
                  "sunshine","monkey","dragon","football","baseball","computer","coffee",
                  "flower","purple","iloveu"])
for w in list(dict_words):
    dict_words.update([w+"123", w+"2020", w+"!"])
dict_words.update([f"word{i}" for i in range(5000)])
dict_list = list(dict_words)
with open(OUT / "dictionary.txt","w") as f:
    for w in dict_list: f.write(w+"\n")

def base_hash_time_ms(algo, param=None):
    if algo=="MD5": return 0.05
    if algo=="SHA1": return 0.08
    if algo=="SHA256": return 0.12
    if algo=="PBKDF2": return 0.00002*param.get("iterations",1000)
    if algo=="bcrypt": return (2**(param.get("cost",10)-6))*1.2
    if algo=="Argon2": return 0.5*math.log2(param.get("mem_kb",32)+1)
    return 1.0

def crack_probability(pw, algo, param=None, salted=False, attacker_dict=set()):
    pwstr, strength = pw["password"], pw["strength"]
    simplified = "".join(ch for ch in pwstr.lower() if ch.isalnum())
    in_dict = (pwstr in attacker_dict) or (simplified in attacker_dict)
    if in_dict:
        if algo in ["MD5","SHA1","SHA256"]:
            base = 0.95 if strength=="weak" else (0.7 if strength=="medium" else 0.2)
        elif algo=="PBKDF2":
            it = param.get("iterations",1000)
            base = 0.9*math.exp(-0.00004*(it-1000))
        elif algo=="bcrypt":
            cost = param.get("cost",10)
            base = 0.9*(0.85**(cost-8))
        elif algo=="Argon2":
            mem = param.get("mem_kb",32)
            base = 0.8*(0.9**(math.log2(mem+1)))
    else:
        base = 0.05 if strength=="weak" else (0.02 if strength=="medium" else 0.001)
    if salted:
        base *= 0.4 if algo in ["MD5","SHA1","SHA256"] else 0.7
    return max(0,min(1,base))

small_dict = set(dict_list[:500])
large_dict = set(dict_list[:4000])

rows=[]
for alg in algorithms:
    if alg["name"]=="PBKDF2":
        for it in alg["iterations"]:
            param={"iterations":it}
            for salted in [False,True]:
                for dictname,dictset in [("small",small_dict),("large",large_dict)]:
                    for _,pw in pw_df.iterrows():
                        t=base_hash_time_ms("PBKDF2",param)
                        prob=crack_probability(pw,"PBKDF2",param,salted,dictset)
                        rows.append([alg["name"],f"iters={it}",salted,dictname,pw["strength"],t,prob>random.random()])
    elif alg["name"]=="bcrypt":
        for cost in alg["costs"]:
            param={"cost":cost}
            for salted in [False,True]:
                for dictname,dictset in [("small",small_dict),("large",large_dict)]:
                    for _,pw in pw_df.iterrows():
                        t=base_hash_time_ms("bcrypt",param)
                        prob=crack_probability(pw,"bcrypt",param,salted,dictset)
                        rows.append([alg["name"],f"cost={cost}",salted,dictname,pw["strength"],t,prob>random.random()])
    elif alg["name"]=="Argon2":
        for mem in alg["mem_kb"]:
            param={"mem_kb":mem}
            for salted in [False,True]:
                for dictname,dictset in [("small",small_dict),("large",large_dict)]:
                    for _,pw in pw_df.iterrows():
                        t=base_hash_time_ms("Argon2",param)
                        prob=crack_probability(pw,"Argon2",param,salted,dictset)
                        rows.append([alg["name"],f"mem={mem}KB",salted,dictname,pw["strength"],t,prob>random.random()])
    else:
        for salted in [False,True]:
            for dictname,dictset in [("small",small_dict),("large",large_dict)]:
                for _,pw in pw_df.iterrows():
                    t=base_hash_time_ms(alg["name"])
                    prob=crack_probability(pw,alg["name"],{},salted,dictset)
                    rows.append([alg["name"],"",salted,dictname,pw["strength"],t,prob>random.random()])

df=pd.DataFrame(rows,columns=["algorithm","param","salted","dict","strength","hash_time_ms","cracked"])
summary=df.groupby(["algorithm","param","salted","dict"]).agg(
    total=("cracked","count"),
    cracked_sum=("cracked","sum"),
    cracked_rate=("cracked","mean"),
    avg_hash_time_ms=("hash_time_ms","mean")
).reset_index()
summary.to_csv(OUT/"summary.csv",index=False)

plt.figure(figsize=(8,5))
mask=(summary["salted"]==False)&(summary["dict"]=="large")
plotdf=summary[mask].sort_values("avg_hash_time_ms")
plt.bar(plotdf["algorithm"]+" "+plotdf["param"],plotdf["avg_hash_time_ms"])
plt.ylabel("Avg hash time (ms)")
plt.xticks(rotation=45,ha="right")
plt.tight_layout()
plt.savefig(OUT/"hash_time_by_algo.png")
plt.close()

plt.figure(figsize=(8,5))
plt.bar(plotdf["algorithm"]+" "+plotdf["param"],plotdf["cracked_rate"])
plt.ylabel("Cracked rate")
plt.xticks(rotation=45,ha="right")
plt.tight_layout()
plt.savefig(OUT/"cracked_rate_by_algo.png")
plt.close()

print("Simulation complete. Results in ./results/")
