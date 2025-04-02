import random
import pandas as pd
import numpy as np
import os

def import_benign_logs():
    benign_logs_csv_file_path = '.venv/brute-force-detection/data/benign_logs.csv'
    df = pd.read_csv(benign_logs_csv_file_path)
    logs = df.values

    return logs

def import_brute_force_attack_logs():
    brute_force_logs_csv_file_path = '.venv/brute-force-detection/data/brute_force.csv'
    df = pd.read_csv(brute_force_logs_csv_file_path)
    logs = df.values

    return logs   
    