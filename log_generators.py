import random
import pandas as pd
import numpy as np
import os
from datetime import datetime, timedelta
from faker import Faker
fake = Faker()

def generate_benign_logins(num_entries=5000):
    logs = []
    start_time = datetime.now() - timedelta(seconds=random.randint(0, 3600 * 24))
    user_login_patterns = {}  # Store user login patterns

    for _ in range(num_entries):
        username = fake.user_name()
        # Simulate user login patterns
        if username in user_login_patterns:
            ip_address, location = user_login_patterns[username]
        else:
            ip_address = fake.ipv4()
            location = fake.city(), fake.country()
            if random.random() < 0.8:  # 80% chance of consistent login
                user_login_patterns[username] = (ip_address, location)

        timestamp = start_time + timedelta(seconds=random.randint(0, 3600))
        hour = timestamp.hour
        # Vary login frequency based on time of day
        if 8 <= hour < 18:  # Business hours
            timestamp = start_time + timedelta(seconds=random.expovariate(1.0 / 60))  # Higher frequency
        else:  # Off-hours
            timestamp = start_time + timedelta(seconds=random.expovariate(1.0 / 300))  # Lower frequency

        # Simulate port and protocol usage
        protocol_probs = {"HTTP": 0.6, "HTTPS": 0.3, "FTP": 0.05, "SSH": 0.05}
        protocol = random.choices(list(protocol_probs.keys()), weights=list(protocol_probs.values()))[0]
        if protocol == "HTTP":
            port = 80
        elif protocol == "HTTPS":
            port = 443
        elif protocol == "SSH":
            port = 22
        elif protocol == "FTP":
            port = 21

        login_status = "success" if random.random() > 0.05 else "failure"
        logs.append([timestamp, username, location, ip_address, port, protocol, login_status])
        start_time = timestamp #ensure that the times are always increasing.

    return logs

def generate_brute_force_attacks(num_attacks=60, login_attempts_per_attack=10, distributed_attack_prob=0.3, common_username_prob=0.2, protocol_target_prob=0.1):
    logs = []
    start_time = datetime.now() - timedelta(seconds=random.randint(0, 3600 * 24))
    for _ in range(num_attacks):
        timestamp = start_time + timedelta(seconds=random.randint(0, 3600))
        attack_duration = random.randint(30, 300)
        attack_end_time = timestamp + timedelta(seconds=attack_duration)
        attempt_count = 0

        if random.random() < distributed_attack_prob:  # Distributed attack scenario
            num_ips = random.randint(2, 5)  # Number of IPs involved
            ips = [fake.ipv4() for _ in range(num_ips)]
            attempts_per_ip = login_attempts_per_attack // num_ips

            while timestamp < attack_end_time and attempt_count < login_attempts_per_attack:
                for ip in ips:
                    if timestamp >= attack_end_time or attempt_count >= login_attempts_per_attack:
                        break
                    if random.random() < common_username_prob:
                        usernames = ["admin", "root", "user", "test"]  # common usernames
                        username = random.choice(usernames)
                    else:
                        username = fake.user_name()
                    location = fake.city(), fake.country()
                    if random.random() < protocol_target_prob:
                        protocol = random.choice(["SSH", "FTP"])  # target ssh and ftp
                    else:
                        protocol = random.choice(["HTTP", "HTTPS", "FTP", "SSH"])
                    port = str(random.randint(1, 65535))
                    logs.append([timestamp, username, location, ip, port, protocol, "failure"])
                    interval = random.uniform(0.1, 5)
                    timestamp += timedelta(seconds=interval)
                    attempt_count += 1
        else:  # Single IP attack
            ip_address = fake.ipv4()
            while timestamp < attack_end_time and attempt_count < login_attempts_per_attack:
                if random.random() < common_username_prob:
                    usernames = ["admin", "root", "user", "test"]  # common usernames
                    username = random.choice(usernames)
                else:
                    username = fake.user_name()
                location = fake.city(), fake.country()
                if random.random() < protocol_target_prob:
                    protocol = random.choice(["SSH", "FTP"])  # target ssh and ftp
                else:
                    protocol = random.choice(["HTTP", "HTTPS", "FTP", "SSH"])
                port = str(random.randint(1, 65535))
                logs.append([timestamp, username, location, ip_address, port, protocol, "failure"])

                attack_type = random.choice(["aggressive", "slow", "exponential"])

                if attack_type == "aggressive":
                    interval = random.uniform(0.01, 2)
                elif attack_type == "slow":
                    interval = random.uniform(30, 300)
                else:
                    interval = random.expovariate(1.0 / 10)

                timestamp += timedelta(seconds=interval)
                attempt_count += 1

    return logs