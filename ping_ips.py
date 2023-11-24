import subprocess
import threading
from concurrent.futures import ThreadPoolExecutor
import re
import sys
import argparse
import pandas as pd
from tqdm import tqdm
import time
from datetime import datetime
import os

# Function to get timestamp for file naming
def get_timestamp():
    return datetime.now().strftime("%Y%m%d_%H%M%S")

# Global variables
ip_stats = {}
lockout_delays = {}
results_lock = threading.Lock()
progress_bar_lock = threading.Lock()

# Load or initialize lockout delay values
def load_lockout_delays(filename, ignore_existing):
    if not ignore_existing and os.path.exists(filename):
        df = pd.read_excel(filename, index_col='IP Address', engine='openpyxl')
        return df['Lockout Delay'].to_dict()
    return {}

# Function to identify the IP addresses column in a spreadsheet
def identify_ip_column(df):
    for column in df.columns:
        # Check if any entry in the column looks like an IP address
        if any(re.match(r'^(\d{1,3}\.){3}\d{1,3}$', str(ip)) for ip in df[column]):
            return df[column].tolist()
    raise ValueError("No IP address column found.")

# Function to perform a ping
def ping_ip(ip_address):
    global ip_stats, progress_bar_lock, lockout_delays
    timeout_count = 0
    delay = lockout_delays.get(ip_address, 1)  # Start with known delay or default to 1
    lockout_time = 30  # Initial lockout time

    while not ip_stats[ip_address]['stop']:
        try:
            output = subprocess.check_output(["ping", "-n", "1", "-w", "2000", ip_address], universal_newlines=True)
            latency = re.search(r'Average = (\d+)ms', output).group(1)
            with results_lock:
                ip_stats[ip_address]['latencies'].append(float(latency))
                ip_stats[ip_address]['attempts'] += 1
            timeout_count = 0
        except subprocess.CalledProcessError as e:
            error_msg = e.output.strip().split('\n')[-1]  # Get the last line of the error message
            with results_lock:
                ip_stats[ip_address]['errors'] += 1
                ip_stats[ip_address]['attempts'] += 1
            timeout_count += 1
            tqdm.write(f"{ip_address} | ERROR | {ip_stats[ip_address]['errors']} Times | Waiting {delay} seconds | {error_msg}")
        except subprocess.TimeoutExpired as e:
            with results_lock:
                ip_stats[ip_address]['timeouts'] += 1
                ip_stats[ip_address]['attempts'] += 1
            timeout_count += 1
            tqdm.write(f"{ip_address} | TIMEOUT | {ip_stats[ip_address]['timeouts']} Times | Waiting {delay} seconds")

        # If we reach 6 timeouts, we assume we are being rate-limited
        if timeout_count >= 6:
            with results_lock:
                ip_stats[ip_address]['pauses'] += 1
                delay += 1  # Increment delay
                lockout_delays[ip_address] = delay  # Update the lockout delay for this IP
            tqdm.write(f"{ip_address} | LOCKED OUT | {ip_stats[ip_address]['pauses']} Times | Waiting {lockout_time} seconds")
            time.sleep(lockout_time)
            timeout_count = 0

        time.sleep(delay)

# Main function
def main(ip_list, num_workers, ignore_existing):
    global ip_stats, lockout_delays
    lockout_delays = load_lockout_delays('lockout_delays.xlsx', ignore_existing)

    ip_stats = {ip: {'latencies': [], 'errors': 0, 'timeouts': 0, 'attempts': 0, 'pauses': 0, 'stop': False} for ip in ip_list}

    max_workers = min(num_workers, len(ip_list)) if num_workers > 0 else len(ip_list)

    with tqdm(total=60 * 60, desc="Pinging IPs", unit="s", smoothing=0.5) as progress_bar:
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = [executor.submit(ping_ip, ip) for ip in ip_list]
            try:
                for _ in range(60 * 60):
                    time.sleep(1)
                    progress_bar.update(1)
            except KeyboardInterrupt:
                print("Interrupted by user, shutting down.")
                for ip in ip_list:
                    ip_stats[ip]['stop'] = True

    progress_bar.close()

    # Prepare results for Excel output
    results_data = [
        (
            ip,
            sum(stats['latencies']) / len(stats['latencies']) if stats['latencies'] else 'N/A',
            stats['attempts'],
            stats['errors'],
            stats['timeouts'],
            stats['pauses']
        )
        for ip, stats in ip_stats.items()
    ]

    # Save results to a new Excel file with timestamp
    timestamp = get_timestamp()
    df_results = pd.DataFrame(results_data, columns=['IP Address', 'Average Latency (ms)', 'Attempts', 'Errors', 'Timeouts', 'Pauses'])
    df_results.to_excel(f'ping_results_{timestamp}.xlsx', index=False)

    # Save the updated lockout delays for future use
    if not ignore_existing:
        df_lockout = pd.DataFrame(list(lockout_delays.items()), columns=['IP Address', 'Lockout Delay'])
        df_lockout.to_excel('lockout_delays.xlsx', index=False)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Ping multiple IPs and output to Excel.")
    parser.add_argument('file', type=str, help="The file containing the list of IPs (.txt, .csv, .xlsx).")
    parser.add_argument('-w', '--workers', type=int, default=0, help="Number of workers to use for pinging. Defaults to one worker per IP.")
    parser.add_argument('-nolock', '--ignore-existing', action='store_true', help="Ignore existing lockout delays and start fresh.")
    args = parser.parse_args()

    # Determine file type and load IP list
    if args.file.lower().endswith(('.xlsx', '.csv')):
        df = pd.read_excel(args.file, engine='openpyxl') if args.file.lower().endswith('.xlsx') else pd.read_csv(args.file)
        ip_list = identify_ip_column(df)  # Identify the column with IPs
    else:
        with open(args.file, 'r') as f:
            ip_list = f.read().splitlines()

    num_workers = args.workers if args.workers > 0 else len(ip_list)
    main(ip_list, num_workers, args.ignore_existing)
