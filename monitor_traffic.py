import psutil
import time
import subprocess
import sys

def install_package(package):
	"""Install a pip package using subprocess."""
	subprocess.check_call([sys.executable, "-m", "pip", "install", package])

# Ensure psutil is installed
try:
	import psutil
except ImportError:
	print("psutil not installed. Installing...")
	install_package("psutil")

def load_whitelisted_ips(filename="whitelist.txt"):
	"""Load whitelisted IPs from a file, creating the file if it doesn't exist."""
	try:
    	with open(filename, 'r') as file:
        	return set(line.strip() for line in file if line.strip())
	except FileNotFoundError:
    	print(f"Whitelist file '{filename}' not found. Creating a new one.")
    	with open(filename, 'w'):  # Create the file
        	pass
    	return set()

def load_blacklist(filename="blacklist.txt"):
	"""Load blacklisted IPs from a file, creating the file if it doesn't exist."""
	try:
    	with open(filename, 'r') as file:
        	return set(line.strip() for line in file if line.strip())
	except FileNotFoundError:
    	print(f"Blacklist file '{filename}' not found. Creating a new one.")
    	with open(filename, 'w'):
        	pass
    	return set()

def add_to_blacklist(ip, filename="blacklist.txt"):
	"""Add an IP to the blacklist file."""
	with open(filename, 'a') as file:
    	file.write(f"{ip}\n")
	print(f"Added IP {ip} to blacklist.")

def monitor_network_usage(ssh_threshold=100 * 1024, general_threshold=50 * 1024 * 1024, whitelist_file="whitelist.txt", blacklist_file="blacklist.txt"):
	"""Monitor network usage and selectively kill processes exceeding thresholds."""
	net_io_start = psutil.net_io_counters(pernic=True)
	total_uploaded = 0
	terminated_processes = set()
	whitelisted_ips = load_whitelisted_ips(whitelist_file)
	blacklist = load_blacklist(blacklist_file)

	try:
    	while True:
        	time.sleep(1)
        	whitelisted_ips = load_whitelisted_ips(whitelist_file)
        	blacklist = load_blacklist(blacklist_file)
        	net_io_current = psutil.net_io_counters(pernic=True)
        	session_uploaded = 0

        	for nic, stats in net_io_current.items():
            	if nic in net_io_start:
                	sent_bytes = stats.bytes_sent - net_io_start[nic].bytes_sent
                	session_uploaded += sent_bytes

        	total_uploaded += session_uploaded
        	print(f"Total uploaded data: {total_uploaded / (1024 * 1024):.2f} MB")

        	check_ssh_connections(ssh_threshold, whitelisted_ips, terminated_processes, blacklist)
       	 
        	if total_uploaded > general_threshold:
            	print("General upload threshold exceeded. Searching for processes to terminate...")
            	terminate_relevant_processes(terminated_processes, whitelisted_ips, blacklist)
            	net_io_start = psutil.net_io_counters(pernic=True)
            	total_uploaded = 0  # Reset after updating net_io_start

	except KeyboardInterrupt:
    	print("Monitoring stopped by user.")

def check_ssh_connections(ssh_threshold, whitelisted_ips, terminated_processes, blacklist):
	for conn in psutil.net_connections(kind='inet'):
    	if conn.status == 'ESTABLISHED' and conn.laddr and conn.raddr and conn.raddr.port == 22:
        	if conn.pid in terminated_processes or conn.raddr.ip in whitelisted_ips or conn.raddr.ip in blacklist:
            	continue
        	process = psutil.Process(conn.pid)
        	bytes_sent = process.io_counters().write_bytes
        	if bytes_sent > ssh_threshold:
            	print(f"SSH upload threshold exceeded for process {process.name()} with PID {conn.pid}.")
            	terminate_process(process, terminated_processes, blacklist)

def terminate_process(process, terminated_processes, blacklist):
	try:
    	if process.is_running():
        	print(f"Terminating process {process.name()} with PID {process.pid}.")
        	process.terminate()
        	process.wait(timeout=3)
        	if not process.is_running():
            	print("Process terminated successfully.")
            	# If possible, add the remote IP to the blacklist
            	for conn in psutil.net_connections(kind='inet'):
                	if conn.pid == process.pid and conn.raddr:
                    	add_to_blacklist(conn.raddr.ip)
        	else:
            	print("Forcing kill...")
            	process.kill()
        	terminated_processes.add(process.pid)
	except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.TimeoutExpired) as e:
    	print(f"Could not terminate process: {e}")
    	if process.is_running():
        	process.kill()
    	terminated_processes.add(process.pid)

def terminate_relevant_processes(terminated_processes, whitelisted_ips, blacklist):
	for conn in psutil.net_connections(kind='inet'):
    	if conn.status == 'ESTABLISHED' and conn.laddr and conn.raddr:
        	if conn.pid in terminated_processes or conn.raddr.ip in whitelisted_ips or conn.raddr.ip in blacklist:
            	continue
        	process = psutil.Process(conn.pid)
        	if process.is_running():
            	terminate_process(process, terminated_processes, blacklist)

if __name__ == "__main__":
	monitor_network_usage()
