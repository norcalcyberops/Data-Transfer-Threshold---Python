A script running in the background on the victim machine monitored the traffic and calculated how much data has been transferred. Once any process has uploaded more than 50 MB of data (our pre-defined threshold), the script kills the process via the process ID. The script then adds the IP associated with the killed process to a blacklist configuration file.

Here’s how it works to defend against potential SSH exploits: Monitoring SSH Traffic: The script uses psutil.net_connections to monitor all active connections on the system. It filters these connections to identify those that are established via SSH (typically using port 22).

Threshold-Based Monitoring: For every SSH connection, it checks the amount of data being sent through the connection. If the data exceeds a predefined threshold (ssh_threshold), this could indicate an attempt at data exfiltration.

Blacklisting IPs: Further, the script adds the IP address of the terminated connection to a blacklist. This prevents any future connections from the same IP, effectively blocking repeated attempts from a known malicious source.

Dynamic Updating: The script dynamically reloads the whitelist and blacklist from file storage, allowing for quick updates to the access control lists without needing to restart the script or lose its monitoring capabilities.

WEAKNESSES

    Performance Resource Consumption: Continuously monitoring network statistics and managing files (like whitelists and blacklists) in real-time can be resource-intensive, especially on systems with high network traffic or a large number of connections.

    Detection Evasion Advanced Evasion Techniques: Skilled attackers might use sophisticated methods to evade detection, such as slowly leaking data to stay below the threshold.

IP Spoofing: The script uses IP addresses to identify and block potentially malicious connections. IP spoofing could render the blacklist ineffective, as attackers might continually change their apparent source IP.

    Technical Limitations Lack of Contextual Awareness: There are currently no configurable application exclusions and all traffic is being logged across all applications. All data transfer from any application currently counts towards the data transfer threshold. There is no segmentation between applications.


