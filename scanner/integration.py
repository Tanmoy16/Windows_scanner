import json
from .scanner import Scanner 
import json
import sys
import argparse
from .scanner import Scanner

def run_scan(targets, profile, custom_ports=None, username=None, password=None):
    """
    Acts as the main bridge between the web UI and the backend scanner.

    :param targets: A string of target IPs, comma-separated.
    :param profile: A string, either 'safe' or 'deep'.
    :param custom_ports: A string of ports, e.g., "80,443" (only used for 'deep' profile).
    :param username: Optional username for credentialed scans (WinRM).
    :param password: Optional password for credentialed scans (WinRM).
    :return: A list of result dictionaries.
    """
    print(f"[+] Starting scan job. Profile: {profile}, Targets: {targets}")
    
    
    creds = None
    if username and password:
        creds = {
            'username': username,
            'password': password
        }

  
    target_list = [ip.strip() for ip in targets.split(',')]
    
    all_results = []
    
    for target in target_list:
        if not target:
            continue
            
        print(f"[+] Scanning target: {target}")
        try:
            
            s = Scanner(target, creds)
            
            
            results = s.run(
                profile=profile,
                custom_ports=custom_ports
            )
            
            all_results.extend(results)
            
        except Exception as e:
            print(f"[!] Error scanning {target}: {e}")
            # Add an error result to the report
            all_results.append({
                'host': target,
                'vulnerability': 'Scan Error',
                'status': 'FAIL',
                'severity': 'Unknown',
                'details': str(e),
                'recommendation': 'Check host connectivity and scanner permissions.'
            })

    print(f"[+] Scan job finished. Found {len(all_results)} results.")
    return all_results
if __name__ == "__main__":
    # --- This part makes it a runnable CLI script ---
    
    parser = argparse.ArgumentParser(description="Agentless Windows Vulnerability Scanner - CLI Runner")
    
    parser.add_argument("-t", "--targets", required=True, 
                        help="Target IPs, comma-separated (e.g., 192.168.1.100)")
    parser.add_argument("-p", "--profile", choices=['safe', 'deep'], default='safe', 
                        help="Scan profile: 'safe' (default) or 'deep'")
    parser.add_argument("--ports", 
                        help="Custom ports for 'deep' scan (e.g., 80,443,5985)")
    parser.add_argument("-u", "--user", 
                        help="Username for credentialed (WinRM) scans")
    parser.add_argument("-w", "--password", 
                        help="Password for credentialed (WinRM) scans")
    
    args = parser.parse_args()
    
    if args.profile == 'deep' and not args.ports:
        print("Error: 'Deep' profile requires the --ports argument.")
        sys.exit(1)
        
    print(f"[+] Starting CLI scan on {args.targets}...")
    
    # Call the main function from this file
    results = run_scan(
        targets=args.targets,
        profile=args.profile,
        custom_ports=args.ports,
        username=args.user,
        password=args.password
    )
    
    # Print the results as clean JSON
    print("\n--- [ SCAN COMPLETE ] ---")
    print(json.dumps(results, indent=2))

