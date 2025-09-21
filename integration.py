import json
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

    # Split targets string into a list
    target_list = [ip.strip() for ip in targets.split(',')]
    
    all_results = []
    
    for target in target_list:
        if not target:
            continue
            
        print(f"[+] Scanning target: {target}")
        try:
            # Initialize our scanner class
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
    """
    This allows you to test your scanner from the command line.
    """
    print("--- [ RUNNING SCANNER IN TEST MODE ] ---")
    
   
    TARGET_IP = "192.168.56.101" # <--- ⚠️ CHANGE THIS
    
    # Credentials for WinRM hotfix scan
    TARGET_USER = "vagrant"      # <--- ⚠️ CHANGE THIS
    TARGET_PASS = "vagrant"      # <--- ⚠️ CHANGE THIS

    # ----------------------------------------
    
    # --- Test 1: Safe Scan (Uncredentialed) ---
    print("\n[TEST 1] Running SAFE scan (uncredentialed)...")
    safe_results = run_scan(
        targets=TARGET_IP,
        profile='safe'
    )
    print(json.dumps(safe_results, indent=2))

    # --- Test 2: Deep Scan (Credentialed) ---
    print("\n[TEST 2] Running DEEP scan with WinRM (credentialed)...")
    deep_results = run_scan(
        targets=TARGET_IP,
        profile='deep',
        custom_ports="445, 5985", # Custom port list
        username=TARGET_USER,
        password=TARGET_PASS
    )
    print(json.dumps(deep_results, indent=2))
    
    print("\n--- [ TEST COMPLETE ] ---")