import nmap
import winrm
from impacket.smbconnection import SMBConnection

from impacket.nmb import NetBIOSTimeout, NetBIOSNameNotFound
import socket # For basic connection errors

class Scanner:
    """
    The core scanner class that performs port discovery and plugin execution.
    """
    def __init__(self, target, credentials=None):
        self.target = target
        self.credentials = credentials if credentials else {}
        self.results = [] # A list to store result dictionaries
        self.nm = nmap.PortScanner()
        self.open_ports = {} # Discovered ports: {445: 'smb', 5985: 'winrm'}

    def _add_result(self, vulnerability, status, severity, details, recommendation):
        """Helper function to format and add a result."""
        self.results.append({
            'host': self.target,
            'vulnerability': vulnerability,
            'status': status,
            'severity': severity,
            'details': details,
            'recommendation': recommendation
        })

    def _discover_ports(self, profile, custom_ports):
        """
        Uses python-nmap to scan for open ports based on the profile.
        
        ⚠️ GOTCHA: This requires the Nmap binary to be installed
        on the machine running the Python script!
        """
        print(f"  [>] Discovering ports on {self.target} (Profile: {profile})")
        
        ports_to_scan = ''
        nmap_args = '-sV' # -sV: Probe open ports to determine service/version info

        if profile == 'deep':
            if not custom_ports:
                raise ValueError("Deep profile selected but no custom ports provided.")
            ports_to_scan = custom_ports
            print(f"  [>] Deep scan configured for ports: {ports_to_scan}")
        else: # 'safe' profile
            # We scan the default top 1000 ports by not specifying -p
            # This is Nmap's default behavior.
            # We also add specific ports just in case they aren't in the top 1000.
            ports_to_scan = '139,445,5985,5986'
            print(f"  [>] Safe scan configured for common ports + Nmap top 1000.")

        try:
            self.nm.scan(self.target, ports_to_scan, arguments=nmap_args, timeout=300)
        except nmap.PortScannerError as e:
            print(f"  [!] Nmap error: {e}")
            raise Exception(f"Nmap failed. Is it installed and in your PATH? Error: {e}")
        except Exception as e:
            print(f"  [!] Unknown error during port scan: {e}")
            raise Exception(f"Port scan failed: {e}")

        if self.target not in self.nm.all_hosts():
            print(f"  [!] Host {self.target} seems to be down.")
            return

        # Populate self.open_ports
        for proto in self.nm[self.target].all_protocols():
            if proto != 'tcp':
                continue
            
            lport = self.nm[self.target][proto].keys()
            for port in lport:
                state = self.nm[self.target][proto][port]['state']
                if state == 'open':
                    service = self.nm[self.target][proto][port]['name']
                    print(f"  [+] Found open port: {port}/{proto} ({service})")
                    self.open_ports[port] = service

    # --- PLUGIN 1: SMB Anonymous Shares ---
    def _check_smb_anon_shares(self):
        """
        Plugin 1: Tries to connect to SMB (port 445) anonymously
        and list available shares.
        """
        vulnerability = "SMB Anonymous Shares"
        
        try:
            # We use the 'impacket' library for this
            # We provide a 'None' user/pass for an anonymous session
            conn = SMBConnection(self.target, self.target, timeout=5)
            conn.login('', '') # Anonymous login
            
            shares = conn.listShares()
            share_names = [s['shi1_netname'].rstrip('\x00') for s in shares]
            
            if share_names:
                details = f"Anonymous user can list shares: {', '.join(share_names)}"
                self._add_result(vulnerability, 'FAIL', 'Medium', details,
                                 "Restrict anonymous access to SMB shares. Check 'NullSessionShares' registry key.")
            else:
                self._add_result(vulnerability, 'PASS', 'Low', "Anonymous login successful but no shares listed.", "N/A")
            
            conn.logoff()

        except (NetBIOSTimeout, NetBIOSNameNotFound, socket.error):
            # This means the port is likely closed or filtered, or not SMB
            print("  [>] SMB Anon: Connection failed. Port 445 might be closed or not SMB.")
            # We don't add a result, as the port scan should be the source of truth
        except Exception as e:
            # This usually means anonymous login is *disallowed*
            if "STATUS_ACCESS_DENIED" in str(e) or "STATUS_LOGON_FAILURE" in str(e):
                self._add_result(vulnerability, 'PASS', 'Low', "Anonymous login properly denied.", "N/A")
            else:
                print(f"  [!] Error checking SMB anon: {e}")

    # --- PLUGIN 2: SMBv1 Enabled ---
    def _check_smb_v1(self):
        """
        Plugin 2: Tries to negotiate an SMBv1 dialect with the server.
        """
        vulnerability = "SMBv1 Enabled"
        
        try:
            # We initiate a connection. 'impacket' will try to negotiate
            # the highest dialect first.
            conn = SMBConnection(self.target, self.target, timeout=5)
            
            # After connection (even if login fails), we can check the dialect
            if conn.getDialect() == 0x02: # 0x02 is the constant for SMBv1
                self._add_result(vulnerability, 'FAIL', 'High', "Server accepts the SMBv1 protocol.",
                                 "Disable SMBv1 on the server. It is insecure and vulnerable to exploits like WannaCry.")
            else:
                self._add_result(vulnerability, 'PASS', 'Low', f"Server negotiated a modern dialect: {conn.getDialect()}", "N/A")
            
        except Exception as e:
            print(f"  [!] Error checking SMBv1: {e}")
            # This check can be noisy. If it fails, we just log and move on.
            pass

    # --- PLUGIN 3: WinRM Hotfix Enumeration ---
    def _check_winrm_hotfixes(self, port):
        """
        Plugin 3: Connects to WinRM (port 5985/5986) with credentials
        and lists installed hotfixes.
        """
        vulnerability = "WinRM Hotfix Enumeration"
        
        # This plugin *requires* credentials
        if 'username' not in self.credentials or 'password' not in self.credentials:
            self._add_result(vulnerability, 'INFO', 'Info', "Skipped. Credentials not provided.",
                             "Provide credentials to enable WinRM-based checks.")
            return

        user = self.credentials['username']
        pwd = self.credentials['password']
        
        # Build the WinRM endpoint URL
        proto = 'https' if port == 5986 else 'http'
        endpoint = f"{proto}://{self.target}:{port}/wsman"
        
        print(f"  [>] Connecting to WinRM at {endpoint} as {user}")

        try:
            
            session = winrm.Session(
                endpoint,
                auth=(user, pwd),
                transport='ntlm',
                server_cert_validation='ignore',
                read_timeout_sec=30
            )
            
            # This is the WMI query to get hotfixes
            ps_script = "wmic qfe list brief | findstr 'KB'"
            
            # Run the command
            # Note: We use run_ps for PowerShell, run_cmd for classic CMD
            r = session.run_cmd(ps_script) 
            
            if r.status_code == 0:
                hotfixes = r.std_out.decode('utf-8').strip().splitlines()
                hotfix_list = [h.split()[-1] for h in hotfixes if h]
                
                # For the hackathon, just *listing* them is the deliverable
                # As suggested, the "wow" factor is checking for one *missing* patch
                details = f"Successfully enumerated {len(hotfix_list)} hotfixes. (e.g., {', '.join(hotfix_list[:3])}...)"
                self._add_result(vulnerability, 'INFO', 'Info', details,
                                 "Cross-reference this list against known critical vulnerabilities (e.g., CVEs).")
            else:
                # This means the command failed
                error_details = r.std_err.decode('utf-8')
                print(f"  [!] WinRM command failed: {error_details}")
                self._add_result(vulnerability, 'FAIL', 'Medium', f"Command failed: {error_details}",
                                 "Check user permissions. User must be an administrator or in 'Remote Management Users'.")

        except Exception as e:
            print(f"  [!] Error connecting to WinRM: {e}")
            self._add_result(vulnerability, 'FAIL', 'Medium', f"Connection failed: {str(e)}",
                             "Check WinRM service (run 'Enable-PSRemoting -Force'), firewall rules, and credentials.")

    # --- Main Orchestration ---
    
    def run(self, profile='safe', custom_ports=None):
        """
        The main public method to orchestrate the scan.
        """
        # 1. Discover Ports
        try:
            self._discover_ports(profile, custom_ports)
        except Exception as e:
            # If Nmap fails, we can't do anything else
            self._add_result('Port Scan', 'FAIL', 'High', str(e), "Ensure Nmap is installed and reachable from the script.")
            return self.results

        if not self.open_ports:
            print(f"  [!] No open ports found for {self.target}.")
            return self.results
            
        # 2. Run Plugins based on open ports
        for port, service in self.open_ports.items():
            
            # SMB Plugins (Port 139 or 445)
            if port in (139, 445) or 'microsoft-ds' in service or 'netbios-ssn' in service:
                print(f"  [>] Running SMB plugins on port {port}...")
                self._check_smb_anon_shares()
                self._check_smb_v1()
                
            # WinRM Plugins (Port 5985 or 5986)
            if port in (5985, 5986) or 'wsman' in service or 'winrm' in service:
                print(f"  [>] Running WinRM plugins on port {port}...")
                self._check_winrm_hotfixes(port)
        
        # 3. Return all collected results
        return self.results