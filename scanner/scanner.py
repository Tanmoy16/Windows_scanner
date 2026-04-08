import socket
import concurrent.futures
import winrm
# --- Import fixes applied ---
from impacket.smbconnection import SMBConnection
from impacket.nmb import NetBIOSTimeout # Fixed import
import socket 

class Scanner:
    """
    The core scanner class that performs port discovery and plugin execution.
    """
    def __init__(self, target, credentials=None):
        self.target = target
        self.credentials = credentials if credentials else {}
        self.results = [] # A list to store result dictionaries
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
        Uses Python's built-in socket library to scan for open ports.
        This completely eliminates the need for an external Nmap installation.
        """
        print(f"  [>] Discovering ports on {self.target} (Profile: {profile})")
        
        target_ports = []

        if profile == 'deep':
            if not custom_ports:
                raise ValueError("Deep profile selected but no custom ports provided.")
            print(f"  [>] Deep scan configured for ports: {custom_ports}")
            # Parse custom ports (e.g. "80,443", "1-1000", or "80")
            for p in custom_ports.split(','):
                p = p.strip()
                if '-' in p:
                    start, end = map(int, p.split('-'))
                    target_ports.extend(range(start, end + 1))
                else:
                    target_ports.append(int(p))
        else: # 'safe' profile
            print(f"  [>] Safe scan configured for common ports.")
            target_ports = [139, 445, 3389, 5985, 5986]

        # Simple port to service mapping since we aren't using Nmap anymore
        service_map = {
            139: 'netbios-ssn',
            445: 'microsoft-ds',
            3389: 'ms-wbt-server',
            5985: 'wsman',
            5986: 'wsman-ssl'
        }

        # Multi-threaded port scanner for speed
        def scan_port(port):
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(1.5) # 1.5 second timeout
                if s.connect_ex((self.target, port)) == 0:
                    service = service_map.get(port, 'tcp')
                    print(f"  [+] Found open port: {port}/tcp ({service})")
                    return port, service
            return None, None

        with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
            futures = [executor.submit(scan_port, port) for port in target_ports]
            for future in concurrent.futures.as_completed(futures):
                port, service = future.result()
                if port:
                    self.open_ports[port] = service

    # --- PLUGIN 1: SMB Anonymous Shares ---
    def _check_smb_anon_shares(self):
        """
        Plugin 1: Tries to connect to SMB (port 445) anonymously
        and list available shares.
        """
        vulnerability = "SMB Anonymous Shares"
        
        try:
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

        except (NetBIOSTimeout, socket.error): # Fixed except block
            print("  [>] SMB Anon: Connection failed. Port 445 might be closed or not SMB.")
        except Exception as e:
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
            conn = SMBConnection(self.target, self.target, timeout=5)
            
            # --- Fixed hardcoded value ---
            # 0x02 is the constant for the SMBv1 dialect
            if conn.getDialect() == 0x02: 
                self._add_result(vulnerability, 'FAIL', 'High', "Server accepts the SMBv1 protocol.",
                                 "Disable SMBv1 on the server. It is insecure and vulnerable to exploits like WannaCry.")
            else:
                self._add_result(vulnerability, 'PASS', 'Low', f"Server negotiated a modern dialect: {conn.getDialect()}", "N/A")
            
        except Exception as e:
            print(f"  [!] Error checking SMBv1: {e}")
            pass

    # --- PLUGIN 3: WinRM Hotfix Enumeration (Upgraded) ---
    def _check_winrm_hotfixes(self, port):
        """
        Plugin 3: Connects to WinRM and checks if a specific
        critical patch (KB5034123) is installed.
        """
        vulnerability = "Missing Critical Patch (KB5034123)"

        if 'username' not in self.credentials or 'password' not in self.credentials:
            self._add_result(vulnerability, 'INFO', 'Info', "Skipped. Credentials not provided.",
                             "Provide credentials to enable WinRM-based checks.")
            return

        user = self.credentials['username']
        pwd = self.credentials['password']
        
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
            
            # --- NEW UPGRADED LOGIC ---
            # We check for a specific patch, e.g., KB5034123 (a 2024 security update)
            ps_script = "wmic qfe list brief | findstr 'KB5034123'"
            
            r = session.run_cmd(ps_script) 
            
            if r.status_code == 0:
                # If status_code is 0, 'findstr' FOUND the patch. This is a PASS.
                details = "Critical security patch KB5034123 is installed."
                self._add_result(vulnerability, 'PASS', 'Low', details, "N/A")
            else:
                # If status_code is not 0, 'findstr' DID NOT find the patch. This is a FAIL.
                details = "Host is missing the critical security patch KB5034123."
                self._add_result(vulnerability, 'FAIL', 'Critical', details,
                                 "Install the latest Windows security updates immediately.")

        except Exception as e:
            print(f"  [!] Error connecting to WinRM: {e}")
            self._add_result("WinRM Scan", 'FAIL', 'Medium', f"Connection failed: {str(e)}",
                             "Check WinRM service (run 'Enable-PSRemoting -Force'), firewall rules, and credentials.")
    # --- PLUGIN 4: Open RDP Access ---
    def _check_rdp_open(self):
        """
        Plugin 4: Checks if the RDP port (3389) is open.
        The 'run' engine only calls this if the port is found.
        """
        self._add_result(
            vulnerability="Open RDP Access",
            status='FAIL',
            severity='High',
            details="Port 3389 (Remote Desktop) is open to the network.",
            recommendation="Ensure RDP is not exposed to the internet. Restrict access to specific, trusted IPs or require a VPN."
        )

    # --- PLUGIN 5: Weak SMB Signing ---
    def _check_smb_signing(self):
        """
        Plugin 5: Checks if the SMB server enforces message signing.
        """
        vulnerability = "SMB Signing Disabled"
        try:
            # This check just negotiates, it doesn't need to log in
            conn = SMBConnection(self.target, self.target, timeout=5)

            if not conn.isSigningRequired():
                self._add_result(
                    vulnerability=vulnerability,
                    status='FAIL',
                    severity='Medium',
                    details="The SMB server does not require message signing, making it vulnerable to man-in-the-middle attacks.",
                    recommendation="Enable 'RequireSecuritySignature' in the server's security policy."
                )
            else:
                self._add_result(
                    vulnerability=vulnerability,
                    status='PASS',
                    severity='Low',
                    details="SMB message signing is correctly enforced.",
                    recommendation="N/A"
                )
            # We don't need to logoff() since we didn't login()
        except Exception as e:
            print(f"  [!] Error checking SMB signing: {e}")

    # --- Main Orchestration ---
    
    # --- Main Orchestration ---
    
    def run(self, profile='safe', custom_ports=None, enabled_plugins=None):
        """
        The main public method to orchestrate the scan.
        """
        try:
            self._discover_ports(profile, custom_ports)
        except Exception as e:
            self._add_result('Port Scan', 'FAIL', 'High', str(e), "Ensure Nmap is installed and reachable from the script.")
            return self.results

        if not self.open_ports:
            print(f"  [!] No open ports found for {self.target}.")
            return self.results

        # Flags to ensure plugins only run once per host
        smb_scanned = False
        winrm_scanned = False
        rdp_scanned = False

        # This is the "Plugin Engine"
        for port, service in self.open_ports.items():

            # Run SMB plugins (Check if we haven't scanned SMB yet)
            if (port in (139, 445) or 'microsoft-ds' in service or 'netbios-ssn' in service) and not smb_scanned:
                print(f"  [>] Running SMB plugins on port {port}...")
                if enabled_plugins is None or enabled_plugins.get('smb_anon', True):
                    self._check_smb_anon_shares()
                if enabled_plugins is None or enabled_plugins.get('smb_v1', True):
                    self._check_smb_v1()
                if enabled_plugins is None or enabled_plugins.get('smb_signing', True):
                    self._check_smb_signing()
                smb_scanned = True # Mark as done

            # Run WinRM plugin (Check if we haven't scanned WinRM yet)
            if (port in (5985, 5986) or 'wsman' in service or 'winrm' in service) and not winrm_scanned:
                print(f"  [>] Running WinRM plugins on port {port}...")
                if enabled_plugins is None or enabled_plugins.get('winrm_hotfix', True):
                    self._check_winrm_hotfixes(port)
                winrm_scanned = True # Mark as done

            # Run RDP plugin (Check if we haven't scanned RDP yet)
            if (port == 3389 or 'ms-wbt-server' in service) and not rdp_scanned:
                print(f"  [>] Running RDP plugins on port {port}...")
                if enabled_plugins is None or enabled_plugins.get('rdp_open', True):
                    self._check_rdp_open()
                rdp_scanned = True # Mark as done

        return self.results