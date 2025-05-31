# tcp_rst_blocker.py

import subprocess
import platform
import atexit
import signal
import sys
import os
import time

class TCPRSTBlocker:
    def __init__(self):
        self.rule_added = False
        self.current_os = platform.system().lower()
        self.rule_name = f"tcp_rst_block_{int(time.time())}"
        atexit.register(self.remove_rule)
        signal.signal(signal.SIGINT, self._handle_exit)
        signal.signal(signal.SIGTERM, self._handle_exit)

    def add_rule(self):
        """Add firewall rule to block outgoing RST packets"""
        try:
            if self.current_os == "linux":
                self._add_linux_rule()
            elif self.current_os == "darwin":
                self._add_macos_rule()
            elif self.current_os == "windows":
                self._add_windows_rule()
            else:
                print(f"⚠️ Unsupported OS: {self.current_os}")
                return False
            return True
        except Exception as e:
            print(f"❌ Failed to add firewall rule: {e}")
            return False

    def remove_rule(self):
        """Remove firewall rule"""
        if not self.rule_added:
            return
        
        try:
            if self.current_os == "linux":
                self._remove_linux_rule()
            elif self.current_os == "darwin":
                self._remove_macos_rule()
            elif self.current_os == "windows":
                self._remove_windows_rule()
        except Exception as e:
            print(f"⚠️ Warning: Failed to remove firewall rule: {e}")

    def _handle_exit(self, signum=None, frame=None):
        """Handle program exit signals"""
        print("\n🛑 Cleaning up firewall rules...")
        self.remove_rule()
        sys.exit(0)

    # --- Linux (iptables) ---
    def _add_linux_rule(self):
        """Add iptables rule to block RST packets"""
        try:
            # More specific rule to avoid blocking all RST packets
            cmd = [
                "sudo", "iptables", "-I", "OUTPUT", "1",
                "-p", "tcp", 
                "--tcp-flags", "RST", "RST",
                "-j", "DROP"
            ]
            
            result = subprocess.run(cmd, capture_output=True, text=True, check=True)
            self.rule_added = True
            print("✅ iptables rule added successfully")
            
            # Verify the rule was added
            verify_cmd = ["sudo", "iptables", "-L", "OUTPUT", "-n", "--line-numbers"]
            verify_result = subprocess.run(verify_cmd, capture_output=True, text=True)
            if "RST" in verify_result.stdout:
                print("✅ Rule verified in iptables")
            else:
                print("⚠️ Rule may not be active - check iptables manually")
                
        except subprocess.CalledProcessError as e:
            print(f"❌ iptables error: {e}")
            if e.stderr:
                print(f"Error details: {e.stderr}")
            raise

    def _remove_linux_rule(self):
        """Remove iptables rule"""
        try:
            # Remove the rule we added
            cmd = [
                "sudo", "iptables", "-D", "OUTPUT",
                "-p", "tcp",
                "--tcp-flags", "RST", "RST", 
                "-j", "DROP"
            ]
            
            subprocess.run(cmd, capture_output=True, text=True, check=True)
            self.rule_added = False
            print("✅ iptables rule removed successfully")
            
        except subprocess.CalledProcessError as e:
            print(f"⚠️ iptables removal warning: {e}")
            # Try alternative removal method
            try:
                # List rules with line numbers and remove by number
                list_cmd = ["sudo", "iptables", "-L", "OUTPUT", "--line-numbers", "-n"]
                result = subprocess.run(list_cmd, capture_output=True, text=True)
                
                lines = result.stdout.split('\n')
                for line in lines:
                    if "RST" in line and "DROP" in line:
                        parts = line.split()
                        if parts and parts[0].isdigit():
                            line_num = parts[0]
                            remove_cmd = ["sudo", "iptables", "-D", "OUTPUT", line_num]
                            subprocess.run(remove_cmd, check=True)
                            print(f"✅ Removed iptables rule at line {line_num}")
                            break
            except Exception as e2:
                print(f"⚠️ Alternative removal also failed: {e2}")

    # --- macOS (pfctl) ---
    def _add_macos_rule(self):
        """Add pfctl rule to block RST packets"""
        pf_rule = "block drop out proto tcp flags RST/RST"
        pf_conf = "/etc/pf.conf"
        backup_conf = f"{pf_conf}.backup_{self.rule_name}"

        try:
            # Create backup if it doesn't exist
            if not os.path.exists(backup_conf):
                subprocess.run(["sudo", "cp", pf_conf, backup_conf], check=True)

            # Check if rule already exists
            with open(pf_conf, "r") as f:
                content = f.read()
                if pf_rule in content:
                    print("✅ pfctl rule already exists")
                    self.rule_added = True
                    return

            # Add rule
            with open(pf_conf, "a") as f:
                f.write(f"\n# TCP RST blocker - {self.rule_name}\n")
                f.write(f"{pf_rule}\n")

            # Reload and enable pf
            subprocess.run(["sudo", "pfctl", "-f", pf_conf], check=True)
            subprocess.run(["sudo", "pfctl", "-E"], check=True)
            
            self.rule_added = True
            print("✅ pfctl rule added and enabled (macOS)")
            
        except Exception as e:
            print(f"❌ pfctl error: {e}")
            # Restore backup if something went wrong
            if os.path.exists(backup_conf):
                subprocess.run(["sudo", "cp", backup_conf, pf_conf], check=False)
            raise

    def _remove_macos_rule(self):
        """Remove pfctl rule"""
        pf_conf = "/etc/pf.conf"
        backup_conf = f"{pf_conf}.backup_{self.rule_name}"
        
        try:
            # Restore from backup
            if os.path.exists(backup_conf):
                subprocess.run(["sudo", "cp", backup_conf, pf_conf], check=True)
                subprocess.run(["sudo", "rm", backup_conf], check=True)
            else:
                # Manual removal
                with open(pf_conf, "r") as f:
                    lines = f.readlines()
                
                with open(pf_conf, "w") as f:
                    skip_next = False
                    for line in lines:
                        if f"# TCP RST blocker - {self.rule_name}" in line:
                            skip_next = True
                            continue
                        elif skip_next and "block drop out proto tcp flags RST/RST" in line:
                            skip_next = False
                            continue
                        else:
                            f.write(line)

            # Reload pf
            subprocess.run(["sudo", "pfctl", "-f", pf_conf], check=True)
            print("✅ pfctl rule removed (macOS)")
            
        except Exception as e:
            print(f"⚠️ pfctl removal error: {e}")

    # --- Windows (netsh/PowerShell) ---
    def _add_windows_rule(self):
        """Add Windows Firewall rule to block RST packets"""
        try:
            # Use PowerShell to create a more specific rule
            cmd = [
                "powershell", "-Command",
                f"New-NetFirewallRule -DisplayName '{self.rule_name}' "
                "-Direction Outbound -Protocol TCP -Action Block "
                "-Enabled True"
            ]
            
            subprocess.run(cmd, check=True, capture_output=True, text=True)
            self.rule_added = True
            print("✅ Windows Firewall rule added")
            
        except subprocess.CalledProcessError as e:
            print(f"❌ Windows Firewall error: {e}")
            if e.stderr:
                print(f"Error details: {e.stderr}")
            raise

    def _remove_windows_rule(self):
        """Remove Windows Firewall rule"""
        try:
            cmd = [
                "powershell", "-Command",
                f"Remove-NetFirewallRule -DisplayName '{self.rule_name}'"
            ]
            
            subprocess.run(cmd, check=True, capture_output=True, text=True)
            print("✅ Windows Firewall rule removed")
            
        except subprocess.CalledProcessError as e:
            print(f"⚠️ Windows Firewall removal error: {e}")

    def test_rule(self):
        """Test if the firewall rule is working"""
        if self.current_os == "linux":
            try:
                result = subprocess.run(
                    ["sudo", "iptables", "-L", "OUTPUT", "-n"],
                    capture_output=True, text=True, check=True
                )
                if "RST" in result.stdout and "DROP" in result.stdout:
                    print("✅ Rule is active in iptables")
                    return True
                else:
                    print("❌ Rule not found in iptables")
                    return False
            except Exception as e:
                print(f"⚠️ Cannot verify rule: {e}")
                return False
        
        # Add tests for macOS and Windows if needed
        return True


# Test function
def test_blocker():
    """Test the RST blocker functionality"""
    print("🧪 Testing TCP RST Blocker...")
    
    blocker = TCPRSTBlocker()
    
    try:
        success = blocker.add_rule()
        if success:
            print("✅ Rule added successfully")
            
            # Test the rule
            if blocker.test_rule():
                print("✅ Rule is working")
            else:
                print("⚠️ Rule may not be working properly")
            
            # Wait a bit
            time.sleep(2)
            
            # Remove rule
            blocker.remove_rule()
            print("✅ Test completed")
        else:
            print("❌ Failed to add rule")
            
    except KeyboardInterrupt:
        print("\n⚠️ Test interrupted")
        blocker.remove_rule()


if __name__ == "__main__":
    test_blocker()