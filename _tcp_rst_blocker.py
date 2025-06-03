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
        print("\n🛑 Cleaning up firewall rules...")
        self.remove_rule()
        sys.exit(0)

    def _rule_exists(self):
        result = subprocess.run(
            ["sudo", "iptables", "-C", "OUTPUT",
             "-p", "tcp", "--tcp-flags", "RST", "RST",
             "-j", "DROP", "-m", "comment", "--comment", "BLOCK_RST"],
            capture_output=True, text=True
        )
        return result.returncode == 0
        
    def _add_linux_rule(self):
        try:
            print("➕ Ajout de la règle iptables pour bloquer les paquets RST sauf vers le port 5000...")

            # First, check if rule exists
            result = subprocess.run(
                ["sudo", "iptables", "-C", "OUTPUT",
                "-p", "tcp", "--tcp-flags", "RST", "RST", "!", "--dport", "5000",
                "-j", "DROP", "-m", "comment", "--comment", "BLOCK_RST_except_5000"],
                capture_output=True, text=True
            )

            if result.returncode == 0:
                print("ℹ️ Règle déjà présente. Pas besoin de la réajouter.")
                self.rule_added = True
                return

            # Add the rule
            cmd = [
                "sudo", "iptables", "-I", "OUTPUT", "1",
                "-p", "tcp", "--tcp-flags", "RST", "RST", "!",
                "--dport", "5000", "-j", "DROP",
                "-m", "comment", "--comment", "BLOCK_RST_except_5000"
            ]

            result = subprocess.run(cmd, capture_output=True, text=True)
            print("📤 stdout:", result.stdout.strip())
            print("⚠️ stderr:", result.stderr.strip())

            if result.returncode != 0:
                print("❌ Échec de l'ajout de la règle.")
                return

            print("✅ Règle ajoutée avec succès.")
            self.rule_added = True

        except subprocess.CalledProcessError as e:
            print(f"❌ Erreur lors de l'exécution de iptables : {e}")
            if e.stderr:
                print(f"🧨 Détail de l'erreur : {e.stderr.strip()}")

    def _remove_linux_rule(self):
        try:
            print("🧹 Suppression de la règle iptables...")

            cmd = [
                "sudo", "iptables", "-D", "OUTPUT",
                "-p", "tcp", "--tcp-flags", "RST", "RST", "!",
                "--dport", "5000", "-j", "DROP",
                "-m", "comment", "--comment", "BLOCK_RST_except_5000"
            ]

            result = subprocess.run(cmd, capture_output=True, text=True)
            print("📤 stdout:", result.stdout.strip())
            print("⚠️ stderr:", result.stderr.strip())

            if result.returncode == 0:
                print("✅ Règle supprimée avec succès")
                self.rule_added = False
            else:
                print("⚠️ La règle n’a pas été supprimée. Peut-être déjà absente.")
        except Exception as e:
            print(f"❌ Erreur lors de la suppression : {e}")
    # def _add_linux_rule(self):
    #     try:
    #         print("➕ Ajout de la règle iptables pour bloquer les paquets RST...")

    #         if self._rule_exists():
    #             print("ℹ️ Règle déjà présente. Pas besoin de la réajouter.")
    #             self.rule_added = True
    #             return

        #     cmd = [
        #         "sudo", "iptables", "-I", "OUTPUT", "1",
        #         "-p", "tcp",
        #         "--tcp-flags", "RST", "RST",
        #         "-j", "DROP",
        #         "-m", "comment", "--comment", "BLOCK_RST"
        #     ]

        #     result = subprocess.run(cmd, capture_output=True, text=True)
        #     print("📤 stdout:", result.stdout.strip())
        #     print("⚠️ stderr:", result.stderr.strip())

        #     if result.returncode != 0:
        #         print("❌ Échec de l'ajout de la règle.")
        #         return

        #     print("✅ Règle ajoutée. Vérification dans iptables...")
        #     verify_cmd = ["sudo", "iptables", "-L", "OUTPUT", "-n", "--line-numbers"]
        #     verify_result = subprocess.run(verify_cmd, capture_output=True, text=True)
        #     print("📜 iptables OUTPUT:")
        #     print(verify_result.stdout)

        #     if "BLOCK_RST" in verify_result.stdout:
        #         print("✅ Règle confirmée : 'BLOCK_RST' active.")
        #         self.rule_added = True
        #     else:
        #         print("⚠️ Règle NON trouvée. Elle n'est peut-être pas active.")

        # except subprocess.CalledProcessError as e:
        #     print(f"❌ Erreur lors de l'exécution de iptables : {e}")
        #     if e.stderr:
        #         print(f"🧨 Détail de l'erreur : {e.stderr.strip()}")

    # def _remove_linux_rule(self):
    #     try:
    #         print("🧹 Suppression de la règle iptables...")

    #         cmd = [
    #             "sudo", "iptables", "-D", "OUTPUT",
    #             "-p", "tcp", "--tcp-flags", "RST", "RST",
    #             "-j", "DROP", "-m", "comment", "--comment", "BLOCK_RST"
    #         ]

    #         result = subprocess.run(cmd, capture_output=True, text=True)
    #         print("📤 stdout:", result.stdout.strip())
    #         print("⚠️ stderr:", result.stderr.strip())

    #         if result.returncode == 0:
    #             print("✅ Règle supprimée avec succès")
    #             self.rule_added = False
    #         else:
    #             print("⚠️ La règle n’a pas été supprimée. Peut-être déjà absente.")
    #     except Exception as e:
    #         print(f"❌ Erreur lors de la suppression : {e}")

    def _add_macos_rule(self):
        pass  # Conservé tel quel, non modifié ici

    def _remove_macos_rule(self):
        pass

    def _add_windows_rule(self):
        pass

    def _remove_windows_rule(self):
        pass

    def test_rule(self):
        if self.current_os == "linux":
            try:
                result = subprocess.run(
                    ["sudo", "iptables", "-L", "OUTPUT", "-n"],
                    capture_output=True, text=True, check=True
                )
                if "BLOCK_RST" in result.stdout:
                    print("✅ Règle détectée (BLOCK_RST)")
                    return True
                else:
                    print("❌ Règle non trouvée dans iptables")
                    return False
            except Exception as e:
                print(f"⚠️ Impossible de vérifier la règle : {e}")
                return False
        return True

def test_blocker():
    print("🧪 Test du TCP RST Blocker...")

    blocker = TCPRSTBlocker()

    try:
        success = blocker.add_rule()
        if success:
            print("✅ Règle ajoutée avec succès")
            if blocker.test_rule():
                print("✅ Règle fonctionnelle")
            else:
                print("⚠️ La règle pourrait ne pas fonctionner correctement")

            time.sleep(2)
            blocker.remove_rule()
            print("✅ Test terminé")
        else:
            print("❌ Échec de l'ajout de la règle")
    except KeyboardInterrupt:
        print("\n⚠️ Test interrompu")
        blocker.remove_rule()

if __name__ == "__main__":
    test_blocker()