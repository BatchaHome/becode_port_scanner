import socket
import threading
import ipaddress
import random
import time
from queue import Queue

from _tcppacket import TCPPacket, get_ip_header, get_tcp_header, check_response, ending_connection_robust, send_and_receive_packet, print_packet
from _tcp_rst_blocker import TCPRSTBlocker

class PortScanner:
    def __init__(self, host_ip, target_ip, thread_count=10):
        self.host_ip = host_ip
        self.target_ip = target_ip
        self.thread_count = thread_count
        
        # Threading helpers
        self.queue = Queue()
        self.lock = threading.Lock()
        
        # Setup firewall rule to block outgoing RST packets
        try:
            self.tcp_rst_blocker = TCPRSTBlocker()
            self.tcp_rst_blocker.add_rule()
            time.sleep(1)  # Give the rule some time to apply
        
        except PermissionError:
            print("❌ Error: Raw sockets require administrative privileges.")
            raise
        
        except Exception as e:
            print(f"❌ Firewall rule setup failed: {e}")
            raise

    def _worker(self):
        while not self.queue.empty():
            target_port = self.queue.get()

            try:
                # Create sockets locally in the thread
                sender_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
                sender_socket.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
                receiver_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
                # Random source port
                host_port = random.randint(1024, 65535)
                syn_packet_obj = TCPPacket("SYN", self.host_ip, self.target_ip, host_port, target_port)
                syn_packet = syn_packet_obj.get_packet()
                
                ip_header = get_ip_header(syn_packet)
                print("test")
                tcp_header = get_tcp_header(syn_packet, ip_header)

                with self.lock:
                    print(f"Scanning port {target_port} on {self.target_ip}")

                response_packet = send_and_receive_packet(syn_packet, sender_socket, receiver_socket, ip_header, tcp_header)
                
                with self.lock:
                    check_response(sender_socket, self.host_ip, self.target_ip, host_port, target_port, response_packet)

            except Exception as e:
                with self.lock:
                    print(f"⚠️ Error scanning port {target_port}: {e}")
            finally:
                sender_socket.close()
                receiver_socket.close()
                self.queue.task_done()

    def scan_ports(self, ports):
        # Fill queue
        for port in ports:
            self.queue.put(port)

        threads = []
        for _ in range(min(self.thread_count, self.queue.qsize())):
            t = threading.Thread(target=self._worker)
            t.start()
            threads.append(t)

        # Wait for all to finish
        self.queue.join()

        for t in threads:
            t.join()

    def close(self):
        try:
            self.tcp_rst_blocker.remove_rule()
            print("Firewall rule cleaned up.")
        except Exception as e:
            print(f"Error cleaning up firewall rule: {e}")
            


if __name__ == "__main__":
    
    host_ip = "10.40.35.124"
    target_ip = "10.40.37.177"

    port_scanner = PortScanner(host_ip, target_ip)
    ports = [80, 5000, 433, 24]

    port_scanner.scan_ports(ports)