import socket
import ipaddress
import random
import time

from _tcppacket import TCPPacket, get_ip_header, get_tcp_header, check_response, ending_connection_robust, send_and_receive_packet, print_packet
from _tcp_rst_blocker import TCPRSTBlocker

class PortScanner:
    def __init__(self, host_ip, target_ip):

        # IP validity checking using ipaddress library
        try:
            host_ipobj = ipaddress.ip_address(host_ip)
            target_ipobj = ipaddress.ip_address(target_ip)
            self.host_ip = str(host_ipobj)
            self.target_ip = str(target_ipobj)
        except ValueError:
            print(f"❌ Invalid IP address: {ip}")
            return   

    def scan_ports(self, ports):

        for target_port in ports:
            if target_port == 0:
                continue
            try:
                # Create sockets
                sender_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
                sender_socket.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

                receiver_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
                # Random source port
                host_port = random.randint(1024, 65535)
                syn_packet_obj = TCPPacket("SYN", self.host_ip, self.target_ip, host_port, target_port)
                syn_packet = syn_packet_obj.get_packet()
                
                ip_header = get_ip_header(syn_packet)
                tcp_header = get_tcp_header(syn_packet, ip_header)

                #print(f"Scanning port {target_port} on {self.target_ip}")

                response_packet = send_and_receive_packet(syn_packet, sender_socket, receiver_socket, ip_header, tcp_header)
                
                check_response(sender_socket, self.host_ip, self.target_ip, host_port, target_port, response_packet)
            except PermissionError:
                print("❌ Error: Raw sockets require administrative privileges.")
                return
            except Exception as e:
                print(f"⚠️ Error scanning port {target_port}: {e}")
                return
            finally:
                sender_socket.close()
                receiver_socket.close()

    def close(self):
        try:
            self.tcp_rst_blocker.remove_rule()
            print("Firewall rule cleaned up.")
        except Exception as e:
            print(f"Error cleaning up firewall rule: {e}")
            

def get_host_ip():
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]

if __name__ == "__main__":

    host_ip = get_host_ip()
    # target_ip = "10.40.37.176"
    target_ip = input("Insert ip address to scan : ")

    port_scanner = PortScanner(host_ip, target_ip)
    ports = [port for port in range(1, 5500)]
    port = [5000]

    port_scanner.scan_ports(ports)