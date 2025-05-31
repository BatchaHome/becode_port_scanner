import socket
import struct
import random
import time
from tcp_rst_blocker import TCPRSTBlocker

"""
1 - IP handling (input validation, etc)
2 - create socket to send raw SYN packet and another to receive packet from remote host -nonblocking-
3 - function for TCP packet : creating IP headers, TCP headers + TCP checksum (used to check for integrity of data through the connection process)
4 - creating the TCP SYN packet
5 - sending the packet
6 - receive the response (either nothing or the SYN-ACK package)
7 - sending the TCP RST packet - to close and not connect
8 - Interpret the flag from answer
9 - make the loop on each port

10 - do not forget for exception handling (errors)
11 - write reports
"""

class TCPPacket():
    """
    A class that creates an IP and TCP packet,
    depending on the mode (SYN or RST by default) and the source and destination IPs
    It will create a TCP header and encapsulate it into a IP header 
    """

    def __init__(self, mode, source_ip, destination_ip, source_port, destination_port, seq_num=0, ack_num=0):

        self._mode =  0x02 if mode == "SYN" else 0x14 # SYN or RST/ACK
        self._ip_saddr = socket.inet_aton(source_ip)  # need for exception handling ?
        self._ip_daddr = socket.inet_aton(destination_ip)
        self._sourceport = source_port
        self._destinationport = destination_port
        self._seq_num = seq_num
        self._ack_num = ack_num

        # creation of the SYN packet
        self._syn_packet = None
        self.create_tcp_syn_packet()

    def get_syn_packet(self):
        return self._syn_packet

    def create_tcp_syn_packet(self):

        ip_header = self.get_IPheader()
        tcp_header = self.get_TCPheader()
        self._syn_packet = ip_header + tcp_header

    def get_IPheader(self):

        """ 
        Our IP header is 20bytes long :
        5 words of 32bits(4bytes) = 160bits (20bytes)
        """

        ##########################################################################################
        # First 32bits word ----------------------------------------------------------------------
        ip_ver = 4                              # version(4bits) -> generally 0100 for ipV4
        ip_ihl = 5                              # header-length(4bits) -> how many 32bits words
        ip_tos = 0                              # TypeOfService(8bits) -> for special treatment like prioritizing. unused here
        ip_tot_len = 20 + 20                    # IP header(5x32bits) + TCP header(5x32bits) = 40bytes
        
        # bitshifting operation to gather the shared byte for packing
        # ip_ver = 0100  &  ip_ihl = 0101
        # so ip_ver_ihl = (01000000) + 0101 = 01000101
        ip_ver_ihl = (ip_ver << 4) + ip_ihl

        # Second 32bits word ---------------------------------------------------------------------
        ip_id = random.randint(0, 65535)   if self._mode == 0x02 else 666   # specific ID (16bits). Used for fragmentation, no use here
        ip_flag = 0                             # Control flag (3bits). Reserved (0), no frag
        ip_frag_off = 0                         # Fragment Offset(13bits). No need here (0), no frag
        
        # here we could use bitshifting for ip_flag and ip_frag_off but each are zero so no need

        # Third 32bits word ----------------------------------------------------------------------
        ip_ttl = 64                             # timetolive(8bits). Number of hops*
        ip_proto = socket.IPPROTO_TCP           # protocol (8bits)
        ip_check = 0                            # headerChecksum(16bits). Not used (TCP )

        # Fourth 32bits word ---------------------------------------------------------------------
        ip_saddr = self._ip_saddr               # Binary IP adress(32bits or 4 x 8bytes)

        # Fifth 32bits word ----------------------------------------------------------------------
        ip_daddr = self._ip_daddr               # Binary IP adress(32bits or 4 x 8bits)
        ##########################################################################################


        # Packing up the header
        # ! = specifyng big-endian byte order  |  B = 1byte  |  H = 2 bytes  |  4s = 4bytes string
        ip_header = struct.pack('!BBHHHBBH4s4s', 
            ip_ver_ihl, ip_tos, ip_tot_len, ip_id, ip_frag_off, 
            ip_ttl, ip_proto, ip_check, ip_saddr, ip_daddr)

        return ip_header


    def get_TCPheader(self):
        
        """ 
        Our TCP header is 20bytes long :
        5 words of 32bits(4bytes) = 160bits (20bytes)
        """

        ##########################################################################################
        # First 32bits word ----------------------------------------------------------------------
        tcp_source_port = self._sourceport              # (16bits)
        tcp_destination_port = self._destinationport    # (16bits)

        # Second 32bits word ----------------------------------------------------------------------
        tcp_seq = random.randint(0, 4294967295) if self._mode == 0x02 else self._seq_num        # sequence number(32bits) how to choose one ?
        # counter number to check number of sent bytes
        # here the initial sequence number (ISN), consumes 1 sequence number
        
        # Third 32bits word ----------------------------------------------------------------------
        tcp_ack_seq = 0 if self._mode == 0x02 else self._ack_num                      # acknowledgment number (32bits). Used for ACK flag
        # counter number to check number of received bytes

        # Fourth 32bits word ----------------------------------------------------------------------
        tcp_doff = 5                                    # data offset(4bits). number of 32bitswords, variable due to Options
        tcp_reserved = 0                                # reserved sapce(4bits)
        # bit shifting for the shared byte
        tcp_doff_res = (tcp_doff << 4) + tcp_reserved

        tcp_flags = self._mode                          # either SYN or RST (8bits)
        tcp_window = socket.htons(5840)                 # (16bits) next packet's sizelimit (in receive mode)

        # Fifth 32bits word ----------------------------------------------------------------------
        tcp_check = 0                                   # checksum value(16bits)
        tcp_urg_ptr = 0                                 # urgent ptr (16bits)
        ##########################################################################################


        # Packing up the header before checksum
        # ! = specifyng big-endian byte order  |  B = 1byte  |  H = 2 bytes  |  4s = 4bytes string
        tcp_header = struct.pack('!HHLLBBHHH', 
            tcp_source_port, tcp_destination_port, tcp_seq, tcp_ack_seq, 
            tcp_doff_res, tcp_flags, tcp_window, tcp_check, tcp_urg_ptr)

        # Creating Pseudo-Header for checksum.
        # PH must have essentials elements in this order : IPs source & destination - Fixed 8bits (padding) - protocol - TCP length
        # Then check sum must be used with [pseudo-header + tcp-header + tcp-body (empty in our case)]
        padding = 0                     # 8bits
        protocol = socket.IPPROTO_TCP   # 8bits
        tcp_length = len(tcp_header)    # 16bits

        pseudo_header = struct.pack('!4s4sBBH', 
            self._ip_saddr, self._ip_daddr, padding, protocol, tcp_length)

        pseudo_packet = pseudo_header + tcp_header
        tcp_check = self.checksum(pseudo_packet) # calling the checksum function

        # Cretaing the header with checksum
        tcp_header = struct.pack('!HHLLBBHHH',
            tcp_source_port, tcp_destination_port, tcp_seq, tcp_ack_seq, 
            tcp_doff_res, tcp_flags, tcp_window, tcp_check, tcp_urg_ptr)

        return tcp_header

    def checksum(self, data):

        # data = 32bytes : 12bytes(pseudo header) + 20bytes (tcp header)
        # we need to split data in chunks of 2bytes. So divided by 16. Then do a sum of all words
        struct_str = "!%dH" % (len(data)//2) # for now let's keep it 16 and assume size will be the same both directions
        words = struct.unpack(struct_str, data)
        checksum = sum(words)

        # now if the sum exceeds 2^16, we have to handle the overflow
        while checksum > (2**16 -1):
            checksum = (checksum & 0xFFFF) + (checksum >> 16) # 

        print(f"After overlap, sum is {checksum}")

        final_checksum = ~checksum & 0xFFFF
        print(f"final is {final_checksum}")

        return final_checksum

    def compare_checksum(self, checksum):
        # en chantier :(
        pass




def print_header(header):
     for key in header:
          print(f"{key}: {header[key]}")
          
def print_packet(ip_header, tcp_header):
     print(f"\nIP Header:\n")
     print_header(ip_header)
     print(f"\nTCP Header:\n")
     print_header(tcp_header)




def get_ip_header(packet):
    ip_header = {}
    version_ihl = packet[0]         # Premier octet
    ihl = version_ihl & 0x0F        # Garde seulement les 4 derniers bits
    ip_header['ip_header_length'] = ihl * 4      # Convertit en octets
    
    header = struct.unpack('!BBHHHBBH4s4s', packet[:ip_header['ip_header_length']])
    

    ip_header["version_ihl"] = header[0]
    ip_header["version"] = ip_header["version_ihl"] >> 4
    ip_header["ihl"] = ip_header["version_ihl"] & 0x0F
    ip_header["tos"] = header[1]
    ip_header["total_length"] = header[2]
    ip_header["identification"] = header[3]
    ip_header["flags_offset"] = header[4]
    ip_header["ttl"] = header[5]
    ip_header["protocol"] = header[6]
    ip_header["checksum"] = header[7]
    ip_header["source_ip"] = socket.inet_ntoa(header[8])
    ip_header["dest_ip"] = socket.inet_ntoa(header[9])

    return ip_header




def get_tcp_header(packet, ip_header):

    header = struct.unpack('!HHLLBBHHH', packet[ip_header["ip_header_length"]:ip_header["ip_header_length"] + 20])
    tcp_header = {}

    tcp_header["source_port"] = header[0]
    tcp_header["dest_port"] = header[1]
    tcp_header["sequence"] = header[2]
    tcp_header["ack"] = header[3]
    tcp_header["data_offset_reserved"] = header[4]
    tcp_header["flags"] = header[5]
    tcp_header["window"] = header[6]
    tcp_header["checksum"] = header[7]
    tcp_header["urg_ptr"] = header[8]
    tcp_header["data_offset"] = (tcp_header["data_offset_reserved"] >> 4) * 4
    tcp_header["flag_bits"] = {
        'URG': (tcp_header["flags"] & 0x20) >> 5,
        'ACK': (tcp_header["flags"] & 0x10) >> 4,
        'PSH': (tcp_header["flags"] & 0x08) >> 3,
        'RST': (tcp_header["flags"] & 0x04) >> 2,
        'SYN': (tcp_header["flags"] & 0x02) >> 1,
        'FIN': (tcp_header["flags"] & 0x01),
    }

    return tcp_header





def check_response(source_ip, dest_ip, source_port, dest_port, packet):
    ip_header = get_ip_header(packet)
    tcp_header = get_tcp_header(packet, ip_header)

    print("=========================== PACKET WE RECEIVED ================================")
    print_packet(ip_header, tcp_header)  
     
    if ip_header["dest_ip"] == source_ip:
        if ip_header["source_ip"] == dest_ip:
            if tcp_header["dest_port"] == source_port:
                if tcp_header["source_port"] == dest_port:
                    
                    if tcp_header["flag_bits"]["ACK"] and tcp_header["flag_bits"]["SYN"]:
                        print(f"Port {dest_port} on {dest_ip} IPv4 adress is OPEN")
                        return tcp_header['sequence'], tcp_header['ack']
                    else:
                        print(f"Port {dest_port} on {dest_ip} IPv4 adress is CLOSE")
                    
                else:
                    print(f"Wrong port dest")
            else:
                print(f"Wrong port received")
        else:
            print(f"Wrong ip dest")
    else:
        print(f"Wrong ip received")

    return None
        




    
def	send_and_receive_packet(packet, sender_socket, receiver_socket, ip_header, tcp_header):
    
    try:
        sender_socket.sendto(packet, (ip_header['dest_ip'], 0))
        print(f"SYN Packet send to {ip_header['dest_ip']} from {tcp_header['dest_port']} port",
            f"from host {ip_header['source_ip']} from port {tcp_header['source_port']}")
    except Exception as e:
        print(f"ERROR SENDING SYN PACKET: ", e)

    try:
        packet_received = receiver_socket.recv(1024)
        print(f"Respond packet received ...")
    except Exception as e:
        print(f"ERROR RECEIVING PACKET: ", e)

    return packet_received



def send_rst_normal_socket(dest_ip, dest_port, source_port, seq, ack):
    """Alternative avec socket normal pour éviter les problèmes de permissions"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.bind(('', source_port))
        sock.connect((dest_ip, dest_port))
        sock.close()  # Envoi automatique du RST
        print("RST sent via normal socket")
    except Exception as e:
        print(f"RST via normal socket failed: {e}")



# def	ending_connection(packet, sender_socket):
#     ip_header = get_ip_header(packet)
#     tcp_header = get_tcp_header(packet, ip_header)

#     print("=========================== RST PACKET WE SEND ================================")
#     print_packet(ip_header, tcp_header)  


#     print(f"Socket permissions: {sender_socket.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR)}")
#     try:
#         sender_socket.sendto(packet, (ip_header['dest_ip'], 0))
#         print(f"RST Packet send to {ip_header['dest_ip']} from {tcp_header['dest_port']} port",
#             f"from host {ip_header['source_ip']} from port {tcp_header['source_port']}")
#     except Exception as e:
#         print(f"ERROR SENDING RST PACKET: ", e)
#         print("Trying Force Brute sending RST")
#         """Alternative avec socket normal pour éviter les problèmes de permissions"""
#         try:
#             sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
#             sock.bind(('', tcp_header['source_port']))
#             sock.connect((ip_header['dest_ip'], tcp_header['dest_port']))
#             sock.close()  # Envoi automatique du RST
#             print("RST sent via normal socket")
#         except Exception as e:
#             print(f"RST via normal socket failed: {e}")


def ending_connection_robust(packet, sender_socket, dest_ip):
    """Version robuste qui gère l'échec du RST"""
    
    print("=== TENTATIVE ENVOI RST ===")
    try:
        # Votre code RST existant
        sender_socket.sendto(packet, (dest_ip, 0))
        print("✅ RST envoyé avec succès")
        return True
        
    except PermissionError as e:
        print(f"❌ RST bloqué par le système: {e}")
        print("   → Connexion fermée par timeout côté serveur")
        
        # Alternative: fermeture brutale du socket
        try:
            sender_socket.shutdown(socket.SHUT_RDWR)
            print("✅ Socket fermé brutalement")
        except:
            pass
        
        return False
    
    except Exception as e:
        print(f"❌ Autre erreur RST: {e}")
        return False


          






vm_ip = "192.168.1.55"
mac_ip = "192.168.1.53"

source_ip = vm_ip
dest_ip = mac_ip
source_port = random.randint(1024, 65535)
dest_port = 5000

tcp_rst_blocker = TCPRSTBlocker()
tcp_rst_blocker.add_rule()
time.sleep(1) # Give time for rule to take effect


"""
    ===================== CREATION OF SYN PACKET =====================================
"""
syn_packet = TCPPacket("SYN", source_ip, dest_ip, source_port, dest_port)
syn_packet = syn_packet.get_syn_packet()
print(f"SYN Packet created ...")
ip_header_syn_packet = get_ip_header(syn_packet)
tcp_header_syn_packet = get_tcp_header(syn_packet, ip_header_syn_packet)

"""
======================================================================================
"""


print("=========================== SYN PACKET WE SENT ================================")
print_packet(ip_header_syn_packet, tcp_header_syn_packet)  

# Raw socket
try:
    sender_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
    sender_socket.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    print(f"Sender Socket created...")
except Exception as e:
    print("ERROR CREATING SENDER SOCKET: ", e)

try:
    receiver_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
    print(f"Receiver Socket created...")
except Exception as e:
    print("ERROR CREATING RECEIVER SOCKET: ", e)

packet_received = send_and_receive_packet(syn_packet, sender_socket, receiver_socket, 
                                              ip_header_syn_packet, tcp_header_syn_packet)



seq_num, ack_num = check_response(source_ip, dest_ip, source_port, dest_port, packet_received)

if seq_num and ack_num:
    """
        ===================== CREATION OF RST PACKET =====================================
    """
    rst_packet = TCPPacket("RST", source_ip, dest_ip, source_port, dest_port, ack_num, seq_num + 1)
    rst_packet = rst_packet.get_syn_packet()
    print(f"RST Packet created ...")
    """
    ======================================================================================
    """

    ending_connection_robust(rst_packet, sender_socket, dest_ip)

sender_socket.close()
receiver_socket.close()

print("ENDING SCAN")