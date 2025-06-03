import socket
import struct
import random
import time

class TCPPacket():
    """
    A class that creates an IP and TCP packet,
    depending on the mode (SYN or RST by default) and the source and destination IPs
    It will create a TCP header and encapsulate it into a IP header 
    """

    def __init__(self, mode, host_ip, target_ip, host_port, target_port, seq_num=0, ack_num=0):

        self._mode =  0x02 if mode == "SYN" else 0x14 # SYN or RST/ACK
        self._ip_host_addr = socket.inet_aton(host_ip)  # need for exception handling ?
        self._ip_target_addr = socket.inet_aton(target_ip)
        self._host_port = host_port
        self._target_port = target_port
        self._seq_num = seq_num
        self._ack_num = ack_num

        # creation of the SYN packet
        self._packet = None
        self.create_tcp_packet()

    def get_packet(self):
        return self._packet

    def create_tcp_packet(self):
        ip_header = self.get_IPheader()
        tcp_header = self.get_TCPheader()
        self._packet = ip_header + tcp_header

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
        ip_host_addr = self._ip_host_addr               # Binary IP adress(32bits or 4 x 8bytes)

        # Fifth 32bits word ----------------------------------------------------------------------
        ip_target_addr = self._ip_target_addr               # Binary IP adress(32bits or 4 x 8bits)
        ##########################################################################################

        # Packing up the header
        # ! = specifyng big-endian byte order  |  B = 1byte  |  H = 2 bytes  |  4s = 4bytes string
        ip_header = struct.pack('!BBHHHBBH4s4s', 
            ip_ver_ihl, ip_tos, ip_tot_len, ip_id, ip_frag_off, 
            ip_ttl, ip_proto, ip_check, ip_host_addr, ip_target_addr)

        return ip_header


    def get_TCPheader(self):
        
        """ 
        Our TCP header is 20bytes long :
        5 words of 32bits(4bytes) = 160bits (20bytes)
        """

        ##########################################################################################
        # First 32bits word ----------------------------------------------------------------------
        tcp_host_port = self._host_port              # (16bits)
        tcp_target_port = self._target_port    # (16bits)

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
            tcp_host_port, tcp_target_port, tcp_seq, tcp_ack_seq, 
            tcp_doff_res, tcp_flags, tcp_window, tcp_check, tcp_urg_ptr)

        # Creating Pseudo-Header for checksum.
        # PH must have essentials elements in this order : IPs source & destination - Fixed 8bits (padding) - protocol - TCP length
        # Then check sum must be used with [pseudo-header + tcp-header + tcp-body (empty in our case)]
        padding = 0                     # 8bits
        protocol = socket.IPPROTO_TCP   # 8bits
        tcp_length = len(tcp_header)    # 16bits

        pseudo_header = struct.pack('!4s4sBBH', 
            self._ip_host_addr, self._ip_target_addr, padding, protocol, tcp_length)

        pseudo_packet = pseudo_header + tcp_header
        tcp_check = self.checksum(pseudo_packet) # calling the checksum function

        # Cretaing the header with checksum
        tcp_header = struct.pack('!HHLLBBHHH',
            tcp_host_port, tcp_target_port, tcp_seq, tcp_ack_seq, 
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
            checksum = (checksum & 0xFFFF) + (checksum >> 16)

        # reverting the checksum
        final_checksum = ~checksum & 0xFFFF
        #print(f"final is {final_checksum}")

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
    version_ihl = packet[0]       # Premier octet
    ihl = version_ihl & 0x0F        # Garde seulement les 4 derniers bits
    ip_header['ip_header_length'] = ihl * 4      # Convertit en octets
    
    try:
        header = struct.unpack('!BBHHHBBH4s4s', packet[:ip_header['ip_header_length']])
    except Exception as e:
        print("ERROR UNPACKING IP HEADER:", e)
        return
    

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
    ip_header["host_ip"] = socket.inet_ntoa(header[8])
    ip_header["target_ip"] = socket.inet_ntoa(header[9])
    return ip_header

def get_tcp_header(packet, ip_header):

    try:
        header = struct.unpack('!HHLLBBHHH', packet[ip_header["ip_header_length"]:ip_header["ip_header_length"] + 20])
    except Exception as e:
        print("ERROR UNPACKING TCP HEADER:", e)
        return
    
    tcp_header = {}

    tcp_header["host_port"] = header[0]
    tcp_header["target_port"] = header[1]
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


def ending_connection_robust(sender_socket, host_ip, target_ip, host_port, target_port, response_ack_num, response_seq_num):
    """Version robuste qui gère l'échec du RST"""
    
    rst_packet = TCPPacket("RST", host_ip, target_ip, target_port, target_port, response_ack_num, response_seq_num + 1)
    rst_packet = rst_packet.get_packet()

    print("=== TENTATIVE ENVOI RST ===")
    try:
        sender_socket.sendto(rst_packet, (target_ip, 0))
        print("✅ RST envoyé avec succès")
        return True
        
    except PermissionError as e:
        print(f"❌ RST bloqué par le système: {e}")
        print("   → Connexion fermée par timeout côté serveur")
        return False
    
    except Exception as e:
        print(f"❌ Autre erreur RST: {e}")
        return False
    
def	send_and_receive_packet(packet, sender_socket, receiver_socket, ip_header, tcp_header):
    
    try:
        sender_socket.sendto(packet, (ip_header['target_ip'], 0))
        # print(f"SYN Packet send to {ip_header['target_ip']} on {tcp_header['target_port']} port",
        #     f"to host {ip_header['host_ip']} on port {tcp_header['host_port']}")
    except Exception as e:
        print(f"ERROR SENDING SYN PACKET: ", e)

    try:
        packet_received = receiver_socket.recv(1024)
        # print(f"Respond packet received ...")
    except Exception as e:
        print(f"ERROR RECEIVING PACKET: ", e)

    return packet_received

def check_response(sender_socket, host_ip, target_ip, host_port, target_port, response_packet):

    response_ip_header = get_ip_header(response_packet)
    response_tcp_header = get_tcp_header(response_packet, response_ip_header)


    # Verify packet headers match expected values
    if (response_ip_header["target_ip"] != host_ip or
        response_ip_header["host_ip"] != target_ip or
        response_tcp_header["target_port"] != host_port or
        response_tcp_header["host_port"] != target_port):
        # print("Received packet does not match expected source/destination") # we sometime get weird and unexpected packets

        return

    # Check if port is open
    if response_tcp_header["flag_bits"]["ACK"] and response_tcp_header["flag_bits"]["SYN"]:

        print(f"🟢 Port {target_port} on {target_ip} IPv4 address is OPEN")

        response_sequence_number = response_tcp_header['sequence']
        response_ack_number = response_tcp_header['ack']

        ending_connection_robust(sender_socket,
                                 host_ip, 
                                 target_ip, 
                                 host_port, 
                                 target_port, 
                                 response_sequence_number, 
                                 response_ack_number)
    else:
        # print(f"🔴 Port {target_port} on {target_ip} IPv4 address is CLOSED")
        return