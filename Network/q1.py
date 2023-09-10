import scapy.all as S
import urllib.parse as urlparse
from typing import Tuple
import re

WEBSITE = 'infosec.cs.tau.ac.il'


def parse_packet(packet) -> Tuple[str]:
    """
    If the given packet is a login request to the course website, return the
    username and password as a tuple => ('123456789', 'opensesame'). Otherwise,
    return None.

    Notes:
    1. You can assume the entire HTTP request fits within one packet, and that
       both the username and password are non-empty for login requests (if any
       of the above assumptions fails, it's OK if you don't extract the
       user/password - but you must still NOT crash).
    2. Filter the course website using the `WEBSITE` constant from above. DO NOT
       use the server IP for the filtering (as our domain may point to different
       IPs later and your code should be reliable).
    3. Make sure you return a tuple, not a list.
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
        if host == WEBSITE:
            parsed_data = urlparse.parse_qs(load)
            # Extract the desired values
            if 'username' in parsed_data and 'password' in parsed_data:
            
                username = parsed_data['username'][0]
                password = parsed_data['password'][0]     
                return username, password
        
    return None
   


def packet_filter(packet) -> bool:
    """
    Filter to keep only HTTP traffic (port 80) from any HTTP client to any
    HTTP server (not just the course website). This function should return
    `True` for packets that match the above rule, and `False` for all other
    packets.

    Notes:
    1. We are only keeping HTTP, while dropping HTTPS
    2. Traffic from the server back to the client should not be kept
    """
    
    if S.TCP in packet:
        if packet[S.TCP].dport == 80:
            return True
    return False
            
        
    


def main(args):
    # WARNING: DO NOT EDIT THIS FUNCTION!
    if '--help' in args:
        print('Usage: %s [<path/to/recording.pcapng>]' % args[0])

    elif len(args) < 2:
        # Sniff packets and apply our logic.
        S.sniff(lfilter=packet_filter, prn=parse_packet)

    else:
        # Else read the packets from a file and apply the same logic.
        for packet in S.rdpcap(args[1]):
            if packet_filter(packet):
                print(parse_packet(packet))


if __name__ == '__main__':
    import sys
    main(sys.argv)
