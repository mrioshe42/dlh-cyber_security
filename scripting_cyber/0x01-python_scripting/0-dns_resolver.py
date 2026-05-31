#!/usr/bin/env python3

import socket

def resolve_domain_to_ipv4(domain_name):

    try:
        ipv4_address = socket.gethostbyname(domain_name)
        return ipv4_address
    
    except socket.gaierror:
        return None
    
    except Exception as e:
        return f"Error: {str(e)}"
