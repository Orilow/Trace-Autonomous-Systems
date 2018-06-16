from argparse import ArgumentParser
import socket
import json
import requests

ECHO_REQUEST_ICMP_PACKET = b'\x08\x00\x0b\x27\xeb\xd8\x01\x00'
PRIVATE_NETWORKS = {
    ('10.0.0.0', '10.255.255.255'),
    ('172.16.0.0', '172.31.255.255'),
    ('192.168.0.0', '192.168.255.255'),
    ('127.0.0.0', '127.255.255.255')
}


def get_parcer():
    pars = ArgumentParser(description="Trace Autonomous Systems")
    pars.add_argument("destination", type=str, help="Destination hostname")
    pars.add_argument("-hops", default=52, type=int, help="Maximum number of hops")
    pars.add_argument("-timeout", default=5, type=int, help="Timeout of response in seconds")
    return pars


def is_white_ip(ip):
    for network in PRIVATE_NETWORKS:
        if network[0] <= ip <= network[1]:
            return False
    return True


def get_ip_info(ip):
    info = json.loads(requests.get("http://ipinfo.io/{0}/json".format(ip)).content)
    mes = "\t {0} {1} {2}".format(info['country'], info['region'], info['city'])
    if "org" in info:
        if info["org"] != "":
            mes += " Organisation: {}".format(info["org"])
    if "loc" in info:
        if info["loc"] != "":
            mes += " Location: {}".format(info["loc"])
    return mes


def traceroute(destination, hops, timeout):
    destination = socket.gethostbyname(destination)
    current_address = None
    ttl = 1
    with socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP) as sock:
        sock.settimeout(timeout)
        while ttl != hops and current_address != destination:
            sock.setsockopt(socket.SOL_IP, socket.IP_TTL, ttl)
            sock.sendto(ECHO_REQUEST_ICMP_PACKET, (destination, 1))
            try:
                packet, adr = sock.recvfrom(1024)
                current_address = adr[0]
                message = "{0} {1}".format(ttl, current_address)
                if is_white_ip(current_address):
                    message += get_ip_info(current_address)
                yield message
            except socket.timeout:
                yield '*****'
            ttl += 1


if __name__ == '__main__':
    parser = get_parcer()
    args = parser.parse_args()
    for message in traceroute(args.destination, args.hops, args.timeout):
        print(message)
