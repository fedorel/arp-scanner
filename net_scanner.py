import argparse
from tabulate import tabulate
from scapy.all import ARP, Ether, srp

def get_arguments():
    parser = argparse.ArgumentParser(description="a simple ARP scanner")
    
    parser.add_argument("-t", "--target", dest="target", required=True, 
                        help="the target IP adrees or subnet range")
    
    parser.add_argument("-w", "--timeout", dest="timeout", type=float, default=2.0,
                    help="response waiting time in seconds (default: 2.0)")
    
    options = parser.parse_args()
    return options

def scan(ip_range, seconds):
    broadcast_layer = Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_layer = ARP(pdst=ip_range)
    packet = broadcast_layer / arp_layer

    answered_list = srp(packet, timeout=seconds, verbose=False)[0]

    clients_list = []
    for element in answered_list:
        client_dict = {"ip": element[1].psrc, "mac": element[1].hwsrc}
        clients_list.append(client_dict)

    return clients_list

def display_result(results):
    if not results:
        print("no devices have been detected on the network")
        return

    table_data = []
    for client in results:
        row = [client["ip"], client["mac"]]
        table_data.append(row)

    columns = ["IP", "MAC"]
    print(tabulate(table_data, headers=columns, tablefmt="fancy_grid"))

if __name__ == "__main__":
    args = get_arguments()
    scan_response = scan(args.target, args.timeout)
    display_result(scan_response)