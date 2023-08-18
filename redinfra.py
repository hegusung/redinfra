#!/usr/bin/python3
import argparse

from aws import AWS
from routing import Routing
from colorama import Fore, Style

def main():
    parser = argparse.ArgumentParser(description='RedInfra: red team infrastructure manager')
    parser.add_argument('--show-config', action='store_true', help='Show the complete config', dest='show_config')

    aws_group = parser.add_argument_group("AWS")
    aws_group.add_argument('--list-aws', action='store_true', help='List AWS instances', dest='list_aws')
    aws_group.add_argument('--start-aws', type=str, help='Start AWS instance', dest='start_aws')
    aws_group.add_argument('--stop-aws', type=str, help='Stop AWS instance', dest='stop_aws')
    aws_group.add_argument('--list-elastic-ips', action='store_true', help='List AWS Elastic IPs', dest='list_elastic_ips')
    aws_group.add_argument('--renew-ip', type=str, help='Renew Elastic IPs', dest='renew_ip')
    aws_group.add_argument('--associate-ip', nargs=2, metavar=("IP", "Instance"), type=str, help='Associate Elastic IPs with an instance', dest='associate_ip')
    aws_group.add_argument('--dissociate-ip', metavar="IP", type=str, help='Dissociate Elastic IPs from an instance', dest='dissociate_ip')

    aws_group.add_argument('--list-dns', action='store_true', help='List DNS entry', dest='list_dns')
    aws_group.add_argument('--new-dns', nargs=2, metavar=("DNS", "Value"), type=str, help='Register new DNS', dest='new_dns')
    aws_group.add_argument('--remove-dns', nargs=2, metavar=("DNS", "Value"), type=str, help='Remove DNS entry', dest='remove_dns')
    aws_group.add_argument('--dns-type', default='A', type=str, help='DNS entry type', dest='dns_type')

    vpn_group = parser.add_argument_group("VPN")
    vpn_group.add_argument('--set-vpn-ip', nargs=2, metavar=("Instance", "IP"), type=str, help='Set an Instance local VPN IP', dest='set_vpn_ip')
    vpn_group.add_argument('--list-vpn-ip', action='store_true', help='List Instances VPN IP', dest='list_vpn_ip')
    vpn_group.add_argument('--remove-vpn-ip', nargs=1, metavar=("Instance",), type=str, help='Remove Instance local VPN IP', dest='remove_vpn_ip')

    routing_group = parser.add_argument_group("Routing")
    routing_group.add_argument('--set-routing', nargs=3, metavar=("Instance", "IP", "Ports"), type=str, help='Set a route between an Instance and an IP', dest='set_routing')
    routing_group.add_argument('--list-routing', action='store_true', help='List routing', dest='list_routing')
    routing_group.add_argument('--remove-routing', nargs=1, metavar=("Instance",), type=str, help='Remove a specific route', dest='remove_routing')
    routing_group.add_argument('--apply', action='store_true', help='Apply routing', dest='apply')


    args = parser.parse_args()

    aws = AWS()

    if args.list_aws:
        aws.list_aws()

    if args.start_aws:
        aws.start_instance(args.start_aws)

    if args.stop_aws:
        aws.stop_instance(args.stop_aws)

    if args.list_elastic_ips:
        aws.list_elastic_ips()

    if args.renew_ip:
        aws.renew_ip(args.renew_ip)

    if args.associate_ip:
        aws.associate_ip(args.associate_ip[0], args.associate_ip[1])

    if args.dissociate_ip:
        aws.dissociate_ip(args.dissociate_ip)

    if args.list_dns:
        aws.list_dns()

    if args.new_dns:
        aws.new_dns(args.new_dns[0], args.new_dns[1], args.dns_type)

    if args.remove_dns:
        aws.remove_dns(args.remove_dns[0], args.remove_dns[1], args.dns_type)

    routing = Routing()

    if args.set_vpn_ip:
        routing.set_vpn_ip(args.set_vpn_ip[0], args.set_vpn_ip[1])

    if args.list_vpn_ip:
        routing.list_vpn_ip()

    if args.remove_vpn_ip:
        routing.remove_vpn_ip(args.remove_vpn_ip[0])

    if args.set_routing:
        routing.set_routing(args.set_routing[0], args.set_routing[1], args.set_routing[2])

    if args.list_routing:
        routing.list_routing()

    if args.remove_routing:
        routing.remove_routing(args.remove_routing[0])

    if args.apply:
        routing.apply()


    if args.show_config:
        config = aws.show_config()
        config = routing.show_config(config)

        print("Current configuration:")
        for c in config:
            dns = c[0]
            public_ip = c[1]
            instance = c[2]
            instance_name = c[3]
            instance_state = c[4]
            vpn_ip = c[5]
            node_ip = c[6]

            if dns != None:
                dns = ("%s ===>   " % (dns,)).rjust(50)
            else:
                dns = " "*50

            if instance != None:
                row = dns + "[%s] (%s) %s [%s]" % (public_ip, instance_name, instance, vpn_ip if vpn_ip != None else "")

                if node_ip != None:
                    row += "   <===>   %s" % node_ip
            else:
                row = dns + "[%s]" % public_ip

            c = Fore.YELLOW
            if instance_state == 'running':
                c = Fore.GREEN
            elif instance_state == 'stopped':
                c = Fore.RED

            print("%s%s%s" % (c, row, Style.RESET_ALL))

if __name__ == '__main__':
    main()
