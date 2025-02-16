#!/usr/bin/python3
import argparse

from lib.aws import AWS
from lib.cloudflare import CloudFlare
from lib.sendgridclient import SendGrid
from lib.routing import Routing
from lib.terraform import Terraform
from lib.automation import Automation
from lib.config import Config
from colorama import Fore, Style

def main():
    parser = argparse.ArgumentParser(description='RedInfra: red team infrastructure manager')

    subparsers = parser.add_subparsers(dest="command", required=True)

    # Auto: automation
    auto_parser = subparsers.add_parser("auto", help="Terraform / Ansible automation")
    auto_parser.add_argument('--install', action='store_true', help='Install the packages for redinfra', dest='install_redinfra')
    auto_parser.add_argument('--apply', action='store_true', help='Execute all the steps to deploy the config', dest='apply')
    auto_parser.add_argument('--destroy', action='store_true', help='Cleanup everything', dest='destroy')
    auto_parser.add_argument('--apply-terraform', action='store_true', help='Execute all the steps to deploy the config', dest='apply_terraform')
    auto_parser.add_argument('--apply-sendgrid', action='store_true', help='Execute all the steps to deploy the config', dest='apply_sendgrid')
    auto_parser.add_argument('--apply-cloudflare', action='store_true', help='Execute all the steps to deploy the config', dest='apply_cloudflare')
    auto_parser.add_argument('--apply-routing', action='store_true', help='Execute all the steps to deploy the config', dest='apply_routing')
    auto_parser.add_argument('--apply-ansible', action='store_true', help='Execute all the steps to deploy the config', dest='apply_ansible')
    auto_parser.add_argument('--playbooks', nargs=2, metavar=("mission", "server"), type=str, help='Execute the playbooks of a host', dest='playbooks')

    aws_parser = subparsers.add_parser("aws", help="AWS listing")
    aws_ec2_group = aws_parser.add_argument_group("AWS - EC2")
    aws_ec2_group.add_argument('--list', action='store_true', help='List AWS instances', dest='list_aws')
    aws_ec2_group.add_argument('--start', type=str, help='Start AWS instance', dest='start_aws')
    aws_ec2_group.add_argument('--stop', type=str, help='Stop AWS instance', dest='stop_aws')

    aws_ips_group = aws_parser.add_argument_group("AWS - Elastic IPs")
    aws_ips_group.add_argument('--list-ips', action='store_true', help='List AWS Elastic IPs', dest='list_elastic_ips')
    aws_ips_group.add_argument('--new-ip', type=str, metavar='Region', help='Get a new Elastic IPs', dest='new_ip')
    aws_ips_group.add_argument('--remove-ip', type=str, help='Delete an Elastic IPs', dest='remove_ip')
    aws_ips_group.add_argument('--renew-ip', type=str, help='Renew Elastic IPs', dest='renew_ip')
    aws_ips_group.add_argument('--associate-ip', nargs=2, metavar=("IP", "Instance"), type=str, help='Associate Elastic IPs with an instance', dest='associate_ip')
    aws_ips_group.add_argument('--dissociate-ip', metavar="IP", type=str, help='Dissociate Elastic IPs from an instance', dest='dissociate_ip')

    cf_parser = subparsers.add_parser("cloudflare", help="Coudflare listing")
    cf_parser.add_argument('--list', action='store_true', help='List DNS entry', dest='list_dns')
    cf_parser.add_argument('--new', nargs=2, metavar=("DNS", "Value"), type=str, help='Register new DNS', dest='new_dns')
    cf_parser.add_argument('--new-proxy', nargs=2, metavar=("DNS", "Value"), type=str, help='Register new proxied DNS', dest='new_proxy')
    cf_parser.add_argument('--remove-dns', nargs=2, metavar=("DNS", "Value"), type=str, help='Remove DNS entry', dest='remove_dns')
    cf_parser.add_argument('--dns-type', default='A', type=str, help='DNS entry type', dest='dns_type')
    
    sg_parser = subparsers.add_parser("sendgrid", help="SendGrid listing")
    sg_parser.add_argument('--new-domain', metavar="domain", type=str, help='Add a new domain to sendgrib, DNS entries will be created', dest='sendgrid_new_domain')
    sg_parser.add_argument('--delete-domain', metavar="domain", type=str, help='Delete a domain from sendgrib, DNS entries will be deleted', dest='sendgrid_delete_domain')
    sg_parser.add_argument('--list-domains', action='store_true', help='List domains from SendGrib', dest='sendgrid_list_domain')
    sg_parser.add_argument('--list-senders', action='store_true', help='List senders from SendGrib', dest='sendgrid_list_senders')
    sg_parser.add_argument('--new-sender', nargs=2, metavar=("Name", "email"), type=str, help='Add a new sender to sendgrib', dest='sendgrid_new_sender')
    sg_parser.add_argument('--delete-sender', metavar="email", type=str, help='Delete a sender from sendgrib', dest='sendgrid_delete_sender')

    local_parser = subparsers.add_parser("local", help="Local actions")
    local_parser.add_argument('--show-config', action='store_true', help='Show the complete config', dest='show_config')

    routing_group = local_parser.add_argument_group("Routing")
    routing_group.add_argument('--set-routing', nargs=3, metavar=("Instance", "IP", "Ports"), type=str, help='Set a route between an Instance and an IP', dest='set_routing')
    routing_group.add_argument('--list-routing', action='store_true', help='List routing', dest='list_routing')
    routing_group.add_argument('--remove-routing', nargs=1, metavar=("Instance",), type=str, help='Remove a specific route', dest='remove_routing')
    routing_group.add_argument('--apply', action='store_true', help='Apply routing', dest='apply')

    vpn_group = local_parser.add_argument_group("VPN")
    vpn_group.add_argument('--set-vpn-ip', nargs=2, metavar=("Instance", "IP"), type=str, help='Set an Instance local VPN IP', dest='set_vpn_ip')
    vpn_group.add_argument('--list-vpn-ip', action='store_true', help='List Instances VPN IP', dest='list_vpn_ip')
    vpn_group.add_argument('--remove-vpn-ip', nargs=1, metavar=("Instance",), type=str, help='Remove Instance local VPN IP', dest='remove_vpn_ip')
    vpn_group.add_argument('--clear-config', action='store_true', help='Clear the configuration', dest='clear_config')


    args = parser.parse_args()

    config = Config()

    cloudflare = CloudFlare(config)
    aws = AWS(config, cloudflare)
    sendgrid = SendGrid(config, cloudflare)
    routing = Routing(config)

    auto = Automation(config, aws, cloudflare, sendgrid, routing) 

    if args.command == 'auto':
        if args.install_redinfra:
            auto.install_redinfra()

        elif args.apply:
            auto.apply()

        elif args.destroy:
            auto.destroy()

        elif args.apply_terraform:
            auto.apply_terraform()

        elif args.apply_sendgrid:
            auto.update_sendgrid()

        elif args.apply_cloudflare:
            auto.update_cloudflare()

        elif args.apply_routing:
            auto.update_routing()

        elif args.apply_ansible:
            auto.update_ansible()

        elif args.playbooks:
            auto.execute_playbooks(args.playbooks[0], args.playbooks[1])


    elif args.command == 'aws':
        if args.list_aws:
            aws.list_aws()

        if args.start_aws:
            aws.start_instance(args.start_aws)

        if args.stop_aws:
            aws.stop_instance(args.stop_aws)

        if args.list_elastic_ips:
            aws.list_elastic_ips()

        if args.new_ip:
            aws.new_ip(args.new_ip)

        if args.remove_ip:
            aws.remove_ip(args.remove_ip)

        if args.renew_ip:
            aws.renew_ip(args.renew_ip)

        if args.associate_ip:
            aws.associate_ip(args.associate_ip[0], args.associate_ip[1])

        if args.dissociate_ip:
            aws.dissociate_ip(args.dissociate_ip)

    elif args.command == 'cloudflare':
        if args.list_dns:
            cloudflare.list_dns()

        if args.new_dns:
            cloudflare.new_dns(args.new_dns[0], args.new_dns[1], args.dns_type)

        if args.new_proxy:
            cloudflare.new_dns(args.new_proxy[0], args.new_proxy[1], 'A', proxied=True)

        if args.remove_dns:
            cloudflare.remove_dns(args.remove_dns[0], args.remove_dns[1], args.dns_type)

    elif args.command == 'sendgrid':

        if args.sendgrid_new_domain:
            sendgrid.new_domain(args.sendgrid_new_domain)

        if args.sendgrid_delete_domain:
            sendgrid.delete_domain(args.sendgrid_delete_domain)

        if args.sendgrid_list_domain:
            sendgrid.list_domains()

        if args.sendgrid_list_senders:
            sendgrid.list_senders()

        if args.sendgrid_new_sender:
            sendgrid.new_sender(args.sendgrid_new_sender[0], args.sendgrid_new_sender[1])

        if args.sendgrid_delete_sender:
            sendgrid.delete_sender(args.sendgrid_delete_sender)

    elif args.command == 'local':

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

        if args.clear_config:
            routing.clear_config()

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
                if c[5] != None:
                    vpn_ip_aws = c[5].split(':')[0]
                    vpn_ip_router = c[5].split(':')[-1]
                else:
                    vpn_ip_aws = None
                    vpn_ip_router = None
                node_ip = c[6]

                if dns != None:
                    dns = ("%s ===>   " % (dns,)).rjust(50)
                else:
                    dns = " "*50

                if instance != None:
                    row = dns + "[%s] (%s) %s [%s] -> [%s]" % (public_ip, instance_name, instance, vpn_ip_aws if vpn_ip_aws != None else "", vpn_ip_router if vpn_ip_router != None else "")

                    if node_ip != None:
                        row += " Redirector   <===>   %s" % node_ip
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
