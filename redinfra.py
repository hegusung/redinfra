#!/usr/bin/python3
import argparse

from aws import AWS

def main():
    parser = argparse.ArgumentParser(description='RedInfra: red team infrastructure manager')
    parser.add_argument('--list-aws', action='store_true', help='List AWS instances', dest='list_aws')
    parser.add_argument('--list-elastic-ips', action='store_true', help='List AWS Elastic IPs', dest='list_elastic_ips')
    parser.add_argument('--renew-ip', type=str, help='Renew Elastic IPs', dest='renew_ip')
    parser.add_argument('--associate-ip', nargs=2, metavar="IP Instance", type=str, help='Associate Elastic IPs with an instance', dest='associate_ip')
    parser.add_argument('--dissociate-ip', metavar="IP", type=str, help='Dissociate Elastic IPs from an instance', dest='dissociate_ip')

    parser.add_argument('--list-dns', action='store_true', help='List DNS entry', dest='list_dns')
    parser.add_argument('--new-dns', nargs=2, metavar="DNS IP", type=str, help='Register new DNS', dest='new_dns')
    parser.add_argument('--remove-dns', nargs=2, metavar="DNS IP", type=str, help='Remove DNS entry', dest='remove_dns')

    args = parser.parse_args()

    aws = AWS()

    if args.list_aws:
        aws.list_aws()

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
        aws.new_dns(args.new_dns[0], args.new_dns[1])

    if args.remove_dns:
        aws.remove_dns(args.remove_dns[0], args.remove_dns[1])


if __name__ == '__main__':
    main()
