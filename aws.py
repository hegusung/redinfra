import boto3
import os
import sys
import configparser

REGIONS = ['eu-west-3']

class AWS:
    def __init__(self):
        self.config = configparser.ConfigParser(interpolation=None)
        self.config.read(os.path.join(os.path.dirname(sys.argv[0]), 'redinfra.cfg'))

        self.clients = []
        for region in REGIONS:
            self.clients.append((region,
                boto3.client('ec2',
                    region_name=region,
                    aws_access_key_id=self.config.get('AWS', 'access_key_id'),
                    aws_secret_access_key=self.config.get('AWS', 'secret_access_key')
                ),
                boto3.client('route53',
                    region_name=region,
                    aws_access_key_id=self.config.get('AWS', 'access_key_id'),
                    aws_secret_access_key=self.config.get('AWS', 'secret_access_key')
                ),
                ))

    def list_aws(self):
        print("AWS Instances")
        for client_tuple in self.clients:
            region, client, _ = client_tuple
            print(type(client))

            print("Region: %s" % region)
            response = client.describe_instances()
            for reservation in response["Reservations"]:
                for instance in reservation["Instances"]:
                    instance_id = instance['InstanceId']
                    public_ips = []

                    for association in instance["NetworkInterfaces"]:
                        if "Association" in association:
                            public_ips.append(association["Association"]["PublicIp"])

                    print(" - %s [%s]" % (instance_id, ", ".join(public_ips)))

    def list_elastic_ips(self):
        print("Elastic IPs")
        for client_tuple in self.clients:
            region, client, _ = client_tuple

            print("Region: %s" % region)
            response = client.describe_addresses()
            for address in response["Addresses"]:
                ip = address["PublicIp"]
                if "InstanceId" in address:
                    instance = address["InstanceId"]
                else:
                    instance = "Not associated"
                print(" - %s => %s" % (ip, instance))

    def renew_ip(self, ip):
        print("> Renewing IP %s" % ip)
        found = False
        for client_tuple in self.clients:
            region, client, _ = client_tuple

            response = client.describe_addresses()
            for address in response["Addresses"]:
                elastic_ip = address["PublicIp"]
                allocation_id = address["AllocationId"]
                association_id = address["AssociationId"]

                if ip == elastic_ip:
                    found = True

                    if "InstanceId" in address:
                        instance = address["InstanceId"]

                        print("> Dissociating from instance %s" % instance)
                        client.disassociate_address(AssociationId=association_id)
                    else:
                        instance = None

                    print("> Getting new elastic IP")
                    new_allocation = client.allocate_address(Domain='vpc')

                    print("> Releasing old elastic IP")
                    client.release_address(AllocationId=allocation_id)

                    if instance != None:
                        print("> Associating new elastic IP to %s" % instance)
                        client.associate_address(AllocationId=new_allocation['AllocationId'], InstanceId=instance)

                    print("New Elastic IP: %s" % new_allocation["PublicIp"])

                else:
                    continue

        if not found:
            print("> Unable to renew IP, not found")

    def associate_ip(self, ip, instance):
        print("> Associating IP %s to %s" % (ip, instance))
        found = False
        for client_tuple in self.clients:
            region, client, _ = client_tuple

            response = client.describe_addresses()
            for address in response["Addresses"]:
                elastic_ip = address["PublicIp"]
                allocation_id = address["AllocationId"]

                if ip == elastic_ip:
                    found = True

                    client.associate_address(AllocationId=allocation_id, InstanceId=instance)

                    print("IP %s associated to %s" % (ip, instance))

                else:
                    continue

        if not found:
            print("> Unable to associate IP, not found")


    def dissociate_ip(self, ip):
        print("> Dissociating IP %s" % ip)
        found = False
        for client_tuple in self.clients:
            region, client, _ = client_tuple

            response = client.describe_addresses()
            for address in response["Addresses"]:
                elastic_ip = address["PublicIp"]
                allocation_id = address["AllocationId"]
                association_id = address["AssociationId"]

                if ip == elastic_ip:
                    found = True

                    if "InstanceId" in address:
                        instance = address["InstanceId"]

                        print("> Dissociating from instance %s" % instance)
                        client.disassociate_address(AssociationId=association_id)
                else:
                    continue

        if not found:
            print("> Unable to dissociate IP, not found")

    def list_dns(self):
        print("DNS entries")
        for client_tuple in self.clients:
            region, _, client = client_tuple

            print("Region: %s" % region)
            response = client.list_hosted_zones()
            for zone in response["HostedZones"]:
                domain = zone["Name"][:-1]
                print("- Zone: %s" % domain)

                response_zone = client.list_resource_record_sets(
                    HostedZoneId=zone['Id']
                )
                for item in response_zone["ResourceRecordSets"]:
                    dns = item['Name']
                    dns_type = item['Type']

                    if not dns_type in ['A', 'MX', 'AAAA']:
                        continue

                    for ip in item['ResourceRecords']:
                        ip = ip['Value']

                        print("  => %s IN A %s" % (dns, ip))

    def new_dns(self, domain, ip):
        print("Setting new domain %s => %s" % (domain, ip))
        for client_tuple in self.clients:
            region, _, client = client_tuple

            response = client.list_hosted_zones()
            for zone in response["HostedZones"]:
                _domain = zone["Name"][:-1]

                if domain.endswith(_domain):
                    print("> Adding new domain %s with ip %s" % (domain, ip))

                    response = client.change_resource_record_sets(
                        ChangeBatch={
                            'Changes': [
                                {
                                    'Action': 'UPSERT',
                                    'ResourceRecordSet': {
                                        'Name': domain,
                                        'ResourceRecords': [
                                            {
                                                'Value': ip,
                                            },
                                        ],
                                        'TTL': 300,
                                        'Type': 'A',
                                    },
                                },
                            ],
                        },
                        HostedZoneId=zone['Id'],
                    )

                    print("Domain %s added with IP %s" % (domain, ip))

    def remove_dns(self, domain, ip):
        print("Removing dns entry %s => %s" % (domain, ip))
        for client_tuple in self.clients:
            region, _, client = client_tuple

            response = client.list_hosted_zones()
            for zone in response["HostedZones"]:
                _domain = zone["Name"][:-1]

                if domain.endswith(_domain):
                    print("> Removing domain %s with ip %s" % (domain, ip))

                    response = client.change_resource_record_sets(
                        ChangeBatch={
                            'Changes': [
                                {
                                    'Action': 'DELETE',
                                    'ResourceRecordSet': {
                                        'Name': domain,
                                        'ResourceRecords': [
                                            {
                                                'Value': ip,
                                            },
                                        ],
                                        'TTL': 300,
                                        'Type': 'A',
                                    },
                                },
                            ],
                        },
                        HostedZoneId=zone['Id'],
                    )

                    print("Domain %s with IP %s removed" % (domain, ip))
