import boto3
import os
import sys
import configparser
from colorama import Fore, Style

class AWS:
    def __init__(self):
        self.config = configparser.ConfigParser(interpolation=None)
        self.config.read(os.path.join(os.path.dirname(sys.argv[0]), 'redinfra.cfg'))

        self.tags = []
        self.filters = []
        for item in self.config.get('AWS', 'tags').split(';'):
            part = item.split(':', 1)
            self.tags.append({"Key": part[0].strip(), "Value": part[1].strip()})
            self.filters.append({"Name": 'tag:%s' % part[0].strip(), "Values": [part[1].strip()]})

        self.clients = []
        for region in self.config.get('AWS', 'regions').split(','):
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

    def show_config(self):
        config = []

        # Get elastic_ip
        elastic_ips = {}
        for client_tuple in self.clients:
            region, client, _ = client_tuple

            response = client.describe_addresses(Filters=self.filters)
            for address in response["Addresses"]:
                ip = address["PublicIp"]
                if "InstanceId" in address:
                    elastic_ips[ip] = address["InstanceId"]

        # List domains
        linked_ips = []
        client_tuple = self.clients[0] # Only use the first one
        region, _, client = client_tuple

        response = client.list_hosted_zones()
        for zone in response["HostedZones"]:
            domain = zone["Name"][:-1]

            response_zone = client.list_resource_record_sets(
                HostedZoneId=zone['Id']
            )
            for item in response_zone["ResourceRecordSets"]:
                dns = item['Name']
                dns_type = item['Type']

                if not dns_type in ['A', 'AAAA']:
                    continue

                for ip in item['ResourceRecords']:
                    ip = ip['Value']

                    if ip in elastic_ips:
                        config.append([dns, ip, elastic_ips[ip]])
                        linked_ips.append(ip)
                    else:
                        config.append([dns, ip, None])

        instance_dict = {}
        for client_tuple in self.clients:
            region, client, _ = client_tuple

            response = client.describe_instances(Filters=self.filters)
            for reservation in response["Reservations"]:
                for instance in reservation["Instances"]:

                    instance_name = "Unknown"
                    if not 'Tags' in instance:
                        continue

                    for tag in instance['Tags']:
                        if tag['Key'] == 'Name':
                            instance_name = tag['Value']
                    state = instance['State']['Name']
                    instance_id = instance['InstanceId']

                    instance_dict[instance_id] = [instance_name, state]
 
        linked_ips = list(set(linked_ips))

        for ip in linked_ips:
            del elastic_ips[ip]

        for ip, instance in elastic_ips.items():
            config.append([None, ip, instance])

        res = []
        for conf in config:
            inst = conf[2]
            if inst != None:
                if inst in instance_dict:
                    res.append(conf + instance_dict[inst])
                else:
                    res.append(conf + [None, None])
            else:
                res.append(conf + [None, None])

        return res


    def list_aws(self):
        print("AWS Instances")
        for client_tuple in self.clients:
            region, client, _ = client_tuple

            print("Region: %s" % region)
            response = client.describe_instances(Filters=self.filters)
            for reservation in response["Reservations"]:
                for instance in reservation["Instances"]:
                    #print(instance)

                    instance_name = "Unknown"
                    if not 'Tags' in instance:
                        continue

                    for tag in instance['Tags']:
                        if tag['Key'] == 'Name':
                            instance_name = tag['Value']
                            
                    state = instance['State']['Name']
                    instance_id = instance['InstanceId']
                    public_ips = []

                    for association in instance["NetworkInterfaces"]:
                        if "Association" in association:
                            public_ips.append(association["Association"]["PublicIp"])

                    c = Fore.YELLOW
                    if state == 'running':
                        c = Fore.GREEN
                    elif state == 'stopped':
                        c = Fore.RED

                    print("%s - %s (%s) [%s] (%s)%s" % (c, instance_id, instance_name, ", ".join(public_ips), state, Style.RESET_ALL))

    def start_instance(self, instance_id):
        print("> Starting instance %s" % (instance_id,))
        found = False
        for client_tuple in self.clients:
            region, client, _ = client_tuple

            response = client.describe_instances(Filters=self.filters)
            for reservation in response["Reservations"]:
                for instance in reservation["Instances"]:
                    if instance_id == instance['InstanceId']:
                        found = True
                        client.start_instances(InstanceIds=[instance_id], DryRun=False)

        if not found:
            print("> Unable to start instance, not found")

    def stop_instance(self, instance_id):
        print("> Stopping instance %s" % instance_id)
        found = False
        for client_tuple in self.clients:
            region, client, _ = client_tuple

            response = client.describe_instances(Filters=self.filters)
            for reservation in response["Reservations"]:
                for instance in reservation["Instances"]:
                    if instance_id == instance['InstanceId']:
                        found = True
                        client.stop_instances(InstanceIds=[instance_id], DryRun=False)

        if not found:
            print("> Unable to stop instance, not found")

    def list_elastic_ips(self):
        print("Elastic IPs")
        for client_tuple in self.clients:
            region, client, _ = client_tuple

            print("Region: %s" % region)
            response = client.describe_addresses(Filters=self.filters)
            for address in response["Addresses"]:
                ip = address["PublicIp"]
                if "InstanceId" in address:
                    instance = address["InstanceId"]
                else:
                    instance = "Not associated"
                print(" - %s => %s" % (ip, instance))


    def new_ip(self, new_ip_region):
        found = False
        for client_tuple in self.clients:
            region, client, _ = client_tuple

            if new_ip_region != region:
                continue

            found = True

            new_allocation = client.allocate_address(Domain='vpc', TagSpecifications=[
                {
                    "ResourceType": 'elastic-ip',
                    "Tags": self.tags
                }
            ])
            
            print("New Elastic IP: %s" % new_allocation["PublicIp"])

        if not found:
            print("> Unable to get new elastic IP, region not found")

    def remove_ip(self, ip):
        found = False
        for client_tuple in self.clients:
            region, client, _ = client_tuple

            response = client.describe_addresses(Filters=self.filters)
            for address in response["Addresses"]:
                elastic_ip = address["PublicIp"]
                allocation_id = address["AllocationId"]
                if not 'AssociationId' in address:
                    association_id = None
                else:
                    association_id = address["AssociationId"]

                if ip == elastic_ip:
                    found = True

                    if "InstanceId" in address:
                        instance = address["InstanceId"]

                        print("> Dissociating from instance %s" % instance)
                        client.disassociate_address(AssociationId=association_id)
                    else:
                        instance = None

                    print("> Releasing elastic IP")
                    client.release_address(AllocationId=allocation_id)
                else:
                    continue

        if not found:
            print("> Unable to delete IP, not found")


    def renew_ip(self, ip):
        print("> Renewing IP %s" % ip)
        found = False
        for client_tuple in self.clients:
            region, client, _ = client_tuple

            response = client.describe_addresses(Filters=self.filters)
            for address in response["Addresses"]:
                elastic_ip = address["PublicIp"]
                allocation_id = address["AllocationId"]
                if not 'AssociationId' in address:
                    association_id = None
                else:
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
                    new_allocation = client.allocate_address(Domain='vpc', TagSpecifications=[
                        {
                            "ResourceType": 'elastic-ip',
                            "Tags": self.tags
                        }
                    ])

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

            response = client.describe_addresses(Filters=self.filters)
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

            response = client.describe_addresses(Filters=self.filters)
            for address in response["Addresses"]:
                elastic_ip = address["PublicIp"]
                allocation_id = address["AllocationId"]
                if not 'AssociationId' in address:
                    association_id = None
                else:
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
        client_tuple = self.clients[0] # Only use the first one
        region, _, client = client_tuple

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

                if not dns_type in ['A', 'MX', 'AAAA', 'TXT']:
                    continue

                for ip in item['ResourceRecords']:
                    ip = ip['Value']

                    print(" => %s IN %s %s" % (dns, dns_type, ip))

    def new_dns(self, domain, value, dns_type='A'):
        print("Setting new domain %s = %s => %s" % (domain, dns_type, value))

        if dns_type == "TXT":
            if not value.startswith('"'):
                value = '"' + value
            if not value.endswith('"'):
                value = value + '"'
        elif dns_type == "MX" and len(value.split()) != 2:
            value = "10 %s" % value

        client_tuple = self.clients[0] # Only use the first one
        region, _, client = client_tuple

        response = client.list_hosted_zones()
        for zone in response["HostedZones"]:
            _domain = zone["Name"][:-1]

            if domain.endswith(_domain):
                print("> Adding new domain %s with value %s (%s)" % (domain, value, dns_type))

                response = client.change_resource_record_sets(
                    ChangeBatch={
                        'Changes': [
                            {
                                'Action': 'UPSERT',
                                'ResourceRecordSet': {
                                    'Name': domain,
                                    'ResourceRecords': [
                                        {
                                            'Value': value,
                                        },
                                    ],
                                    'TTL': 300,
                                    'Type': dns_type,
                                },
                            },
                        ],
                    },
                    HostedZoneId=zone['Id'],
                )

                print("Domain %s added with value %s (%s)" % (domain, value, dns_type))

    def remove_dns(self, domain, value, dns_type='A'):
        print("Removing dns entry %s = %s => %s" % (domain, dns_type, value))

        if dns_type == "TXT":
            value = "\"%s\"" % value 
        elif dns_type == "MX" and len(value.split()) != 2:
            value = "10 %s" % value

        client_tuple = self.clients[0] # Only use the first one
        region, _, client = client_tuple

        response = client.list_hosted_zones()
        for zone in response["HostedZones"]:
            _domain = zone["Name"][:-1]

            if domain.endswith(_domain):
                print("> Removing domain %s with value %s (%s)" % (domain, value, dns_type))

                response = client.change_resource_record_sets(
                    ChangeBatch={
                        'Changes': [
                            {
                                'Action': 'DELETE',
                                'ResourceRecordSet': {
                                    'Name': domain,
                                    'ResourceRecords': [
                                        {
                                            'Value': value,
                                        },
                                    ],
                                    'TTL': 300,
                                    'Type': dns_type,
                                },
                            },
                        ],
                    },
                    HostedZoneId=zone['Id'],
                )

                print("Domain %s with value %s removed (%s)" % (domain, value, dns_type))
