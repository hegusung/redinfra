import os
import sys
import yaml
import json

CONFIG_PATH = "./config/"
DATA_PATH = "./data/"

def no_duplicates_constructor(loader, node, deep=False):
  """Check for duplicate keys."""
  mapping = {}
  for key_node, value_node in node.value:
    key = loader.construct_object(key_node, deep=deep)
    if key in mapping:
      msg = "Duplicate key {0} (overwrite existing value '{1}' with new value '{2}'"
      msg = msg.format(key, mapping[key], value_node)
      raise Exception(msg)
    value = loader.construct_object(value_node, deep=deep)
    mapping[key] = value
  return loader.construct_mapping(node, deep)

def construct_mapping(loader, node):
  loader.flatten_mapping(node)
  return object_pairs_hook(loader.construct_pairs(node))

class DupCheckLoader(yaml.Loader):
  pass

DupCheckLoader.add_constructor(
  yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG,
  no_duplicates_constructor)

class Config:

    def __init__(self):
        self.previous_config = None

        self.region_to_ami = self.load_ami()

        self.main_config = self.load_main()

        self.missions = self.load_missions()

        os.environ["AWS_ACCESS_KEY_ID"] = self.get_api_key("aws_key")
        os.environ["AWS_SECRET_ACCESS_KEY"] = self.get_api_key("aws_secret")


    # == Config load ==

    def load_ami(self):
        with open(CONFIG_PATH + "aws.yml") as stream:
            return yaml.load(stream, DupCheckLoader)

    def load_main(self):
        with open(CONFIG_PATH + "main.yml") as stream:
            return yaml.load(stream, DupCheckLoader)

    def load_missions(self):
        mission_dict = {}
        
        mission_config_files = [os.path.join(CONFIG_PATH, f) for f in os.listdir(CONFIG_PATH) if os.path.isfile(os.path.join(CONFIG_PATH, f)) and not f in ['main.yml', 'aws.yml']]
        for mission_config_file in mission_config_files:
            with open(mission_config_file) as stream:
                mission_config = yaml.load(stream, DupCheckLoader)

                mission_name = mission_config['mission']
                if not mission_config['enabled']:
                    continue

                del mission_config['mission']
                del mission_config['enabled']

                mission_dict[mission_name] = mission_config

        return mission_dict
        
    # == Get config info ==

    def get_routing_config(self):
        return self.main_config['routing']

    def get_api_key(self, api):
        return self.main_config['api'][api]

    def get_tags(self):
        return self.main_config['tags']

    def get_cloud_regions(self):
        regions = []
       
        """
        regions.append(self.main_config['vpn']['region'])

        for mission in self.missions:
            for server in self.missions[mission]:
                regions.append(self.missions[mission][server]['region'])
        """

        regions = list(self.load_ami().keys()) 

        return list(set(regions))

    def get_vpn_region(self):
        return self.main_config['vpn']['region']

    def get_vpn_instance_type(self):
        return self.main_config['vpn']['instance_type']

    def get_ami(self, region):
        return self.region_to_ami[region]

    def get_nodes(self):
        node_list = []
        for mission, mission_info in self.missions.items():
            for name, srv_info in mission_info.items():
                node_list.append({
                    'mission': mission,
                    'name': name,
                    'region': srv_info['region'],
                    'ports': srv_info['ports'],
                    'instance_type': srv_info['instance_type'],
                })

        return node_list

    def get_mail_entries(self):
        mail_dict = {}

        for mission, mission_info in self.missions.items():
            for name, srv_info in mission_info.items():
                if 'mail' in srv_info:
                    for email_info in srv_info['mail']:
                        domain = email_info['mail'].split('@')[-1]

                        if not domain in mail_dict:
                            mail_dict[domain] = {}

                        mail_dict[domain][email_info['mail']] = email_info['name']

        return mail_dict

    def get_dns(self):
        dns_entries = {
            'A': [],
            'proxy': [],
        }

        for mission, mission_info in self.missions.items():
            for name, srv_info in mission_info.items():
                if 'dns_A' in srv_info:
                    for dns in srv_info['dns_A']:
                        dns_entries['A'].append((dns, mission, name))
                if 'dns_proxy' in srv_info:
                    for dns in srv_info['dns_proxy']:
                        dns_entries['proxy'].append((dns, mission, name))
                if 'dns' in srv_info:
                    for type, dns_list in srv_info['dns'].items():
                        if not type in dns_entries:
                            dns_entries[type] = []

                        for dns_info in dns_list:
                            dns_entries[type].append((dns_info['key'], dns_info['value']))

        return dns_entries

    def get_routing(self):
        routing = []

        for mission, mission_info in self.missions.items():
            for name, srv_info in mission_info.items():
                node_name = "Node_%s_%s" % (mission, name)
                local_ip = srv_info['local_ip']
                ports = srv_info['ports']

                routing.append({
                    'node_name': node_name,
                    'local_ip': local_ip,
                    'ports': ports,
                })

        return routing

    def get_playbooks(self):
        playbooks = []

        for mission, mission_info in self.missions.items():
            for name, srv_info in mission_info.items():
                local_ip = srv_info['local_ip']
                
                if 'ansible' in srv_info:
                    for playbook_info in srv_info['ansible']:
                        playbooks.append({
                            'mission': mission,
                            'name': name,
                            'local_ip': local_ip,
                            'playbook': playbook_info['playbook'],
                            'args': playbook_info['args'] if 'args' in playbook_info else {}
                        })

        return playbooks

    # == Terraform changes ==

    def detect_terraform_changes(self):
        pass

    # == Routing ==

    def detect_routing_changes(self):
        pass

    # == Cloudflare == 

    def detect_cloudflare_changes(self):
        pass

    # == SendGrid ==

    def detect_sendgrid_changes(self):
        pass
