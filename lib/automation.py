import os
import json
import configparser
import os.path
import ansible_runner

from lib.terraform import Terraform

ANSIBLE_FILE = "ansible.cfg"

class Automation:

    def __init__(self, config, aws, cloudflare, sendgrid, routing):
        self.config = config
        self.aws = aws
        self.cloudflare = cloudflare
        self.sendgrid = sendgrid
        self.routing = routing
        
        self.terraform = Terraform(config)

    def install_redinfra(self):
        runner = ansible_runner.run(
            private_data_dir="ansible",
            playbook="install_router.yml"
        )

        if runner.rc == 0:
            print("[+] RedInfra server packages installed")
        else:
            print("Playbook execution failed!")
            print("STDERR:", runner.stderr.read())


    def apply(self):

        if not self.apply_terraform():
            return

        if not self.update_sendgrid():
            return

        if not self.update_cloudflare():
            return

        if not self.update_routing():
            return

        if not self.update_ansible():
            return


    def delete_terraform(self):

        print("[+] Deletion of old terraform files")

        return_code = self.terraform.destroy()

        if return_code != 0:
            print("[-] ERROR")
            return False

        self.terraform.delete_terraform_files()

        # Config changed lets reload it
        self.routing.reload_config()

        print("[+] Done")
        return True

    def apply_terraform(self):
        self.terraform.delete_terraform_files()

        print("[+] Creation of new terraform files")
        self.terraform.create_tf_files()

        return_code = self.terraform.apply()

        if return_code != 0:
            print("[-] ERROR")
            return False

        # Config changed lets reload it
        self.routing.reload_config()

        self.update_config_instances()

        print("[+] Done")
        return True


    def update_config_instances(self):

        print("[+] Removing deleted instances from the config")
        aws_instances = [item[0] for item in self.aws._list_aws() if item[1].startswith('Node_') and item[2] != 'terminated'] 

        config_ids = self.routing._get_config_instance_ids()

        for deleted_id in list(set(config_ids) - set(aws_instances)):
            print("[+] Removing instance %s from the config" % deleted_id)
            self.routing.remove_vpn_ip(deleted_id)

        print("[+] Done")
        return True

    def update_sendgrid(self):

        print("[+] Creating the SendGrid mail entries")

        config_mail_entries = self.config.get_mail_entries()

        current_mail = self.sendgrid.get_config()

        # Checking for deleted domains
        deleted_domains = list(set(current_mail.keys()) - set(config_mail_entries.keys()))
        for domain in deleted_domains:
            print("[+] [Sendgrid] Removing domain %s" % domain)
            self.sendgrid.delete_domain(domain)

        # Checking for new domains
        new_domains = list(set(config_mail_entries.keys()) - set(current_mail.keys()))
        for domain in new_domains:
            print("[+] [Sendgrid] Creating domain %s" % domain)
            self.sendgrid.new_domain(domain)

            current_mail[domain] = {
                'email': {},
            }

        for domain in current_mail:
            if domain in config_mail_entries:
                current_emails = config_mail_entries[domain].keys()
            else:
                current_emails = []

            # Checking for deleted emails
            deleted_emails = list(set(current_mail[domain]['email'].keys()) - set(current_emails))
            for email in deleted_emails:
                print("[+] [Sendgrid] Removing email %s" % email)
                self.sendgrid.delete_sender(email)

            # Checking for new emails
            new_emails = list(set(current_emails) - set(current_mail[domain]['email'].keys()))
            for email in new_emails:
                name = config_mail_entries[domain][email]

                print("[+] [Sendgrid] Creating email %s <%s>" % (name, email))
                self.sendgrid.new_sender(name, email)

        print("[+] Done")
        return True

    def clear_sendgrid(self):

        print("[+] Crearing the SendGrid mail entries")

        self.sendgrid.disable_clicktracking()

        current_mail = self.sendgrid.get_config()

        for domain in current_mail.keys():
            print("[+] [Sendgrid] Removing domain %s" % domain)
            self.sendgrid.delete_domain(domain)

        print("[+] Done")
        return True


    def update_cloudflare(self): 

        print("[+] Creating the DNS entries in cloudflare")

        self.cloudflare.set_encryption_mode(mode="full")

        current_mail = self.sendgrid.get_config()

        config_dns = self.config.get_dns()

        aws_instances = self.aws._list_aws() 

        instance_dict = {}
        for instance in aws_instances:
            # Ignore terminated instances
            if instance[2] == 'terminated':
                continue

            node_name = instance[1] 

            instance_dict[node_name] = instance[3] 

        config_dns_dict = {}
        for type, type_dns_list in config_dns.items():
            for info in type_dns_list:
                if type == 'A':
                    instance_name = "Node_%s_%s" % (info[1], info[2])

                    if instance_name in instance_dict:
                        for ip in instance_dict[instance_name]:
                            dns_hash = "A_%s_%s" % (info[0], ip)

                            config_dns_dict[dns_hash] = ('A', info[0], ip)
                elif type == 'proxy':
                    instance_name = "Node_%s_%s" % (info[1], info[2])

                    if instance_name in instance_dict:
                        for ip in instance_dict[instance_name]:
                            dns_hash = "proxy_%s_%s" % (info[0], ip)

                            config_dns_dict[dns_hash] = ('proxy', info[0], ip)
                else:
                    dns_hash = "%s_%s_%s" % (type, info[0], info[1])

                    config_dns_dict[dns_hash] = (type, info[0], info[1])

        # Mail entries
        for _, data in current_mail.items():
            for entry in data['dns']:
                dns_hash = "%s_%s_%s" % (entry['type'].upper(), entry['key'], entry['value'])
                config_dns_dict[dns_hash] = (entry['type'], entry['key'], entry['value'])

        current_dns_config = self.cloudflare.get_dns()
        current_dns_config_dict = {}
        for key, info in current_dns_config.items():
            if info['proxied'] == True:
                dns_hash = "proxy_%s_%s" % (key, info['content'])

                current_dns_config_dict[dns_hash] = ('proxy', key, info['content'])
            else:
                dns_hash = "%s_%s_%s" % (info['type'].upper(), key, info['content'])
                
                current_dns_config_dict[dns_hash] = (info['type'], key, info['content'])

        # Checking for deleted dns
        deleted_dns = list(set(current_dns_config_dict.keys()) - set(config_dns_dict.keys()))
        for dns_hash in deleted_dns:
            print("[+] [Cloudflare] Removing DNS [%s] %s => %s" % current_dns_config_dict[dns_hash])

            dns_info = current_dns_config_dict[dns_hash]
            if dns_info[0] == 'proxy':
                self.cloudflare.remove_dns(dns_info[1], dns_info[2], dns_type='A')
            else:
                self.cloudflare.remove_dns(dns_info[1], dns_info[2], dns_type=dns_info[0])

        # Checking for new domains
        new_dns = list(set(config_dns_dict.keys()) - set(current_dns_config_dict.keys()))
        for dns_hash in new_dns:
            print("[+] [Cloudflare] Creating DNS [%s] %s => %s" % config_dns_dict[dns_hash])

            dns_info = config_dns_dict[dns_hash]
            if dns_info[0] == 'proxy':
                self.cloudflare.new_dns(dns_info[1], dns_info[2], dns_type='A', proxied=True)
            else:
                self.cloudflare.new_dns(dns_info[1], dns_info[2], dns_type=dns_info[0])

        print("[+] Done")
        return True

    def clear_cloudflare(self): 
        print("[+] Clearing the DNS entries in cloudflare")

        current_dns_config = self.cloudflare.get_dns()
        for key, info in current_dns_config.items():
            print("[+] [Cloudflare] Removing DNS [%s] %s => %s" % (info['type'], key, info['content']))

            self.cloudflare.remove_dns(key, info['content'], dns_type=info['type'])

        print("[+] Done")
        return True

    def update_routing(self):

        print("[+] Creating the routing")

        # Delete all routes
        self.routing.clear_routing()

        routing_config = self.config.get_routing()
        
        aws_instances = self.aws._list_aws() 

        instance_dict = {}
        for instance in aws_instances:
            if instance[2] == 'terminated':
                continue

            node_name = instance[1] 

            instance_dict[node_name] = instance[0] 

        for routing_info in routing_config:
            self.routing.set_routing(instance_dict[routing_info['node_name']], routing_info['local_ip'], ','.join([str(port) for port in routing_info['ports']]))

        self.routing.apply()

        print("[+] Done")
        return True

    def clear_routing(self):

        print("[+] Clearing the routing")

        self.routing.clear_routing()

        print("[+] Done")
        return True

    def update_ansible(self):

        print("[+] Apply the playbooks")

        playbooks = self.config.get_playbooks()

        # Delete previous inventory files
        inventory_path = "ansible/inventory/"
        for file in os.listdir(inventory_path):
            file_path = os.path.join(inventory_path, file)
            if os.path.isfile(file_path):
                os.remove(file_path)

        previous_execution = configparser.ConfigParser()
        previous_execution.read(ANSIBLE_FILE)

        if not 'Execution' in previous_execution:
            previous_execution['Execution'] = {}

        for playbook in playbooks:
            playbook_hash = '%s_%s_%s_%s' % (playbook['local_ip'], playbook['mission'], playbook['name'], playbook['playbook'])

            if playbook_hash in previous_execution['Execution']:
                previous_args = json.loads(previous_execution['Execution'][playbook_hash])

                if playbook['args'] == previous_args:
                    print("[+] Skipping playbook: Mission: %s, Host: %s, Playbook: %s" % (playbook['mission'], playbook['name'], playbook['playbook']))
                    continue

            # Create inventory file
            inventory_file = "inventory_%s_%s" % (playbook['mission'], playbook['name'])
            f = open(inventory_path + inventory_file, 'w')
            f.write("""
[all:vars]
ansible_ssh_common_args='-o StrictHostKeyChecking=accept-new'

[host]
%s ansible_ssh_user=root ansible_ssh_private_key_file=../files/ansible
""" % playbook['local_ip'])
            f.close()

            # Execute the playblook
            runner = ansible_runner.run(
                private_data_dir="ansible",
                playbook=playbook['playbook'],
                extravars=playbook['args'],
                inventory=inventory_file,
            )

            if runner.rc == 0:
                print("[+] Playbook execution success: Mission: %s, Host: %s, Playbook: %s" % (playbook['mission'], playbook['name'], playbook['playbook']))

                previous_execution['Execution'][playbook_hash] = json.dumps(playbook['args'])

                with open(ANSIBLE_FILE, "w") as configfile:
                    previous_execution.write(configfile)

            else:
                print("Playbook execution failed!")
                print("STDERR:", runner.stderr.read())

        print("[+] Done")
        return True

    def destroy(self):
        if not self.delete_terraform():
            return

        if not self.clear_sendgrid():
            return

        if not self.clear_cloudflare():
            return

        if not self.clear_routing():
            return

    def execute_playbooks(self, mission, server):
        
        playbooks = self.config.get_playbooks()

        previous_execution = configparser.ConfigParser()
        previous_execution.read(ANSIBLE_FILE)

        if not 'Execution' in previous_execution:
            previous_execution['Execution'] = {}


        inventory_path = "ansible/inventory/"
        for playbook in playbooks:
            if playbook['mission'] == mission and playbook['name'] == server:
                # Create inventory file
                inventory_file = "inventory_%s_%s" % (playbook['mission'], playbook['name'])
                f = open(inventory_path + inventory_file, 'w')
                f.write("""
    [all:vars]
    ansible_ssh_common_args='-o StrictHostKeyChecking=accept-new'

    [host]
    %s ansible_ssh_user=root ansible_ssh_private_key_file=../files/ansible
    """ % playbook['local_ip'])
                f.close()

                # Execute the playblook
                runner = ansible_runner.run(
                    private_data_dir="ansible",
                    playbook=playbook['playbook'],
                    extravars=playbook['args'],
                    inventory=inventory_file,
                )

                if runner.rc == 0:
                    print("[+] Playbook execution success: Mission: %s, Host: %s, Playbook: %s" % (playbook['mission'], playbook['name'], playbook['playbook']))

                    playbook_hash = '%s_%s_%s_%s' % (playbook['local_ip'], playbook['mission'], playbook['name'], playbook['playbook'])
                    previous_execution['Execution'][playbook_hash] = json.dumps(playbook['args'])

                    with open(ANSIBLE_FILE, "w") as configfile:
                        previous_execution.write(configfile)

                else:
                    print("Playbook execution failed!")
                    print("STDERR:", runner.stderr.read())


