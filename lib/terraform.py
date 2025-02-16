import os
import os.path
from jinja2 import Environment, FileSystemLoader
from python_terraform import *
from python_terraform import Terraform as TF

TERRAFORM_PATH = "terraform"

class Terraform:

    def __init__(self, config):
        self.config = config

        file_loader = FileSystemLoader('./templates') # directory of template file
        self.env = Environment(loader=file_loader)

    def create_tf_files(self):
        # Default config shared by all regions
        regions = self.config.get_cloud_regions()

        self.create_default_files(regions)

        # VPN config
        vpn_region = self.config.get_vpn_region()

        self.create_vpn_file(vpn_region)

        # Node config
        for node_info in self.config.get_nodes():
            self.create_node_file(node_info)

    def create_default_files(self, regions):
        template = self.env.get_template("default.tf.j2")

        for region in regions:
            output = template.render(region=region)

            with open("./terraform/default_%s.tf" % region, "w") as f:
                f.write(output)

    def create_vpn_file(self, region):
        template = self.env.get_template("vpn.tf.j2")

        ami = self.config.get_ami(region)
        base_vpn_ip = self.config.get_routing_config()['vpn_range'].split('/')[0]
        tags = self.config.get_tags()
        instance_type = self.config.get_vpn_instance_type()
            
        output = template.render(name="RedInfraVPN", ami=ami, region=region, base_vpn_ip=base_vpn_ip, tags=tags, instance_type=instance_type)

        with open("./terraform/vpn.tf", "w") as f:
            f.write(output)

    def create_node_file(self, node_info):
        template = self.env.get_template("node.tf.j2")

        region = node_info['region']
        name = "%s_%s" % (node_info['mission'], node_info['name'])
        ports = node_info['ports']
        instance_type = node_info['instance_type']
        tags = self.config.get_tags()

        ami = self.config.get_ami(region)
            
        output = template.render(name=name, ami=ami, region=region, ports=ports, tags=tags, instance_type=instance_type)

        with open("./terraform/node_%s.tf" % name, "w") as f:
            f.write(output)

    def delete_terraform_files(self):
        folder_path = TERRAFORM_PATH
        for file in os.listdir(folder_path):
            file_path = os.path.join(folder_path, file)
            if os.path.isfile(file_path) and file.endswith(".tf"):  # Check if it's a terraform file (not a folder)
                os.remove(file_path)

        folder_path = TERRAFORM_PATH + "/inventory"
        for file in os.listdir(folder_path):
            file_path = os.path.join(folder_path, file)
            if os.path.isfile(file_path):  # Check if it's a file (not a folder)
                os.remove(file_path)

        folder_path = TERRAFORM_PATH + "/vars"
        for file in os.listdir(folder_path):
            file_path = os.path.join(folder_path, file)
            if os.path.isfile(file_path):  # Check if it's a file (not a folder)
                os.remove(file_path)

    def apply(self):
        tf = TF(working_dir=TERRAFORM_PATH)

        # Run terraform init
        print("[+] Running terraform init...")
        init_result = tf.init()

        # Check if init was successful
        if init_result[0] == 0:
            print("[+] Terraform init successful!")
        else:
            print("[-] Error during terraform init")
            print(init_result[1])            
            return 1

        # Run terraform apply
        print("[+] Running terraform apply...")
        apply_result = tf.apply(skip_plan=True, auto_approve=True)

        # Check if apply was successful
        if apply_result[0] == 0:
            print("[+] Terraform apply successful!")
        else:
            print("[-] Error during terraform apply")
            print(apply_result[2])            
            return 1

        return 0

    def destroy(self):
        tf = TF(working_dir=TERRAFORM_PATH)

        # Run terraform init
        print("[+] Running terraform init...")
        init_result = tf.init()

        # Check if init was successful
        if init_result[0] == 0:
            print("[+] Terraform init successful!")
        else:
            print("[-] Error during terraform init")
            print(init_result[1])            
            return 1

        # Run terraform apply
        print("[+] Running terraform destroy...")
        destroy_result = tf.destroy(force=IsNotFlagged, auto_approve=True)

        # Check if apply was successful
        if destroy_result[0] == 0:
            print("[+] Terraform destroy successful!")
        else:
            print("[-] Error during terraform apply")
            print(destroy_result[2])            
            return 1

        return 0




        
