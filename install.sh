# Install Ansible
apt update
apt install -y software-properties-common
add-apt-repository --yes --update ppa:ansible/ansible
apt install -y ansible

# Install Terraform
apt install -y gnupg software-properties-common curl
#curl -fsSL https://apt.releases.hashicorp.com/gpg | tee /usr/share/keyrings/hashicorp-archive-keyring.gpg > /dev/null
wget -O- https://apt.releases.hashicorp.com/gpg | gpg --dearmor | tee /usr/share/keyrings/hashicorp-archive-keyring.gpg > /dev/null

echo "deb [signed-by=/usr/share/keyrings/hashicorp-archive-keyring.gpg] https://apt.releases.hashicorp.com $(lsb_release -cs) main" | tee /etc/apt/sources.list.d/hashicorp.list
apt update
apt install -y terraform

# Install additional dependencies
apt install -y python3-pip unzip sshpass
pip3 install boto3 botocore --break-system-packages

# Install pip requirements
pip3 install -r requirements.txt --break-system-packages

# Verify
ansible --version
terraform version


