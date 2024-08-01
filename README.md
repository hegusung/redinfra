# RedInfra
Easily deploy redirectors through AWS, manage DNS entries and route outgoing traffic

Features:
  * Route an internet-exposed AWS node to a C&C for specific ports
  * Route an operator computer traffic to internet through an AWS node
  * Start/Stop AWS instances
  * Renew/Associate/Dissociate Elastic IPs to AWS instances
  * Manage DNS entries

## Usage

To list the current configuration:
```
./redinfra.py --show-config
```

To apply the routing (after you checked the config):
```
./redinfra.py --apply
```

### Setting up DNS entries

#### Listing current DNS entries
```
./redinfra.py --list-dns
```

#### Add a DNS entry
```
./redinfra.py --new-dns <domain> <ip>
```

#### Remove a DNS entry
```
./redinfra.py --remove-dns <domain> <ip>
```

### Setting up the AWS instances and Elastic IPs

#### Listing current AWS instances
```
./redinfra.py --list-aws
```

#### Start an instance
```
./redinfra.py --start-aws <aws-instance>
```

#### Stop an instance
```
./redinfra.py --stop-aws <aws-instance>
```

#### Listing current Elastic IPs
```
./redinfra.py --list-elastic-ips
```

#### Associate an Elastic IP to an instance
```
./redinfra.py --associate-ip <elastic-ip> <aws-instance>
```

#### Dissociate an Elastic IP from an instance
```
./redinfra.py --associate-ip <elastic-ip>
```

#### Renew an Elastic IP
```
./redinfra.py --renew-ip <elastic-ip>
```

### Route an instance with a node

Current routing can be listed with
```
./redinfra.py --list-routing
```

#### C&C configuration (port 80 and 443 from an instance rooted to the C&C)
```
./redinfra.py --set-routing <aws_instance> <c&c_local_ip> 80,443

# Check the config
./redinfra.py --show-config

# Apply the config
./redinfra.py --apply
```

#### Outgoing traffic routing
```
./redinfra.py --set-routing <aws_instance> <attacker_host_local_ip> ''

# Check the config
./redinfra.py --show-config

# Apply the config
./redinfra.py --apply
```

The attacker host default route must be the router

Remember to disable IPv6

## Install

### Preparing the router

Connect to the routing server

#### Clone the redinfra project

Clone the redinfra project
```
git clone https://github.com/hegusung/redinfra
cd redinfra
pip3 install -r requirements.txt
```

#### Create the OpenVPN server

Clone and setup the openvpn-install project
```
git clone https://github.com/angristan/openvpn-install.git
cd openvpn-install
./openvpn-install.sh
```

  * Edit the /etc/openvpn/server.conf
  * Add "client-to-client" to the configuration
  * Change "dev tun" to "dev tap"
  * Remove the following line : 'push "redirect-gateway def1 bypass-dhcp"'

To prevent connections from the VPN to the router
```
iptables -A INPUT -s 192.168.56.0/24 -j DROP
```

#### Generate the EC2 configuration

Execute the following and follow the instructions
```
./openvpn-install.sh
```

### Preparing AWS

#### Generating API keys

  * Go to your AWS interface > Identity and Access Management (IAM) > Access management > Users
  * Select the user to to connect to AWS using the API
  * Go to the "Security credentials" tab > Access keys section
  * Generate an access key
  * Put this access key in the redinfra.cfg file  (create this file from the redinfra.cfg.sample)

#### Add a domain from AWS to manage

  * Go to your AWS interface > Route 53 > Hosted zone
  * Click on "Create hosted zone"
  * Fill the information and "Create hosted zone"

#### Create an EC2 instance

  * Go to your AWS interface > EC2
  * Select the desired region (top-right corner)
  * Make sure the region is provided in the redinfra.cfg file so the script can find the instance
  * Go to Instances > Instances
  * Create an instance by clicking on "Launch instances" (top-right corner)
  * Once the instance is created, click on it
  * Go to Security tab and set the firewall parameters, generally you need the following
      * Inbound rules:
          * port 22, to connect to the instance and configure it later on
          * the port to be redirected to the C&C, if any
      * Outbound rules:
          * All port to 0.0.0.0/0

#### Create an elastic IP

  * Go to your AWS interface > EC2
  * Select the desired region (top-right corner)
  * Make sure the region is provided in the redinfra.cfg file so the script can find the instance
  * Go to Network & Security > Elastic IPs
  * Create an instance by clicking on "Allocate Elastic IP address" (top-right corner)
  * Allocate the Elastic IP to the instance

### Preparing the EC2 instance

Transfer the Openvpn from the Router to the EC2 instance
```
scp -i aws_ssh_key.pem Node.ovpn ec2-user@<aws_public_ip>:.
```

Connect to the EC2 using the SSH key
```
ssh -i aws_ssh_key.pem ec2-user@<aws_public_ip>
```
#### Install openvpn

Install openvpn in the EC2 instance
```
# Install EC2 extensions
amazon-linux-extras install epel
yum update
# Install OpenVPN
yum install openvpn
```

Edit the Openvpn config file
  * change "dev tun" to "dev tap"

Copy the configuration 
```
sudo cp Node.ovpn /etc/openvpn/client/Node.conf
```

Start OpenVPN service

```
systemctl start openvpn-client@Node
systemctl enable openvpn-client@Node
```

#### Configure the VPN IP on the router

Connect to the router, setup the VPN IP of the newly generated EC2 instance with the following command:
```
./redinfra.py --set-vpn-ip <aws_instance> <vpn_ip>
```

Save the given router IP, it will be useful for after... (on the instance config)

VPN config can be listed with:
```
./redinfra.py --list-vpn-ip
```

#### Setup the routing on the instance

Execute the following commands
```
echo 1 >/proc/sys/net/ipv4/ip_forward
# Make this persistent, edit the /etc/sysctl.d/00-defaults.conf file:
net.ipv4.ip_forward = 1

# setup iptables
iptables -F FORWARD
iptables -t nat -A POSTROUTING -s <ip_vpn_router> -j MASQUERADE
iptables -t nat -A PREROUTING -d <ip_local_aws> -p tcp ! --dport 22 -j DNAT --to-destination <ip_vpn_router_given>   # usually the ip + 100 given when saving the AWS VPN IP in redinfra.py

# Make this persistent
yum install iptables-services -y
systemctl enable iptables
systemctl start iptables
service iptables save
```

