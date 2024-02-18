import configparser
from pyroute2 import IPDB, NDB
import os

#os.environ["XTABLES_LIBDIR"] = "/usr/lib/xtables"

CONFIG_FILE = "redinfra.cfg"
ROUTING_CONFIG_FILE = "routing.cfg"

class Routing():

    def __init__(self):
        self.config = configparser.ConfigParser()
        self.routing_config = configparser.ConfigParser()

        self.config.read(CONFIG_FILE)
        self.routing_config.read(ROUTING_CONFIG_FILE)

        if not 'VPN' in self.routing_config.sections():
            self.routing_config['VPN'] = {}

            with open(ROUTING_CONFIG_FILE, "w") as configfile:
                self.routing_config.write(configfile)

        if not 'Routing' in self.routing_config.sections():
            self.routing_config['Routing'] = {}

            with open(ROUTING_CONFIG_FILE, "w") as configfile:
                self.routing_config.write(configfile)

    def show_config(self, config):
        for c in config:
            instance = c[-3]

            if instance != None:
                if instance in self.routing_config['VPN']:
                    c.append(self.routing_config['VPN'][instance])
                else:
                    c.append(None)

                if instance in self.routing_config['Routing']:
                    c.append(self.routing_config['Routing'][instance])
                else:
                    c.append(None)
            else:
                c += [None, None]

        return config

    def set_vpn_ip(self, instance, ip):
        # Create a specific IP for the AWS 192.168.56.2 -> 192.168.56.102
        ip_parts = ip.split('.')
        if int(ip_parts[-1]) >= 100:
            raise Exception("AWS VPN ip should be between 1 and 99")
        ip_parts[-1] = str(int(ip_parts[-1]) + 100)
        ip_router = ".".join(ip_parts)

        print("[+] Instance ip: %s, Corresponding router ip: %s" % (ip, ip_router))

        self.routing_config['VPN'][instance] = "%s:%s" % (ip, ip_router)

        with open(ROUTING_CONFIG_FILE, "w") as configfile:
            self.routing_config.write(configfile)

    def list_vpn_ip(self):
        print("Instances VPN IPs:")
        for instance, ip in self.routing_config['VPN'].items():
            ip_vpn_aws = ip.split(':')[0]
            ip_vpn_router = ip.split(':')[-1]
            print(" - %s : %s -> %s" % (instance, ip_vpn_aws, ip_vpn_router))

    def remove_vpn_ip(self, instance):
        try:
            del self.routing_config['VPN'][instance]
        except KeyError:
            pass

        with open(ROUTING_CONFIG_FILE, "w") as configfile:
            self.routing_config.write(configfile)


    def set_routing(self, instance, ip, ports):
        self.routing_config['Routing'][instance] = "%s:%s" % (ip, ports)

        with open(ROUTING_CONFIG_FILE, "w") as configfile:
            self.routing_config.write(configfile)

    def list_routing(self):
        print("Routing:")
        for instance, ip in self.routing_config['Routing'].items():
            print(" - %s : %s" % (instance, ip))

    def remove_routing(self, instance):
        try:
            del self.routing_config['Routing'][instance]
        except KeyError:
            pass

        with open(ROUTING_CONFIG_FILE, "w") as configfile:
            self.routing_config.write(configfile)

    def apply(self):
        print("[+] Enabling ip_forward")
        os.system("echo 1 >/proc/sys/net/ipv4/ip_forward")

        vpn_interface = self.config['Routing']['vpn_interface']
        redinfra_chain = self.config['Routing']['iptables_chain']
        vpn_range = self.config['Routing']['vpn_range']
        redirector_vpn_ip = self.config['Routing']['redirector_vpn_ip']
        rule_priority = int(self.config['Routing']['rule_priority'])

        # flush
        IPTablesManager.flush_rules(redinfra_chain, rule_priority)

        # Create default chain
        IPTablesManager.create_chain(redinfra_chain, vpn_range, vpn_interface)

        # Enable packet marking
        print("[+] Enabling packet marking")
        cmd = 'iptables -t mangle -A PREROUTING -j CONNMARK --restore-mark'
        print("> %s" % cmd)
        os.system(cmd)


        # Create AWS to local node
        # use table_id as the marking value
        table_id = int(self.config['Routing']['rule_start_table'])
        for aws_instance, local_ip_ports in self.routing_config['Routing'].items():
            aws_vpn_ip = self.routing_config['VPN'][aws_instance].split(':')[0]
            corresponding_vpn_ip = self.routing_config['VPN'][aws_instance].split(':')[-1]
            local_ip = local_ip_ports.split(':')[0]
            if len(local_ip_ports.split(':')[1]) != 0:
                ports = [int(p) for p in local_ip_ports.split(':')[1].split(',')]
            else:
                ports = []

            print("[+] Creating the IP %s in the VPN interface %s" % (corresponding_vpn_ip, vpn_interface))
            range_subnet = vpn_range.split("/")[-1]
            cmd = 'ip addr add %s/%s dev %s' % (corresponding_vpn_ip, range_subnet, vpn_interface)
            print("> %s" % cmd)
            os.system(cmd)

            # Set the marking rule
            print("[+] Marking packet destined to %s with mark %d" % (corresponding_vpn_ip, table_id))
            cmd = 'iptables -t mangle -A PREROUTING -d %s -m state --state NEW -j CONNMARK --set-mark %d' % (corresponding_vpn_ip, table_id)
            print("> %s" % cmd)
            os.system(cmd)

            print("[+] Creating iptable rule for %s -> %s:%s" % (aws_vpn_ip, local_ip, str(ports)))
            if len(ports) != 0:
                for port in ports:
                    cmd = 'iptables -t nat -A %s_dnat -p tcp -d %s --dport %d -j DNAT --to-destination %s' % (redinfra_chain, corresponding_vpn_ip, port, local_ip)
                    print("> %s" % cmd)
                    os.system(cmd)
                    cmd = 'iptables -A FORWARD -d %s -p tcp --dport %d -j ACCEPT' % (aws_vpn_ip, port)
                    print("> %s" % cmd)
                    os.system(cmd)
            # Accept already established connections
            cmd = 'iptables -A FORWARD -d %s -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT' % (local_ip,)
            print("> %s" % cmd)
            os.system(cmd)
                
            cmd = 'iptables -t nat -A %s_snat -s %s -j SNAT --to-source %s' % (redinfra_chain, local_ip, redirector_vpn_ip)
            print("> %s" % cmd)
            os.system(cmd)
            #cmd = 'iptables -A FORWARD -s %s -d %s -j ACCEPT' % (local_ip, aws_vpn_ip)
            cmd = 'iptables -A FORWARD -s %s -j ACCEPT' % (local_ip,)
            print("> %s" % cmd)
            os.system(cmd)

            table_id += 1

        # Create outgoing rules
        ipdb = IPDB()
        ndb = NDB()

        table_id = int(self.config['Routing']['rule_start_table'])
        for aws_instance, local_ip in self.routing_config['Routing'].items():
            #print("==================")
            #print(aws_instance)
            #print(local_ip)
            aws_vpn_ip = self.routing_config['VPN'][aws_instance].split(':')[0]
            corresponding_vpn_ip = self.routing_config['VPN'][aws_instance].split(':')[-1]
            local_ip = local_ip.split(':')[0]

            spec = {'src': '%s/32' % local_ip,
                    'table': table_id,
                    'priority': int(self.config['Routing']['rule_priority']),
                    }
            print("[+] Creating rule from %s to table %d" % (local_ip, table_id))
            try:
                # fwmark same as table id
                ndb.rules.create(src='%s/32' % local_ip, fwmark=table_id, table=table_id, priority=int(self.config['Routing']['rule_priority'])).commit()
            except Exception as e:
                # Exception raised but it works....
                pass
            #ipdb.rules.add(spec).commit()
            spec = {'dst': 'default',
                    'table': table_id,
                    'gateway': aws_vpn_ip,
                    }
            print("[+] Creating default route to %s in table %d" % (aws_vpn_ip, table_id))
            ndb.routes.create(dst='default', table=table_id, gateway=aws_vpn_ip).commit()
            #ipdb.routes.add(spec).commit()

            table_id += 1

class IPTablesManager():

    @classmethod
    def create_chain(self, redinfra_chain, vpn_range, vpn_interface):
        # TODO: use pyroute2.nftables

        # Create chain
        print("Creating iptables chains")
        cmd = "iptables -t nat -N %s_dnat" % redinfra_chain
        print("> %s" % cmd)
        os.system(cmd)
        cmd = "iptables -t nat -N %s_snat" % redinfra_chain
        print("> %s" % cmd)
        os.system(cmd)

        rule_exist = os.system("iptables -t nat -C PREROUTING -d %s -j %s_dnat" % (vpn_range, redinfra_chain)) == 0
        if not rule_exist:
            print("Creating PREROUTING rule linked to %s_dnat" % redinfra_chain)
            cmd = "iptables -t nat -A PREROUTING -d %s -j %s_dnat" % (vpn_range, redinfra_chain)
            print("> %s" % cmd)
            os.system(cmd)

        rule_exist = os.system("iptables -t nat -C POSTROUTING -o %s -j %s_snat" % (vpn_interface, redinfra_chain)) == 0
        if not rule_exist:
            print("Creating POSTROUTING rule linked to %s_snat" % redinfra_chain)
            cmd = "iptables -t nat -A POSTROUTING -o %s -j %s_snat" % (vpn_interface, redinfra_chain)
            print("> %s" % cmd)
            os.system(cmd)

    @classmethod
    def flush_rules(self, redinfra_chain, rule_priority):
        # TODO: use pyroute2.nftables

        print("Flushing IPTables rules")

        # Flush iptables
        cmd = "iptables -t nat -F %s_dnat" % redinfra_chain
        print("> %s" % cmd)
        os.system(cmd)
        cmd = "iptables -t nat -F %s_snat" % redinfra_chain
        print("> %s" % cmd)
        os.system(cmd)
        cmd = "iptables -t mangle -F PREROUTING"
        print("> %s" % cmd)
        os.system(cmd)
        cmd = "iptables -F FORWARD"
        print("> %s" % cmd)
        os.system(cmd)

        # Flush rules
        ipdb = IPDB()
        ndb = NDB()

        print("Flushing IP route and rules")
        for rule in list(ndb.rules):
            if rule.priority == rule_priority:
                print("> Deleting route table %d" % rule.table)
                try:
                    while True:
                        ndb.routes[{'table': rule.table}].remove().commit()
                except KeyError:
                    pass

                """
                try:
                    for route in ndb.routes:
                        if route.table == rule.table:
                            print(route)
                            print(type(route))
                            route.remove().commit()
                except KeyError:
                    pass
                """
                print("> Deleting rule linked to table %d" % rule.table)
                ndb.rules[{'table': rule.table}].remove().commit()


