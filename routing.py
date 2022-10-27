import configparser
from pyroute2 import IPDB
import os

#os.environ["XTABLES_LIBDIR"] = "/usr/lib/xtables"

CONFIG_FILE = "routing.cfg"

IPTABLES_CHAIN = "redinfra"
VPN_RANGE = "10.8.0.0/16"
START_TABLE = 10
RULE_PRIORITY = 30000

class Routing():

    def __init__(self):
        self.config = configparser.ConfigParser()

        self.config.read(CONFIG_FILE)

        if not 'VPN' in self.config.sections():
            self.config['VPN'] = {}

            with open(CONFIG_FILE, "w") as configfile:
                self.config.write(configfile)

        if not 'Routing' in self.config.sections():
            self.config['Routing'] = {}

            with open(CONFIG_FILE, "w") as configfile:
                self.config.write(configfile)

    def show_config(self, config):
        for c in config:
            instance = c[-1]

            if instance != None:
                if instance in self.config['VPN']:
                    c.append(self.config['VPN'][instance])
                else:
                    c.append(None)

                if instance in self.config['Routing']:
                    c.append(self.config['Routing'][instance])
                else:
                    c.append(None)
            else:
                c += [None, None]

        return config

    def set_vpn_ip(self, instance, ip):
        self.config['VPN'][instance] = ip

        with open(CONFIG_FILE, "w") as configfile:
            self.config.write(configfile)

    def list_vpn_ip(self):
        print("Instances VPN IPs:")
        for instance, ip in self.config['VPN'].items():
            print(" - %s : %s" % (instance, ip))

    def remove_vpn_ip(self, instance):
        try:
            del self.config['VPN'][instance]
        except KeyError:
            pass

        with open(CONFIG_FILE, "w") as configfile:
            self.config.write(configfile)


    def set_routing(self, instance, ip, ports):
        self.config['Routing'][instance] = "%s:%s" % (ip, ports)

        with open(CONFIG_FILE, "w") as configfile:
            self.config.write(configfile)

    def list_routing(self):
        print("Routing:")
        for instance, ip in self.config['Routing'].items():
            print(" - %s : %s" % (instance, ip))

    def remove_routing(self, instance):
        try:
            del self.config['Routing'][instance]
        except KeyError:
            pass

        with open(CONFIG_FILE, "w") as configfile:
            self.config.write(configfile)

    def apply(self):
        os.system("echo 1 >/proc/sys/net/ipv4/ip_forward")

        # flush
        IPTablesManager.flush_rules()

        # Create default chain
        IPTablesManager.create_chain()

        # Create AWS to local node
        for aws_instance, local_ip_ports in self.config['Routing'].items():
            aws_vpn_ip = self.config['VPN'][aws_instance]
            local_ip = local_ip_ports.split(':')[0]
            ports = [int(p) for p in local_ip_ports.split(':')[1].split(',')]

            for port in ports:
                os.system('iptables -t nat -A %s -p tcp -s %s --dport %d -j DNAT --to-destination %s' % (IPTABLES_CHAIN, aws_vpn_ip, port, local_ip))
                os.system('iptables -A FORWARD -s %s -d %s -p tcp --dport %d -j ACCEPT' % (aws_vpn_ip, local_ip, port))
            os.system('iptables -A FORWARD -s %s -d %s -j ACCEPT' % (local_ip, aws_vpn_ip))

        # Create outgoing rules
        ipdb = IPDB()

        table_id = START_TABLE
        for aws_instance, local_ip in self.config['Routing'].items():
            aws_vpn_ip = self.config['VPN'][aws_instance]
            local_ip = local_ip_ports.split(':')[0]

            spec = {'src': local_ip,
                    'table': table_id,
                    'priority': RULE_PRIORITY,
                    }
            ipdb.rules.add(spec).commit()
            spec = {'dst': 'default',
                    'table': table_id,
                    'gateway': aws_vpn_ip,
                    }
            ipdb.routes.add(spec).commit()

            table_id += 1

class IPTablesManager():

    @classmethod
    def create_chain(self):
        # TODO: use pyroute2.nftables

        #os.system("iptables -N %s" % IPTABLES_CHAIN)
        os.system("iptables -t nat -N %s" % IPTABLES_CHAIN)
        print("iptables -t nat -N %s" % IPTABLES_CHAIN)

        rule_exist = os.system("iptables -t nat -C PREROUTING -s %s -p tcp -j %s" % (VPN_RANGE, IPTABLES_CHAIN)) == 0
        if not rule_exist:
            os.system("iptables -t nat -A PREROUTING -s %s -p tcp -j %s" % (VPN_RANGE, IPTABLES_CHAIN))
            print("iptables -t nat -A PREROUTING -s %s -p tcp -j %s" % (VPN_RANGE, IPTABLES_CHAIN))

    @classmethod
    def flush_rules(self):
        # TODO: use pyroute2.nftables

        # Flush iptables
        os.system("iptables -t nat -F %s" % IPTABLES_CHAIN)
        print("iptables -t nat -F %s" % IPTABLES_CHAIN)
        os.system("iptables -F FORWARD")
        print("iptables -F FORWARD")

        # Flush rules
        ipdb = IPDB()
        for rule in list(ipdb.rules):
            if rule.priority == RULE_PRIORITY:
                try:
                    for route in ipdb.routes.tables[rule.table]:
                        route.remove().commit()
                except KeyError:
                    pass
                ipdb.rules[rule.table].remove().commit()


