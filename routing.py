import configparser

CONFIG_FILE = "routing.cfg"

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


    def set_routing(self, instance, ip):
        self.config['Routing'][instance] = ip

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
