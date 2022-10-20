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
