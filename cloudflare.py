import os
import sys
import requests
import configparser

class CloudFlare:
    def __init__(self):
        self.config = configparser.ConfigParser(interpolation=None)
        self.config.read(os.path.join(os.path.dirname(sys.argv[0]), 'redinfra.cfg'))

        self.api_key = self.config.get('CloudFlare', 'api')

    def query(self, uri, post=None):
        headers = {
            'Authorization':  "Bearer %s" % self.api_key,
            'Content-Type':  'application/json'
        }

        url = 'https://api.cloudflare.com/client/v4%s' % uri

        if not post:
            r = requests.get(url, headers=headers, json="")
        else:
            r = requests.post(url, headers=headers, json=post)

        return r.json()

    def delete(self, uri):
        headers = {
            'Authorization':  "Bearer %s" % self.api_key,
            'Content-Type':  'application/json'
        }

        url = 'https://api.cloudflare.com/client/v4%s' % uri

        r = requests.delete(url, headers=headers, json='')

        return r.json()


    def get_dns(self):
        output = {}

        json = self.query("/zones")

        for i in json["result"]:
            zone = i["name"]
            zone_id = i['id']

            dns_json = self.query("/zones/%s/dns_records" % zone_id)

            for dns_info in dns_json["result"]:

                output[dns_info['name']] = {
                    'type': dns_info['type'],
                    'content': dns_info['content'],
                    'proxied': dns_info['proxied']
                }

        return output


    def list_dns(self):
        print("DNS entries")

        json = self.query("/zones")

        for i in json["result"]:
            zone = i["name"]
            zone_id = i['id']

            print(" - %s" % zone)

            dns_json = self.query("/zones/%s/dns_records" % zone_id)

            for dns_info in dns_json["result"]:
                if dns_info['type'] == 'A':
                    print("\t %s %s %s (proxied: %s)" % (dns_info['name'].ljust(40), dns_info['type'].ljust(10), dns_info['content'].ljust(40), dns_info['proxied'] ))
                else:
                    print("\t %s %s %s" % (dns_info['name'].ljust(40), dns_info['type'].ljust(10), dns_info['content']))

  
    def new_dns(self, domain, value, dns_type='A', proxied=False):
        print("Setting new domain %s = %s => %s (proxied: %s)" % (domain, dns_type, value, proxied))

        json = self.query("/zones")

        for i in json["result"]:
            zone = i["name"]
            zone_id = i['id']

            if domain.endswith(zone):

                data = {
                    "content": value,
                    "type": dns_type,
                    "name": domain,
                    "proxied": proxied,
                }

                if dns_type == 'MX':
                    data['priority'] = 10

                dns_json = self.query("/zones/%s/dns_records" % zone_id, post=data)

                if dns_json['success'] == True:
                    print("Success !")
                else:
                    print("Fail: %s" % dns_json['errors'][0]['message'])




    def remove_dns(self, domain, value, dns_type='A'):
        print("Removing dns entry %s = %s => %s" % (domain, dns_type, value))

        json = self.query("/zones")

        found = False
        for i in json["result"]:
            zone = i["name"]
            zone_id = i['id']

            if domain.endswith(zone):

                dns_json = self.query("/zones/%s/dns_records" % zone_id)

                for dns_info in dns_json["result"]:
                    if domain == dns_info['name'] and dns_info['type'] == dns_type and dns_info['content'] == value:

                        delete_json = self.delete('/zones/%s/dns_records/%s' % (zone_id, dns_info['id']))

                        if delete_json['success'] == True:
                            found = True
                            print("Success !")
                        else:
                            print("Fail: %s" % delete_json['errors'][0]['message'])

                        return

        if not found:
            print("Unable to find DNS")








