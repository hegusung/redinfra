import os
import sys
import json
import time
import sendgrid 
import configparser

from lib.color import color

class SendGrid:

    def __init__(self, config, cloudflare):
        self.cloudflare = cloudflare
        self.config = config

        #self.config = configparser.ConfigParser(interpolation=None)
        #self.config.read(os.path.join(os.path.dirname(sys.argv[0]), 'redinfra.cfg'))

        #self.api_key = self.config.get('SendGrid', 'api')
        self.api_key = self.config.get_api_key('sendgrid_api')

        self.sg = sendgrid.SendGridAPIClient(api_key=self.api_key)

    def disable_clicktracking(self):
        # Disable Click Tracking globally
        data = {"enabled": False}

        try:
            response = self.sg.client.tracking_settings.click.patch(request_body=data)
            print(color("    [+] Click tracking has been disabled globally.", "green"))

            return 0
        except HTTPError as e:
            print(color("    [-] Failed to update settings: " + str(e), "red"))

            return 1

    def new_domain(self, domain):
        print(color("    [*] Registring the domain %s in SendGrid" % domain, "blue"))

        data = {
            "automatic_security": True,
            "default": False,
            "domain": domain,
            "subdomain": "mail",
        }
        try:
            response = self.sg.client.whitelabel.domains.post(request_body=data)
        except Exception as e:
            print(color("    [-] Failed to add domain to SendGrid", "red"))
            return 1

        if response.status_code == 201:
            print(color("    [+] Domain added to SendGrid", "green"))
        else:
            print(color("    [-] Failed to add domain to SendGrid: %s" % response.body, "red"))
            return 1

        response_json = json.loads(response.body)
        domain_id = response_json['id']

        print(color("    [*] Creating associated DNS entries", "blue"))

        try:
            for key, dns_entry in response_json['dns'].items():
                res = self.cloudflare.new_dns(dns_entry['host'], dns_entry['data'], dns_type=dns_entry['type'].upper())

                if res != 0:
                    print(color("    [-] Failed to add the DNS", "red"))
                    raise StopIteration
        except StopIteration:
            return 1

        # Adding DMARC
        res = self.cloudflare.new_dns("_dmarc.%s" % domain, "\"v=DMARC1; p=none;\"", dns_type="TXT")
        if res != 0:
            print(color("    [-] Failed to add the DNS", "red"))
            return 1

        print(color("    [*] DNS entries added to CloudFlare", "blue"))

        validated = True
        for _ in range(10):
            print(color("    [*] Waiting 10 seconds before validating", "blue"))

            time.sleep(10)

            print(color("    [*] Validating the domain", "blue"))

            try:
                response = self.sg.client.whitelabel.domains._(domain_id).validate.post()
            except Exception as e:
                print(color("    [-] Failed to validate the domain", "red"))
                return 1

            response_json = json.loads(response.body)
            validated = True
            for entry, info in response_json["validation_results"].items():
                if info['valid'] == False:
                    validated = False
                    break

            if validated:
                break

            print(color("    [-] Failed to validated the domain", "red"))
        
        if validated:
            print(color("    [+] Domain validated", "green"))
        else:
            print(color("    [-] Failed to validate the domain", "red"))

        return 0

    def get_config(self):
        email_config = {}

        params = {
            'exclude_subusers': 'true'
        }
        response = self.sg.client.whitelabel.domains.get(query_params=params)
        response_json = json.loads(response.body)

        for dom_info in response_json:
            email_config[dom_info['domain']] = {
                "email": {},
                "dns": [],
            }

            for key, dns_info in dom_info['dns'].items():
                email_config[dom_info['domain']]['dns'].append({
                    'type': dns_info['type'],
                    'key': dns_info['host'],
                    'value': dns_info['data']
                })
            email_config[dom_info['domain']]['dns'].append({
                'type': 'TXT',
                'key': "_dmarc.%s" % dom_info['domain'],
                'value': "\"v=DMARC1; p=none;\""
            })

        # This API bugs with forbidden, WHY ????
        try:
            response = self.sg.client.senders.get()
            response_json = json.loads(response.body)

            for sender_info in response_json:
                domain = sender_info['from']['email'].split('@')[-1]
                email_config[domain]['email'][sender_info['from']['email']] = sender_info['from']['name']
        except Exception as e:
            print(color("    [-] SENDGRID API ERROR: get senders", "red"))

        return email_config



    def list_domains(self):
        print("[+] Domains:")

        params = {
            'exclude_subusers': 'true'
        }
        response = self.sg.client.whitelabel.domains.get(query_params=params)
        response_json = json.loads(response.body)

        for dom_info in response_json:
            print(" > %s (valid: %s)" % (dom_info['domain'], dom_info['valid']))

        return 0

    def delete_domain(self, domain):
        print(color("    [*] Getting the domain ID for the domain %s from SendGrid" % domain, "blue"))

        params = {
            'domain': domain,
            'exclude_subusers': 'true',
            'limit': 1
        }
        response = self.sg.client.whitelabel.domains.get(query_params=params)
        response_json = json.loads(response.body)[0]

        if len(response_json) == 0:
            print(color("    [-] Domain not found", "red"))
            return 1

        domain_id = response_json["id"]

        print(color("    [*] Deleting associated DNS entries", "blue"))

        try:
            for key, dns_entry in response_json['dns'].items():
                res = self.cloudflare.remove_dns(dns_entry['host'], dns_entry['data'], dns_type=dns_entry['type'].upper())

                if res == 1:
                    print(color("    [-] Failed to remove the DNS", "red"))
                    #raise StopIteration
                elif res == 2:
                    print(color("    [-] DNS entry does not exist", "red"))
        except StopIteration:
            return 1

        # Adding DMARC
        res = self.cloudflare.remove_dns("_dmarc.%s" % domain, "\"v=DMARC1; p=none;\"", dns_type="TXT")
        if res != 0:
            print(color("    [-] Failed to remove the DNS", "red"))
            #return 1

        print(color("    [+] DNS entries removed from CloudFlare", "green"))

        print(color("    [*] Removing the senders related to the domain %s" % domain, "blue"))

        try:
            response = self.sg.client.senders.get()
            response_json = json.loads(response.body)

            for sender_info in response_json:
                sender_name = sender_info['from']['name']
                sender_email = sender_info['from']['email']

                if sender_email.endswith("@%s" % domain):
                    print(color("    [*] Deleting sender %s <%s>" % (sender_name, sender_email), "blue"))
                    sender_id = sender_info['id']

                    try:
                        response = self.sg.client.senders._(sender_id).delete()
                    
                        print(color("    [+] Sender deleted", "green"))
                    except Exception as e:
                        print(color("    [-] Failed to delete the sender", "red"))

            print(color("    [+] Senders removed", "green"))
        except Exception:
            print(color("    [-] SENDGRID ERROR", "red"))

        print(color("    [*] Removing the domain %s from SendGrid" % domain, "blue"))

        try:
            response = self.sg.client.whitelabel.domains._(domain_id).delete()
        except Exception as e:
            print(color("    [-] Failed to remove the domain", "red"))
            return 1

        if response.status_code == 204:
            print(color("    [+] Domain removed", "green"))
        else:
            print(color("    [-] Failed to remove the domain", "red"))
            return 1

        return 0

    def list_senders(self):
        print("[+] Senders:")

        response = self.sg.client.senders.get()
        response_json = json.loads(response.body)

        for sender_info in response_json:
            print(" > %s <%s> (verified: %s)" % (sender_info['from']['name'], sender_info['from']['email'], sender_info['verified']['status']))

        return 0

    def new_sender(self, name, email):
        print(color("    [*] Registring the sender %s <%s> in SendGrid" % (name, email), "blue"))

        data = {
            "address": "*",
            "city": "*",
            "country": "*",
            "from": {
                "email": email,
                "name": name
            },
            "nickname": name,
            "reply_to": {
                "email": email,
                "name": name
            },
            "state": "",
            "zip": ""
        }
        try:
            response = self.sg.client.senders.post(request_body=data)
        except Exception as e:
            print(color("    [-] Failed to register the sender", "red"))
            return 1

        if response.status_code == 201:
            print(color("    [+] Sender %s <%s> registered" % (name, email), "green"))
            return 0

        print(color("    [-] Failed to register the sender", "red"))
        return 1

    def delete_sender(self, email):
        print(color("    [+] Deleting the sender %s in SendGrid" % (email,), "blue"))

        response = self.sg.client.senders.get()
        response_json = json.loads(response.body)

        sender_id = None
        for sender_info in response_json:
            sender_email = sender_info['from']['email']

            if sender_email == email:
                sender_id = sender_info['id']
                break
        else:
            print(color("    [-] Sender not found", "red"))
            return 1

        if sender_id == None:
            print(color("    [-] Sender not found", "red"))
            return 1

        try:
            response = self.sg.client.senders._(sender_id).delete()
        except Exception as e:
            print(color("    [-] Failed to delete the sender", "red"))
            return 1

        if response.status_code == 204:
            print(color("    [+] Sender deleted", "green"))
            return 0

        print(color("    [-] Failed to register the sender", "red"))
        return 1


