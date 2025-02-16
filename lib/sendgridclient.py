import os
import sys
import json
import time
import sendgrid 
import configparser

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
            print("[+] Click tracking has been disabled globally.")

            return 0
        except HTTPError as e:
            print("[-] Failed to update settings:", e)

            return 1

    def new_domain(self, domain):
        print("[+] Registring the domain %s in SendGrid" % domain)

        data = {
            "automatic_security": True,
            "default": False,
            "domain": domain,
            "subdomain": "mail",
        }
        try:
            response = self.sg.client.whitelabel.domains.post(request_body=data)
        except Exception as e:
            print("[-] Failed to add domain to SendGrid")
            return 1

        if response.status_code == 201:
            print("[+] Domain added to SendGrid")
        else:
            print("[-] Failed to add domain to SendGrid: %s" % response.body)
            return 1

        response_json = json.loads(response.body)
        domain_id = response_json['id']

        print("[+] Creating associated DNS entries")

        try:
            for key, dns_entry in response_json['dns'].items():
                res = self.cloudflare.new_dns(dns_entry['host'], dns_entry['data'], dns_type=dns_entry['type'].upper())

                if res != 0:
                    print("[-] Failed to add the DNS")
                    raise StopIteration
        except StopIteration:
            return 1

        # Adding DMARC
        res = self.cloudflare.new_dns("_dmarc.%s" % domain, "\"v=DMARC1; p=none;\"", dns_type="TXT")
        if res != 0:
            print("[-] Failed to add the DNS")
            return 1

        print("[+] DNS entries added to CloudFlare")

        validated = True
        for _ in range(10):
            print("[+] Waiting 10 seconds before validating")

            time.sleep(10)

            print("[+] Validating the domain")

            try:
                response = self.sg.client.whitelabel.domains._(domain_id).validate.post()
            except Exception as e:
                print("[-] Failed to validate the domain")
                return 1

            response_json = json.loads(response.body)
            validated = True
            for entry, info in response_json["validation_results"].items():
                if info['valid'] == False:
                    validated = False
                    break

            if validated:
                break

            print("[-] Failed to validated the domain")
        
        if validated:
            print("[+] Domain validated")
        else:
            print("[-] Failed to validate the domain")

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

        response = self.sg.client.senders.get()
        response_json = json.loads(response.body)

        for sender_info in response_json:
            domain = sender_info['from']['email'].split('@')[-1]
            email_config[domain]['email'][sender_info['from']['email']] = sender_info['from']['name']

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
        print("[+] Getting the domain ID for the domain %s from SendGrid" % domain)

        params = {
            'domain': domain,
            'exclude_subusers': 'true',
            'limit': 1
        }
        response = self.sg.client.whitelabel.domains.get(query_params=params)
        response_json = json.loads(response.body)[0]

        if len(response_json) == 0:
            print("[-] Domain not found")
            return 1

        domain_id = response_json["id"]

        print("[+] Deleting associated DNS entries")

        try:
            for key, dns_entry in response_json['dns'].items():
                res = self.cloudflare.remove_dns(dns_entry['host'], dns_entry['data'], dns_type=dns_entry['type'].upper())

                if res == 1:
                    print("[-] Failed to remove the DNS")
                    raise StopIteration
                elif res == 2:
                    print("[-] DNS entry does not exist")
        except StopIteration:
            return 1

        # Adding DMARC
        res = self.cloudflare.remove_dns("_dmarc.%s" % domain, "\"v=DMARC1; p=none;\"", dns_type="TXT")
        if res != 0:
            print("[-] Failed to remove the DNS")
            return 1

        print("[+] DNS entries removed from CloudFlare")

        print("[+] Removing the senders related to the domain %s" % domain)

        response = self.sg.client.senders.get()
        response_json = json.loads(response.body)

        for sender_info in response_json:
            sender_name = sender_info['from']['name']
            sender_email = sender_info['from']['email']

            if sender_email.endswith("@%s" % domain):
                print("[+] Deleting sender %s <%s>" % (sender_name, sender_email))
                sender_id = sender_info['id']

                try:
                    response = self.sg.client.senders._(sender_id).delete()
                
                    print("[+] Sender deleted")
                except Exception as e:
                    print("[-] Failed to delete the sender")

        print("[+] Senders removed")

        print("[+] Removing the domain %s from SendGrid" % domain)

        try:
            response = self.sg.client.whitelabel.domains._(domain_id).delete()
        except Exception as e:
            print("[-] Failed to remove the domain")
            return 1

        if response.status_code == 204:
            print("[+] Domain removed")
        else:
            print("[-] Failed to remove the domain")
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
        print("[+] Registring the sender %s <%s> in SendGrid" % (name, email))

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
            print("[-] Failed to register the sender")
            return 1

        if response.status_code == 201:
            print("[+] Sender %s <%s> registered" % (name, email))
            return 0

        print("[-] Failed to register the sender")
        return 1

    def delete_sender(self, email):
        print("[+] Deleting the sender %s in SendGrid" % (email,))

        response = self.sg.client.senders.get()
        response_json = json.loads(response.body)

        sender_id = None
        for sender_info in response_json:
            sender_email = sender_info['from']['email']

            if sender_email == email:
                print("[+] Sender found")
                sender_id = sender_info['id']
                break
        else:
            print("[-] Sender not found")
            return 1

        if sender_id == None:
            print("[-] Sender not found")
            return 1

        try:
            response = self.sg.client.senders._(sender_id).delete()
        except Exception as e:
            print("[-] Failed to delete the sender")
            return 1

        if response.status_code == 204:
            print("[+] Sender deleted")
            return 0

        print("[-] Failed to register the sender")
        return 1


