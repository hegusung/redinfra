import os
import sys
import json
import time
import msal
import requests

from lib.color import color

class O365:

    def __init__(self, cloudflare):
        self.cloudflare = cloudflare

    def setup_tenants(self, config):
        tenants = []

        for key, tenant_config in config.items():
            tenants.append(Tenant(self, tenant_config))

        return tenants

class Tenant:

    def __init__(self, o365, config):
        self.o365 = o365
        self.config = config

        self.domains = {}
        self.users = {}
        self.services = {}
        for domain, domain_info in config["domains"].items():
            self.domains[domain] = domain_info
            for user, user_info in domain_info["emails"].items():
                self.users[user] = user_info

            if not 'services' in self.domains[domain]:
                self.services[domain] = ['Email', 'OfficeCommunicationsOnline']
            else:
                self.services[domain] = self.domains[domain]['services']

        AUTHORITY = f"https://login.microsoftonline.com/%s" % config['tenant_id']
        self.app = msal.ConfidentialClientApplication(
           config['client_id'], authority=AUTHORITY, client_credential=config['client_secret']
        )

        SCOPE = ["https://graph.microsoft.com/.default"]
        result = self.app.acquire_token_for_client(scopes=SCOPE)

        if not "access_token" in result:
            raise Exception("Failed to get O365 access content")

        self.token = result["access_token"]

    def list_users(self):
        resp = requests.get(
            "https://graph.microsoft.com/v1.0/users?$select=id,userPrincipalName,assignedLicenses",
            headers={"Authorization": "Bearer %s" % self.token}
        )
        for user in resp.json().get('value', []):
            yield user

    def delete_old_users(self):
        print(color("    [*] Deleting old O365 users...", "blue"))

        for user in self.list_users():
            if not user["userPrincipalName"] in self.users:

                resp = requests.get(
                    "https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments?$filter=principalId eq '%s'" % user["id"],
                    headers={"Authorization": "Bearer %s" % self.token}
                )
                
                if len(resp.json()["value"]) == 0: # Simple user, we can delete
                    print(color("    [*] Deleting user %s" % user["userPrincipalName"], "blue"))

                    resp = requests.delete(
                        "https://graph.microsoft.com/v1.0/users/%s" % user["id"],
                        headers={"Authorization": "Bearer %s" % self.token}
                    )
                    if resp.status_code in [200,201]:
                        print(color("    [+] User %s deleted" % user["userPrincipalName"], "green"))
                    else:
                        print(color("    [-] Failed to delete user: %s" % resp.json(), "red"))

        print(color("    [*] Done", "blue"))


    def create_new_users(self):
        print(color("    [*] Creating new O365 users...", "blue"))

        # Gathering licences
        available_licences = []
        resp = requests.get(
            "https://graph.microsoft.com/v1.0/subscribedSkus",
            headers={"Authorization": "Bearer %s" % self.token}
        )
        for licence in resp.json().get('value', []):
            available_licences.append(licence['skuId'])

        # Get current config from o365
        current_users = {}
        for user in self.list_users():
            current_users[user["userPrincipalName"]] = user

            for licence in user['assignedLicenses']:
                try:
                    available_licences.remove(licence['skuId'])
                except ValueError:
                    pass

        for user in self.users:
            if not user in current_users:
                print(color("    [*] Adding user %s to O365" % user, "blue"))

                body = {
                  "accountEnabled": True,
                  "displayName": self.users[user]['name'],
                  "mailNickname": self.users[user]['email'].split('@')[0],
                  "userPrincipalName": self.users[user]['email'],
                  "usageLocation": self.users[user]['usageLocation'],
                  "passwordProfile": {
                    "forceChangePasswordNextSignIn": False,
                    "password": self.users[user]['password']
                  }
                }
                resp = requests.post(
                    "https://graph.microsoft.com/v1.0/users",
                    headers={"Authorization": "Bearer %s" % self.token},
                    json=body
                )

                if resp.status_code in [200,201]:
                    print(color("    [+] User %s added" % user, "green"))
                else:
                    print(color("    [-] Failed to add user: %s" % resp.json(), "red"))

                print(color("    [*] Adding a licence to %s" % user, "blue"))

                if len(available_licences) == 0:
                    print(color("    [-] No more licences to user, buy more", "red"))
                else:
                    skuid = available_licences.pop()
                    print(color("    [*] Using license %s" % skuid, "blue"))

                    body = {
                        "addLicenses": [{"skuId": skuid, "disabledPlans": []}],  # optionally disable plans
                        "removeLicenses": []
                    }
                    r = requests.post(
                        "https://graph.microsoft.com/v1.0/users/%s/assignLicense" % user,
                        headers={"Authorization": "Bearer %s" % self.token},
                        json=body
                    )
                    if r.status_code in [200, 201]:
                        print(color("    [+] Successfully added license", "green"))
                    else:
                        print(color("    [-] Failed to add license: %s" % r.json(), "red"))

        print(color("    [*] Done", "blue"))

    def list_domains(self):
        resp = requests.get(
            "https://graph.microsoft.com/v1.0/domains",
            headers={"Authorization": "Bearer %s" % self.token}
        )
        for domain in resp.json().get('value', []):
            yield domain

    def delete_old_domains(self):
        print(color("    [*] Deleting old O365 domains...", "blue"))

        for domain in self.list_domains():

            if not domain["id"] in self.domains:
                if domain["isInitial"] == False:
                    print(color("    [*] Deleting domain %s" % domain["id"], "blue"))

                    resp = requests.delete(
                        "https://graph.microsoft.com/v1.0/domains/%s" % domain["id"],
                        headers={"Authorization": "Bearer %s" % self.token}
                    )

                    if resp.status_code in [200, 201]:
                        print(color("    [+] Successfully deleted the domain", "green"))
                    else:
                        print(color("    [-] Failed to delete the domain: %s" % resp.json(), "red"))

        print(color("    [*] Done", "blue"))

    def create_new_domains(self):
        print(color("    [*] Creating new O365 domains...", "blue"))

        # Get current config from o365
        current_domains = {}
        for domain in self.list_domains():
            current_domains[domain["id"]] = domain

        for domain in self.domains:
            if not domain in current_domains:
                print(color("    [*] Adding domain %s to O365" % domain, "blue"))

                body = {"id": domain}
                resp = requests.post(
                    "https://graph.microsoft.com/v1.0/domains",
                    headers={"Authorization": "Bearer %s" % self.token},
                    json=body
                )

                if resp.status_code in [200, 201]:
                    print(color("    [+] Successfully deleted the domain", "green"))
                else:
                    print(color("    [-] Failed to delete the domain: %s" % resp.json(), "red"))

                print(resp.status_code, resp.json())

        for domain in self.list_domains():
            # Check if domain is verified
            if domain["isVerified"] == False:
                print(color("    [*] Verifying domain %s in O365" % domain['id'], "blue"))
                verified = False

                resp = requests.get(
                    "https://graph.microsoft.com/v1.0/domains/%s/verificationDnsRecords" % domain['id'],
                    headers={"Authorization": "Bearer %s" % self.token}
                )

                print(color("    [*] Adding records in Cloudflare", "blue"))
                for record in resp.json().get('value', []):
                    if record['recordType'].upper() == "TXT":
                        self.o365.cloudflare.new_dns(record['label'], record['text'], dns_type='TXT')
                    elif record['recordType'].upper() == "MX":
                        self.o365.cloudflare.new_dns(record['label'], record['mailExchange'], dns_type='MX', priority=record['preference'])

                while verified == False:
        
                    print(color("    [*] Waiting for O365 verification... (can take a few minutes)", "blue"))
                    resp = requests.post(
                        "https://graph.microsoft.com/v1.0/domains/%s/verify" % domain['id'],
                        headers={"Authorization": "Bearer %s" % self.token},
                    )

                    if resp.status_code == 200:
                        break
                    elif 'error' in resp.json() and "Error in DNS verification" in resp.json()['error']['message']:
                        time.sleep(30)
                    else:
                        break
                        
                print(color("    [+] Domain %s is verified" % domain['id'], "green"))

            if len(domain["supportedServices"]) == 0:
                print(color("    [*] Setting services for the domain %s" % domain['id'], "blue"))

                patch_body = {
                    "isDefault": False,
                    "supportedServices": self.services[domain['id']]
                }
                resp = requests.patch(
                    "https://graph.microsoft.com/v1.0/domains/%s" % domain['id'],
                    headers={"Authorization": "Bearer %s" % self.token},
                    json=patch_body
                )

                if resp.status_code in [200, 201]:
                    print(color("    [+] Successfully added the services", "green"))
                else:
                    print(color("    [-] Failed to add services: %s" % resp.json(), "red"))

        print(color("    [*] Done", "blue"))

    def get_dns_entries(self):

        # We need the tenant name to guess the DKIM
        tenant_name = None
        for domain in self.list_domains():
            if domain['id'].endswith(".onmicrosoft.com"):
                tenant_name = domain['id'][:-1*len(".onmicrosoft.com")]

        for domain in self.list_domains():
            if not domain['id'] in self.services:
                continue

            services = self.services[domain['id']]

            resp = requests.get(
                "https://graph.microsoft.com/v1.0/domains/%s/serviceConfigurationRecords" % domain['id'],
                headers={"Authorization": "Bearer %s" % self.token}
            )
            domain_id = None
            for record in resp.json().get('value', []):
                print(record)

                # So Microsoft API sucks and doesn't provide the DKIM entries so we will try to guess it
                # Format => CNAME    selector1._domainkey.{domain}    selector1-{domain_id}._domainkey.{tenant_name}.w-v1.dkim.mail.microsoft
                if 'mailExchange' in record and record['mailExchange'].endswith(".mail.protection.outlook.com"):
                    domain_id = record['mailExchange'][:-1*len(".mail.protection.outlook.com")]

                if record['supportedService'] in services:
                    yield record

            if tenant_name and domain_id:
                yield {"label": "selector1._domainkey.%s" % domain["id"], "recordType": "CName", "canonicalName": "selector1-%s._domainkey.%s.d-v1.dkim.mail.microsoft" % (domain_id, tenant_name)}
                yield {"label": "selector2._domainkey.%s" % domain["id"], "recordType": "CName", "canonicalName": "selector2-%s._domainkey.%s.d-v1.dkim.mail.microsoft" % (domain_id, tenant_name)}

