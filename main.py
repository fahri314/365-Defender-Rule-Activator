import json
import requests
from time import sleep
from datetime import datetime, timedelta


class activator:
    def __init__(self):
        with open("config.json", "r") as config:
            self.auth = json.loads(config.read())
            self.auth['session']['XSRF-TOKEN'] = self.auth['session']['XSRF-TOKEN'].replace('%3A', ":")
        self.edit_list = []
        self.activated = 0
        self.passed = 0
        self.i = 0
        self.start_time = datetime.now()
        self.step = self.auth['step']

    def get_queries(self):
        endpoint_uri = 'https://security.microsoft.com/apiproxy/mtp/huntingService/queries/?type=scheduled'
        headers = {"x-xsrf-token": self.auth['session']['XSRF-TOKEN']}
        cookies = {"sccauth": self.auth['session']['sccauth']}
        response = requests.get(endpoint_uri, headers = headers, cookies = cookies)
        
        if response:
            return json.loads(response.text)
        else:
            raise Exception("Unable to get rules from tenant, did the session time out?")

    def get_query_text(self, query_id):
        endpoint_uri = f'https://security.microsoft.com/apiproxy/mtp/huntingService/queries/{query_id}'
        headers = {"x-xsrf-token": self.auth['session']['XSRF-TOKEN']}
        cookies = {"sccauth": self.auth['session']['sccauth']}
        response = requests.get(endpoint_uri, headers = headers, cookies = cookies)
        if response.status_code == 503:
            print("[-] status_code: 503 | reason: 'Service Unavailable'")
            print("[+] Waiting ...")
            sleep(30)
            print("[!] Retrying ...")
            return self.get_query_text(query_id)
        response = json.loads(response.text)
        return response['QueryText']

    def generate_post_data(self, query_text):
        post_data = {}
        post_data['QueryText'] = query_text 
        # Check time in query
        if query_text.find("ago(") == -1:
            post_data['StartTime'] = (datetime.now() - timedelta(30)).strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3] + 'Z'  # 2023-07-26T15:31:18.773Z
        else:
            post_data['StartTime'] = None
        post_data['EndTime'] = (datetime.now() - timedelta(hours = 3)).strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3] + 'Z'
        post_data['MaxRecordCount'] = None
        post_data['TenantIds'] = None
        return post_data

    def run_query(self, post_data):
        endpoint_uri = 'https://security.microsoft.com/apiproxy/mtp/huntingService/queryExecutor'
        headers = {"x-xsrf-token": self.auth['session']['XSRF-TOKEN'], "method": "POST"}
        cookies = {"sccauth": self.auth['session']['sccauth']}
        response = requests.post(endpoint_uri, json = post_data, headers = headers, cookies = cookies)
        if response.status_code == 503:
            print("[-] status_code: 503 | reason: 'Service Unavailable'")
            print("[+] Waiting ...")
            sleep(30)
            print("[!] Retrying ...")
            return self.run_query(post_data)
        response = json.loads(response.text)
        return response
    
    def get_rule_info(self, query_id):
        tenant_id = self.auth["tenant"]["id"]
        endpoint_uri = f'https://security.microsoft.com/apiproxy/mtp/huntingService/rules/byquery/{query_id}?tenantIds={tenant_id}'
        headers = {"x-xsrf-token": self.auth['session']['XSRF-TOKEN']}
        cookies = {"sccauth": self.auth['session']['sccauth']}
        response = requests.get(endpoint_uri, headers = headers, cookies = cookies)
        if response.status_code == 503:
            print("[-] status_code: 503 | reason: 'Service Unavailable'")
            print("[+] Waiting ...")
            sleep(30)
            print("[!] Retrying ...")
            return self.get_rule_info(query_id)
        response = json.loads(response.text)
        return response

    def enable_rule(self, rule_id):
        endpoint_uri = 'https://security.microsoft.com/apiproxy/mtp/huntingService/rules/status'
        headers = {"x-xsrf-token": self.auth['session']['XSRF-TOKEN'], "method": "PATCH"}
        cookies = {"sccauth": self.auth['session']['sccauth']}
        patch_data = {}
        patch_data["RuleIds"] = [rule_id]
        patch_data["IsEnabled"] = True
        response = requests.patch(endpoint_uri, json = patch_data, headers = headers, cookies = cookies)
        
        if response.status_code == 200:
            return
        elif response.status_code == 503:
            print("[-] status_code: 503 | reason: 'Service Unavailable'")
            print("[+] Waiting ...")
            sleep(30)
            print("[!] Retrying ...")
            self.enable_rule(rule_id)
            return
        else:
            print("[-] status_code:" + str(response.status_code))
            print("[!] Error at `enable_rule` function")
            exit()

    def print_results(self):
        print(f"\x1b[1;31;43m[++++++++++] Edit List [++++++++++]\x1b[0;0m")
        print(*self.edit_list, sep = "\n")
        print(f"\x1b[1;31;43m[++++++++++] Activated Rules Count [++++++++++]\x1b[0;0m")
        print(self.activated)
        print(f"\x1b[1;31;43m[++++++++++] Passed Rules Count [++++++++++]\x1b[0;0m")
        print(self.passed)
        end_time = datetime.now()
        print("\n\n\x1b[1;31;43m[!]\x1b[0;0mElapsed time: ", end_time - self.start_time)



if __name__ == '__main__':
    activator = activator()
    queries = activator.get_queries()
    print(f"\x1b[1;31;43m[+] Fetched ({len(queries)}) queries\x1b[0;0m\n")

    try:
        for query in queries:
            if activator.i < activator.step:
                activator.i += 1
                continue
            activator.i += 1
            print(f"\x1b[1;31;43m[+] Query Name: '{query['Name']} || Query ID: ({query['Id']})' Step: ({activator.i})\x1b[0;0m")
            print("[!] Reading rule informations")

            rule_info = activator.get_rule_info(query['Id'])

            if (rule_info["IsEnabled"] == False) and (rule_info["IsDeleted"] == False):
                query_text = activator.get_query_text(query['Id'])
                post_data = activator.generate_post_data(query_text)

                print("[!] Query running")
                response = activator.run_query(post_data)

                if len(response['Results']) == 0:
                    # Enable Rule
                    print("[!] Rule enabling")
                    activator.enable_rule(rule_info["Id"])
                    activator.activated += 1
                else:
                    # Append to edit list
                    print("[!] Rule appended to edit list")
                    activator.edit_list.append(rule_info["Name"])
                    with open("edit_list", "a") as f:
                        f.write(rule_info["Name"] + "\n")
            else:
                print(f"[!] Query ID: {query['Id']} passed!")
                activator.passed += 1
                continue

        activator.print_results()

    except KeyboardInterrupt:
        activator.print_results()
