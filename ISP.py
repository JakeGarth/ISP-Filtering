from website_functions import *
from domain import Domain

class ISP:

    DNS_Tampered_Domains = {}

    def __init__(self, name, domains):
        self.name = name
        self.domains = domains
        print("SELF DOMAINS TYPE:------------------------------"+str(type(self.domains)))






    def get_domain(self, domain_code):
        return self.domains[domain_code]

    def return_class_variables(ISP):
        return(ISP.__dict__)

    def Find_DNS_Tampered_Domains(self):
        print("Printing domains for: "+self.name)
        print(type(self.domains))
        print(self.domains)
        for domain in self.domains:
             '''
             print("Domain name: "+(self.domains.get(domain).domain))
             print(type(self.domains.get(domain).ISP_IP_Response_Code))
             print(self.domains.get(domain).ISP_IP_Response_Code)
             print(self.domains.get(domain).AARC_DNS_Response_Code)
             print(self.domains.get(domain).Optus_DNS_Response_Code)
             print(self.domains.get(domain).Google_DNS_Response_Code)
             print(type(self.domains.get(domain).Cloudflare_DNS_Response_Code))
             print(self.domains.get(domain).Cloudflare_DNS_Response_Code)
             '''

        # Converting string to list
             #res = self.domains.get(domain).ISP_IP_Response_Code.strip('][').split(', ')
             for item in self.domains.get(domain).ISP_IP_Response_Code:

                 print(item)

             if '200' in self.domains.get(domain).ISP_IP_Response_Code:
                 print("200 found...."+str(self.domains.get(domain).domain))

             for item in self.domains.get(domain).Traceroute:
                 print(item)

             print("DONE")

            # printing final result and its type


        #if '200' not in res:
        #    print("200 not in RES.....")
        #    print("DNS TAMPERING......")
