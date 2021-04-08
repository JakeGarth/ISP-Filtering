from CSV_Methods import *
from website_functions import *

class ISP_Domain_Results_Interpreter:

    def __init__(self, name, ISP, ALL_ISP_LIST, domain_response_codes, default_DNS_response_codes, public_DNS_response_codes):

        self.name = name
        self.ISP = ISP
        self.domains_explanation = {}
        self.All_ISPs = ALL_ISP_LIST
        self.All_Other_ISPs = list(ALL_ISP_LIST).remove(self.ISP)
        self.domain_response_codes = domain_response_codes
        self.default_DNS_response_codes = default_DNS_response_codes
        self.public_DNS_response_codes = public_DNS_response_codes

    def get_domains(self):

        return self.ISP.domains




    def any_IP_Private(self, ipList):
        any_ISP_Resolved_IP_Is_Private = False



        for ip in ipList:

            if ip != '':
                if isIPPrivate(ip) == True:
                    any_ISP_Resolved_IP_Is_Private = True

                    return any_ISP_Resolved_IP_Is_Private


        return any_ISP_Resolved_IP_Is_Private


    def IPsInTwoLists(self, firstDNSIPList, secondDNSIPList):
        firstFoundInSecond = False
        for firstIP in firstDNSIPList:

            if firstIP in secondDNSIPList:
                firstFoundInSecond = True


                return True

        return False

    def writeResults(self):
        for dom in self.ISP.domains:
            domain = self.ISP.domains.get(dom)



            writeToCSVMethod([self.name,
            domain.domain,
            self.any_IP_Private(domain.ISP_DNS_IPS),
            self.any_IP_Private(domain.Google_DNS + domain.Cloudflare_DNS),
            domain.IntersectionOfPublicAndDefaultDNS,
            self.IPWorksDomainDoesnt(domain.responseCode, domain.ISP_IP_Response_Code),
            domain.responseCode,
            list(dict.fromkeys(domain.ISP_IP_Response_Code)),
            list(dict.fromkeys((domain.Google_DNS_Response_Code + domain.Cloudflare_DNS_Response_Code))),
            list(dict.fromkeys(self.domain_response_codes.get(dom))),
            list(dict.fromkeys(self.default_DNS_response_codes.get(dom))),
            list(dict.fromkeys(self.public_DNS_response_codes.get(dom))),
            self.blockingMethodAlgorithm(domain)],
            'Results/collated_results_interpreted.csv')



    def blockingMethodAlgorithm(self, domain):
        #Checking for DNS Tampering by comparing Public DNS IPs with ISP DNS IPs

        print("THIS ISP: "+self.name)
        #for isp in self.All_Other_ISPs:
        #    print(isp.name)
        #for isp in self.All_ISPs:
        #    print(isp.name)

        if domain.IntersectionOfPublicAndDefaultDNS == False:
            return "DNS Poison"

        #
        #for isp in self.All_ISPs:

            #print(isp.name)


    def differenceInResponseCodes(self):
        #checks if default DNS Response code differ from public

        return 1

    def domainCodeDifferentIpCode(self):
        #

        return 1

    def IPWorksDomainDoesnt(self, domainResponse, ipResponseList):
        #if DNS resolved IP's get 200 but the domain doesn't, then the domain is beying name keyword blocked

        if domainResponse != '200' and '200' in ipResponseList:
            return True
        else:
            return False
