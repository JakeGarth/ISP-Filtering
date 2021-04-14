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
        print(self.IPBlockingDetection())
        print(self.dictOfAllDomainsOfAllISPs("CopyRight_Telstra.txt", "Cloudflare Block Page Public DNS"))

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
            self.printBlockPages(),
            self.blockingMethodAlgorithm(domain)],
            'Results/collated_results_interpreted.csv')


    def dictOfAllDomainsOfAllISPs(self, domainFile, reason):
        dictionaryOfDomains = {}


        with open(domainFile) as fp:
            Lines = fp.readlines()
        for line in Lines:


            line = line.rstrip("\n")
            name = 'domain_{}'.format(stripDomainName(line).get('WebsiteNoHttpNoWWWNoSlash').replace('.',"").rstrip("\n"))
            dictionaryOfDomains[name] = {}

            for isp in self.All_ISPs:
                print("Name: "+str(name))
                print(isp.domains.keys())
                domain = isp.domains.get(name)
                print(domain.domain)

                if reason == "Response Code":
                    dictionaryOfDomains[name][isp.name] = domain.responseCode
                elif reason == "Block Page":
                    dictionaryOfDomains[name][isp.name] = domain.domainBlockPage
                elif reason == "Cloudflare Block Page":
                    dictionaryOfDomains[name][isp.name] = domain.domainCloudFlareBlockPage
                elif reason == "Response Code Public DNS":
                    dictionaryOfDomains[name][isp.name] = domain.Public_DNS_Response_Codes
                elif reason == "Block Page Public DNS":
                    dictionaryOfDomains[name][isp.name] = domain.Block_Page_Public_DNS_List
                elif reason == "Cloudflare Block Page Public DNS":
                    dictionaryOfDomains[name][isp.name] = domain.Cloudflare_Block_Page_Public_DNS_List
                else:
                    dictionaryOfDomains[name][isp.name] = "Didn't input a reason"

        return dictionaryOfDomains

    def IsWesbiteLive(self):
        #check a domain in every ISP for a 200 response code and not a blockpage
        #check every ip address as well returned by the DNS
        return True

    def DNSTamperingDetection(self):
        #does default server return different DNS results from publci DNS, does the different IP's have different response codes and not blockpage
        return True

    def IPBlockingDetection(self):
        ListOfResponseCodes = {}
        ListOfBlockPages = {}
        for isp in self.All_ISPs:
            print("ISP: "+str(isp.name))
            for dom in isp.domains:
                print("DOM: "+str(dom))
                domain = isp.domains.get(dom)
                ListOfResponseCodes[isp.name] = domain.responseCode

        #does ip give a different response code or vary in whether it returns a blockpage to other ISP's
        print(ListOfResponseCodes)
        return True

    def DomainNameBlockingDetection(self):
        #does ip address reutrn 200 and is not a blockpage, does domain not return 200
        #and does domain name return different response code and non blockpage
        return True

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

    def printBlockPages(self):
        domainBlockList = []
        for dom in self.ISP.domains:
            domain = self.ISP.domains.get(dom)
            print(domain.domainBlockPage)
            domainBlockList.append(domain.domainBlockPage)

        return domainBlockList
