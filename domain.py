from website_functions import *

class Domain:



    def __init__(self, domain="", domainNoHTTP = "", domainNoHTTPNoSlash = "", domainNoHTTPNoSlashNoWWW = "", responseCode="", ISP_DNS="", ISP_DNS_IPS="", ISP_IP_Response_Code=[], Hops_to_Domain=-1, Traceroute="", AARC_DNS_IPs="",
    Resolved_IPs = [], Optus_DNS_IPs="", Google_DNS="", Cloudflare_DNS="", Response_Code_Different_DNS_List={},AARC_DNS_Response_Code="", Optus_DNS_Response_Code="",Google_DNS_Response_Code="", Cloudflare_DNS_Response_Code=""):
        self.domain = domain


        self.domainNoHTTP =domainNoHTTP
        self.domainNoHTTPNoSlash = domainNoHTTPNoSlash
        self.domainNoHTTPNoSlashNoWWW = domainNoHTTPNoSlashNoWWW
        self.responseCode = self.return_Response_Code()
        self.ISP_DNS = self.return_DNS()
        self.ISP_DNS_IPS = self.return_ISP_IP_List()
        self.ISP_IP_Response_Code = self.IPResponseCodesListFromString()

        self.Traceroute = self.tracerouteToDomain()
        self.Hops_to_Domain = len(self.Traceroute)

        self.Resolved_IPs = self.return_IPs_Different_DNS()

        self.AARC_DNS_IPs = self.Resolved_IPs[1][1]
        self.Optus_DNS_IPs = self.Resolved_IPs[2][1]
        self.Google_DNS = self.Resolved_IPs[3][1]
        self.Cloudflare_DNS = self.Resolved_IPs[4][1]


        self.Response_Code_Different_DNS_List = self.IPResponseCodesList

        self.AARC_DNS_Response_Code = self.Response_Code_Different_DNS_List().get('AARC')
        self.Optus_DNS_Response_Code = self.Response_Code_Different_DNS_List().get('Optus')
        self.Google_DNS_Response_Code = self.Response_Code_Different_DNS_List().get('Google')
        self.Cloudflare_DNS_Response_Code = self.Response_Code_Different_DNS_List().get('Cloudflare')

    def myfunc(self):
        print("Hello my name is " + self.domain)

    def return_Response_Code(self):
        https = False
        http = False
        print(self.domain[0:5])
        print(self.domain[0:5])
        if self.domain[0:5] == "https":
            https = True

        if self.domain[0:5] == "http:":
            http = True

        return requestWebsite(self.domainNoHTTP, http, https).get('RespondeCode')


    def return_ISP_IP_List(self):
        return getIPAddressOfDomain(self.domainNoHTTPNoSlash)[0]

    def return_DNS(self):
        return getMyDNS()

    def tracerouteToDomain(self):
        return scapyTracerouteWithSR(self.domainNoHTTPNoSlashNoWWW)

    def IPResponseCodesListFromString(self):
        print("IP Responses")
        print(self.ISP_DNS_IPS)
        IPResponsesList = (self.ISP_DNS_IPS.replace("[","").replace("]","").replace("'","").replace(" ","")).split(";")
        print(IPResponsesList)
        responseCodeList = IPResponseCodes(IPResponsesList)
        print(responseCodeList)
        return responseCodeList


    def return_IPs_Different_DNS(self):
        DifferentDNSIPs = resolveIPFromDNS(self.domainNoHTTPNoSlashNoWWW, listOfDNSs())
        print(DifferentDNSIPs)
        return DifferentDNSIPs

    def IPResponseCodesList(self):
        return {'AARC': IPResponseCodes(self.AARC_DNS_IPs), 'Optus':IPResponseCodes(self.Optus_DNS_IPs),
        'Google':IPResponseCodes(self.Google_DNS), 'Cloudflare':IPResponseCodes(self.Cloudflare_DNS)}

    def return_class_variables(Domain):
      return(Domain.__dict__)




    if __name__ == "__main__":
      a = Domain()
      print(return_class_variables(a))
