from website_functions import *

class Domain:

    def __init__(self, domain="", domainNoHTTP = "", domainNoHTTPNoSlash = "", domainNoHTTPNoSlashNoWWW = "", responseCode="", ISP_DNS="", ISP_DNS_IPS="", ISP_IP_Response_Code=[], Hops_to_Domain=-1, Traceroute="", AARC_DNS_IPs="",
    Resolved_IPs = [], Optus_DNS_IPs="", Google_DNS="", Cloudflare_DNS="", Response_Code_Different_DNS_List={},AARC_DNS_Response_Code="", Optus_DNS_Response_Code="",Google_DNS_Response_Code="", Cloudflare_DNS_Response_Code=""):


        #Raw Results
        self.domain = domain
        self.domainNoHTTP =domainNoHTTP
        self.domainNoHTTPNoSlash = domainNoHTTPNoSlash
        self.domainNoHTTPNoSlashNoWWW = domainNoHTTPNoSlashNoWWW


        if responseCode == "":

            self.responseCode = self.return_Response_Code()
        else:
            self.responseCode = responseCode

        if ISP_DNS == "":
            self.ISP_DNS = self.return_DNS()
        else:
            self.ISP_DNS = ISP_DNS

        if ISP_DNS_IPS == "":
            self.ISP_DNS_IPS = self.return_ISP_IP_List()
        else:
            try:
                #splitting in to a list
                ipList = ISP_DNS_IPS[0].replace(" ","").replace("'","").split(";")
                self.ISP_DNS_IPS = ipList
            except Exception as e:
                print("ERROR HERE----------------------------")
                print(e)

                self.ISP_DNS_IPS = ISP_DNS_IPS

        if ISP_IP_Response_Code == []:
            self.ISP_IP_Response_Code = self.IPResponseCodesListFromString()
        else:
            self.ISP_IP_Response_Code = ISP_IP_Response_Code

        if Traceroute == "":
            self.Traceroute = self.tracerouteToDomain()
        else:
            self.Traceroute = Traceroute

        if Hops_to_Domain == -1:
            self.Hops_to_Domain = len(self.Traceroute)
        else:
            self.Hops_to_Domain = Hops_to_Domain

        if Resolved_IPs == []:
            self.Resolved_IPs = self.return_IPs_Different_DNS()
        else:
            self.Resolved_IPs = Resolved_IPs

        if AARC_DNS_IPs == "":
            self.AARC_DNS_IPs = self.Resolved_IPs[1][1]
        else:
            self.AARC_DNS_IPs = AARC_DNS_IPs

        if Optus_DNS_IPs == "":
            self.Optus_DNS_IPs = self.Resolved_IPs[2][1]
        else:
            self.Optus_DNS_IPs = Optus_DNS_IPs

        if Google_DNS == "":
            self.Google_DNS = self.Resolved_IPs[3][1]
        else:
            try:

                ipList = []
                for ip in Google_DNS:

                    ipList.append(ip.replace(" ","").replace("'",""))
                self.Google_DNS = ipList

            except Exception as e:
                print("ERROR HERE----------------------------")
                print(e)
            #splitting in to a list
                self.Google_DNS = Google_DNS


        if Cloudflare_DNS == "":
            self.Cloudflare_DNS = self.Resolved_IPs[4][1]
        else:
            try:
                ipList = []
                for ip in Cloudflare_DNS:

                    ipList.append(ip.replace(" ","").replace("'",""))
                self.Cloudflare_DNS = ipList


            except Exception as e:
                print("ERROR HERE----------------------------")
                print(e)
            #splitting in to a list
                self.Cloudflare_DNS = Cloudflare_DNS


        self.Public_DNS_Ips = self.Google_DNS + self.Cloudflare_DNS

        if Response_Code_Different_DNS_List == {}:
            self.Response_Code_Different_DNS_List = self.IPResponseCodesList
        else:
            self.Response_Code_Different_DNS_List = Response_Code_Different_DNS_List

        if AARC_DNS_Response_Code == "":
            self.AARC_DNS_Response_Code = self.Response_Code_Different_DNS_List().get('AARC')
        else:
            self.AARC_DNS_Response_Code = AARC_DNS_Response_Code

        if Optus_DNS_Response_Code == "":
            self.Optus_DNS_Response_Code = self.Response_Code_Different_DNS_List().get('Optus')
        else:
            self.Optus_DNS_Response_Code = Optus_DNS_Response_Code

        if Google_DNS_Response_Code == "":
            self.Google_DNS_Response_Code = self.Response_Code_Different_DNS_List().get('Google')
        else:
            self.Google_DNS_Response_Code = Google_DNS_Response_Code

        if Cloudflare_DNS_Response_Code == "":
            self.Cloudflare_DNS_Response_Code = self.Response_Code_Different_DNS_List().get('Cloudflare')
        else:
            self.Cloudflare_DNS_Response_Code = Cloudflare_DNS_Response_Code


        self.ISP_IP_in_Non_ISP_IP = self.Is_ISP_IP_In_NonISP_DNS_IP()


        #Results Analysis
        self.IntersectionOfPublicAndDefaultDNS = self.IPsInTwoLists(self.ISP_DNS_IPS, self.Public_DNS_Ips)


    def Is_ISP_IP_In_NonISP_DNS_IP(self):
        #formula should be: if dns ip's provide 404's, if non isp dns's provide 200's some form of tampering is happening
        print("HERE")
        print(".........................")
        print(self.ISPDNSResponseContradictionPublicDNSResponse())
        print(".........................")
        self.getPublicDNSResponses()
        print("name: "+self.domain)
        print(self.Google_DNS)
        print(self.Cloudflare_DNS)
        publicDNSIPList = self.Google_DNS + self.Cloudflare_DNS

        print("DNS IP LIST: ")
        print(type(publicDNSIPList))
        print(publicDNSIPList)
        print(publicDNSIPList[0])
        print("ISP_DNS_IPS")
        print(type(self.ISP_DNS_IPS[0].split("; ")))
        print(self.ISP_DNS_IPS[0].split("; "))
        print(self.ISP_DNS_IPS[0].split("; "))

        print("SEEING ID DNS TAMPERING")
        for ip in self.ISP_DNS_IPS[0].split("; "):
            print("IP: "+ip)
            print("publicDNSIPList: " +str(publicDNSIPList))
            if ip in publicDNSIPList:
                print("IP matches: "+ip)

                return True

        else:
            return False


    def getPublicDNSResponses(self):
        compiledList = self.Google_DNS_Response_Code+self.Cloudflare_DNS_Response_Code
        print("CompiledList")
        print(compiledList)
        resultsDict = {}
        for code in compiledList:
            if code in resultsDict:
                resultsDict[code] = resultsDict.get(code)+1
            else:
                resultsDict[code] = 1

        print(resultsDict)
        return resultsDict




    def ISPDNSResponseContradictionPublicDNSResponse(self):
        Public_Codes = self.getPublicDNSResponses()
        ISP_Codes = self.ISP_IP_Response_Code
        everyPubCodeIs200 = True
        everyISPCodeIs200 = True




        for pub_code in Public_Codes:
            if pub_code != '200':
                everyPubCodeIs200 = False

        for ISP_code in ISP_Codes:
            if ISP_code != '200':
                everyISPCodeIs200 = False

        print("Public_Codes: "+str(Public_Codes))
        print("ISP_Codes: "+str(ISP_Codes))
        print("everyISPCodeIs200: "+str(everyISPCodeIs200))
        print("everyPubCodeIs200: "+str(everyPubCodeIs200))

        if everyISPCodeIs200 == False and everyPubCodeIs200 == True:
            print("DNS TAMPERING!")
            return True
        else:
            print("NO DNS TAMPERING!")
            return False




    def myfunc(self):
        print("Hello my name is " + self.domain)

    def return_Response_Code(self):


        https = False
        http = False

        if self.domain[0:5] == "https":
            https = True

        if self.domain[0:5] == "http:":
            http = True

        try:
            return requestWebsite(self.domainNoHTTP, http, https).get('RespondeCode')
        except Exception as e:
            return str(e).replace(',',';')


    def return_ISP_IP_List(self):

        return getIPAddressOfDomain(self.domainNoHTTPNoSlash)[0]

    def return_DNS(self):
        return getMyDNS()

    def tracerouteToDomain(self):
        return scapyTracerouteWithSR(self.domainNoHTTPNoSlashNoWWW)

    def IPResponseCodesListFromString(self):

        IPResponsesList = (self.ISP_DNS_IPS.replace("[","").replace("]","").replace("'","").replace(" ","")).split(";")

        responseCodeList = IPResponseCodes(IPResponsesList)

        return responseCodeList


    def return_IPs_Different_DNS(self):
        DifferentDNSIPs = resolveIPFromDNS(self.domainNoHTTPNoSlashNoWWW, listOfDNSs())

        return DifferentDNSIPs

    def IPResponseCodesList(self):
        return {'AARC': IPResponseCodes(self.AARC_DNS_IPs), 'Optus':IPResponseCodes(self.Optus_DNS_IPs),
        'Google':IPResponseCodes(self.Google_DNS), 'Cloudflare':IPResponseCodes(self.Cloudflare_DNS)}

    def return_class_variables(Domain):
      return(Domain.__dict__)


    def IPsInTwoLists(self, firstDNSIPList, secondDNSIPList):
        firstFoundInSecond = False
        for firstIP in firstDNSIPList:

            if firstIP in secondDNSIPList:
                firstFoundInSecond = True


                return True

        return False


    if __name__ == "__main__":
      a = Domain()
