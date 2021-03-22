import requests
import urllib.request
from website_functions import *
import pydnsbl
import csv
from nslookup import Nslookup
from domain import Domain
import ipaddress




def getResolvedIPs(TupleList):
    IPAddresses = []
    for tup in TupleList:
        IPList = tup[1]
        if IPList:
            firstIP = IPList[0]
        else:
            firstIP = ''
        IPAddresses.append(firstIP)

    return IPAddresses



def writeToCSVMethod(mylist, fileName):
    with open(fileName, 'a', newline='') as myfile:
        wr = csv.writer(myfile, quoting=csv.QUOTE_ALL)
        wr.writerow(mylist)


def InsertResultsDomain(domainObject):
    domainName = domainObject.domain
    print("Domain name: "+domainName)



def stripDomainName(domainName):
    positionofWWW = domainName.find('://')

    if "http" in domainName:
        WebsiteNOHttp = domainName[positionofWWW+3:]
    else:
    #If http in domain name, change to + 3, if no http, change to +1
        WebsiteNOHttp = domainName[positionofWWW+1:]


    WebsiteNOHttpNoSlash = WebsiteNOHttp.replace('/',"")

    if 'www.' == WebsiteNOHttp[0:4]:
        print("change")
        WebsiteNoWWWNoSlash = WebsiteNOHttp[4:]
    else:
        WebsiteNoWWWNoSlash = WebsiteNOHttp
    if '/' == WebsiteNoWWWNoSlash[-1]:
        WebsiteNoWWWNoSlash = WebsiteNoWWWNoSlash[0:-1]

    print(domainName)
    print(WebsiteNoWWWNoSlash)
    print(WebsiteNOHttp)
    print(WebsiteNOHttpNoSlash)
    print(WebsiteNoWWWNoSlash)
    return {'WebsiteNOHttp': WebsiteNOHttp,  'WebsiteNOHttpNoSlash': WebsiteNOHttpNoSlash, 'WebsiteNoHttpNoWWWNoSlash': WebsiteNoWWWNoSlash}

def WriteResultsList(domainList, writeFile):
    websiteList = []
    with open(domainList) as fp:
        Lines = fp.readlines()
    for line in Lines:
        websiteList.append(line.strip('\n'))


    ourIP = str(getIPAddress())

    #AARNFile =  open("Most_Visited.txt","w", encoding="utf-8")
    for item in websiteList:
        positionofWWW = item.find('://')

        if "http" in item:
            WebsiteNOHttp = item[positionofWWW+3:]
        else:
        #If http in domain name, change to + 3, if no http, change to +1
            WebsiteNOHttp = item[positionofWWW+1:]
        print(WebsiteNOHttp)
        try:

            requestResults = requestWebsite(WebsiteNOHttp)
            responseCODE = requestResults.get('RespondeCode')
            print(responseCODE)
        except Exception as e:

            responseCODE = str(e)
            print(responseCODE)

        try:
            WebsiteNOHttpNoSlash = WebsiteNOHttp.replace('/',"")
            ResolvedIPs = getIPAddressOfDomain(WebsiteNOHttpNoSlash)
            IPString = ResolvedIPs[0]
            IPList = ResolvedIPs[1]
            print("IP")
            print(IP)

        except Exception as e:
            print("Exception happened here")
            print(str(e))
            IPString = str(e)
            IPList = ['NaN','NaN','NaN','NaN','NaN','NaN','NaN','NaN','NaN','NaN','NaN','NaN']

        responseCODE = responseCODE.replace(',',';')


        print(WebsiteNOHttp[0:4])
        print(WebsiteNOHttp)
        if 'www.' == WebsiteNOHttp[0:4]:
            print("change")
            WebsiteNoWWWNoSlash = WebsiteNOHttp[4:]
        else:
            WebsiteNoWWWNoSlash = WebsiteNOHttp
        if '/' == WebsiteNoWWWNoSlash[-1]:
            WebsiteNoWWWNoSlash = WebsiteNoWWWNoSlash[0:-1]

        print(WebsiteNoWWWNoSlash)
        hopList = scapyTracerouteWithSR(WebsiteNoWWWNoSlash)
        hopNumber = len(hopList)
        hopListSting = str(hopList).replace(',',';')

        DifferentDNSIPs = resolveIPFromDNS(WebsiteNoWWWNoSlash, listOfDNSs())

        print("DifferentDNSIPs")
        print(DifferentDNSIPs)

        DNSResolvedIPS = getResolvedIPs(DifferentDNSIPs)
        print("DNSResolvedIPS:")
        print(DNSResolvedIPS)

        DNSIPResponseCodes = IPResponseCodes(DNSResolvedIPS)

        print("DNSIPResponseCodes")
        print(DNSIPResponseCodes)

        DifferentDNSIPSting = str(DifferentDNSIPs).replace(',',';')

        print("IPList")
        print(type(IPList))
        print(IPList)

        IpRequestResponseCodes = IPResponseCodes(IPList)
        print("Jake Look here >>>>>>>>>>>")
        print("IpRequestResponseCode")
        print(IpRequestResponseCodes)
        IpRequestResponseCodesString = str(IpRequestResponseCodes).replace(",",';')

        resultsList = [item, responseCODE, IPString, IpRequestResponseCodesString, hopNumber, hopListSting, DNSResolvedIPS[0], DNSResolvedIPS[1], DNSResolvedIPS[2],
        DNSResolvedIPS[3], DNSResolvedIPS[4],DNSIPResponseCodes[0],DNSIPResponseCodes[1],DNSIPResponseCodes[2],DNSIPResponseCodes[3], DNSIPResponseCodes[4]]

        writeToCSVMethod(resultsList, writeFile)
        #AARNFile.write(item + "," + str(responseCODE) +"," +IP + "\n")

    AARNFile.close()



def checkErrorCodeOfOtherDNS(tupleList):
    for tupl in tupleList:
        ip = tupl[0]



def checkIP():
    p=sr1(IP(dst='140.32.113.3')/ICMP())
    if p:
        p.show()
    print(p)



def writeObjectToCSV(obj, writeFile):
    resultsList = [obj.domain, obj.responseCode, obj.ISP_DNS, obj.ISP_DNS_IPS, obj.ISP_IP_Response_Code ,obj.Traceroute , obj.Hops_to_Domain ,  obj.AARC_DNS_IPs, obj.Optus_DNS_IPs, obj.Google_DNS, obj.Cloudflare_DNS, obj.AARC_DNS_Response_Code, obj.Optus_DNS_Response_Code, obj.Google_DNS_Response_Code, obj.Cloudflare_DNS_Response_Code]

    writeToCSVMethod(resultsList, writeFile)


def CalculateListOfDomains(openFile, writeFile):
    websiteList = []
    with open(openFile) as fp:
        Lines = fp.readlines()
    for line in Lines:
        websiteList.append(line.strip('\n'))


    ourIP = str(getIPAddress())

    #AARNFile =  open("Most_Visited.txt","w", encoding="utf-8")
    for item in websiteList:
        domain = item
        domainStripped = stripDomainName(domain)
        WebsiteNOHttp = domainStripped.get('WebsiteNOHttp')
        WebsiteNOHttpNoSlash  = domainStripped.get('WebsiteNOHttpNoSlash')
        WebsiteNoHttpNoWWWNoSlash  = domainStripped.get('WebsiteNoHttpNoWWWNoSlash')

        obj = Domain(domain = domain,domainNoHTTP = WebsiteNOHttp,domainNoHTTPNoSlash = WebsiteNOHttpNoSlash, domainNoHTTPNoSlashNoWWW =  WebsiteNoHttpNoWWWNoSlash)
        writeObjectToCSV(obj, "test.csv")

def main():


    print('10.127.5.17')
    print(ipaddress.ip_address('10.127.5.17').is_private)
    print('35.186.224.25')
    print(ipaddress.ip_address('35.186.224.25').is_private)
    #stripDomainName('https://www.wallumai.com.au/')


    CalculateListOfDomains("CopyRight_Telstra.txt","test.csv")

    r = requests.get("http://unblockproject.pw", auth=('user', 'pass'))
    print(r)
    #print(requestWebsite("unblockproject.pw"))

    '''
    domain = "https://www.stockspot.com.au/"
    domainStripped = stripDomainName(domain)
    WebsiteNOHttp = domainStripped.get('WebsiteNOHttp')
    WebsiteNOHttpNoSlash  = domainStripped.get('WebsiteNOHttpNoSlash')
    WebsiteNoHttpNoWWWNoSlash  = domainStripped.get('WebsiteNoHttpNoWWWNoSlash')

    test = Domain(domain = domain,domainNoHTTP = WebsiteNOHttp,domainNoHTTPNoSlash = WebsiteNOHttpNoSlash, domainNoHTTPNoSlashNoWWW =  WebsiteNoHttpNoWWWNoSlash)

    writeObjectToCSV(test, "test.csv")
    '''
    '''
    InsertResultsDomain(test)

    print(test.myfunc())

    print(test.__dict__)
    print(vars(test))

    '''
    '''
    openFile = "CopyRight_Telstra.txt"
    writeFile = "Copy_Right_Telstra_Results_UNI.csv"
    WriteResultsList(openFile, writeFile)
    '''








if __name__ == "__main__":
    main()
