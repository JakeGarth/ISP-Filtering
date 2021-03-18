import requests
import urllib.request
from website_functions import *
import pydnsbl
import csv
from nslookup import Nslookup

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
            IP = getIPAddressOfDomain(WebsiteNOHttpNoSlash)
            print("IP")
            print(IP)

        except Exception as e:
            IP = str(e)

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
        print("Jake Look here>>>>>>>>>>>")
        print(DifferentDNSIPs)
        DNSResolvedIPS = getResolvedIPs(DifferentDNSIPs)
        DNSIPResponseCodes = IPResponseCodes(DNSResolvedIPS)

        DifferentDNSIPSting = str(DifferentDNSIPs).replace(',',';')

        resultsList = [item, responseCODE, IP, hopNumber, hopListSting, DNSResolvedIPS[0], DNSResolvedIPS[1], DNSResolvedIPS[2],
        DNSResolvedIPS[3], DNSResolvedIPS[4],DNSIPResponseCodes[0],DNSIPResponseCodes[1],DNSIPResponseCodes[2],DNSIPResponseCodes[3], DNSIPResponseCodes[4]]

        writeToCSVMethod(resultsList, writeFile)
        #AARNFile.write(item + "," + str(responseCODE) +"," +IP + "\n")

    AARNFile.close()

def getIPResponseCode(IPAddress):
    if IPAddress == '' or IPAddress == None:
        return "NaN"

    try:
        print('http://'+IPAddress)
        r = requests.get('http://'+IPAddress)
        print(r)
        print(r.status_code)
        return r.status_code
    except Exception as e:
        return e

def IPResponseCodes(IPList):
    responseCodeList = []

    for IP in IPList:
        response = getIPResponseCode(IP)
        responseCodeList.append(response)

    return responseCodeList

def checkErrorCodeOfOtherDNS(tupleList):
    for tupl in tupleList:
        ip = tupl[0]



def checkIP():
    p=sr1(IP(dst='140.32.113.3')/ICMP())
    if p:
        p.show()
    print(p)

def main():

    #DifferentDNSIPs = resolveIPFromDNS("unblocked.to", listOfDNSs())
    #print("Jake Look here>>>>>>>>>>>")
    #print(DifferentDNSIPs)
    #print(getResolvedIPs(DifferentDNSIPs))
    #getIPResponseCode('54.79.28.199')
    #checkIP()
    # set optional Cloudflare public DNS server
    #website = "tutorialspoint.com"
    #result = resolveIPFromDNS(website, listOfDNSs())
    #print (result)
    #print(type(result))
    #tryingDifferentDNS()
    #getIPSpecificDNS()
    #print(type(getMyDNS()))
    #print(getMyDNS())
    #getIPSpecificDNS()
    #print(scapyTracerouteWithSR('cisco.com'))
    openFile = "CopyRight_Telstra.txt"
    writeFile = "Copy_Right_Telstra_Results_Optus.csv"
    WriteResultsList(openFile, writeFile)

    #print(CompareDNSResults("facebook.com"))
    #print((getTraceRouteList("facebook.com")))
    #CompareDNSResults("cisco.com")



    '''
    print(len(getTraceRouteList("cisco.com")))
    print(getIPAddressOfDomain("cisco.com"))



    dns_resolver = dns.resolver.Resolver()
    dns_resolver.nameservers[0]
    print(type(dns_resolver.nameservers[0]))
    print(dns_resolver.nameservers[0])
    print("DNS Traceroute Google DNS:")
    print(str(DNSTraceroute('8.8.8.8')[0]))

    '''

    #print("DNS Traceroute Default DNS:")
    #print(str(DNSTraceroute(dns_resolver.nameservers[0])[0]))


    #print(str(DNSTraceroute(dns_resolver.nameservers[0])[1]))
    #WriteResultsList()







if __name__ == "__main__":
    main()
