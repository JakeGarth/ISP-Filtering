import requests
import urllib.request
from website_functions import *
import pydnsbl
import csv


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

        resultsList = [item, responseCODE, IP, hopNumber, hopListSting]

        writeToCSVMethod(resultsList, writeFile)
        #AARNFile.write(item + "," + str(responseCODE) +"," +IP + "\n")

    AARNFile.close()




def main():

    #print(scapyTracerouteWithSR('cisco.com'))
    openFile = "CopyRight_Telstra.txt"
    writeFile = "Copy_Right_Telstra_Results_UNI.csv"
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
