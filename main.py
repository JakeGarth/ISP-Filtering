import requests
import urllib.request
from website_functions import *
import pydnsbl


def getResponseCodeList():
    websiteList = []
    with open("100MostVisitedSites.txt") as fp:
        Lines = fp.readlines()
    for line in Lines:
        websiteList.append(line.strip('\n'))


    ourIP = str(getIPAddress())

    AARNFile =  open("Most_Visited.txt","w", encoding="utf-8")
    for item in websiteList:
        positionofWWW = item.find('://')

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
        AARNFile.write(item + "," + str(responseCODE) +"," +IP + "\n")

    AARNFile.close()




def main():
    getResponseCodeList()







if __name__ == "__main__":
    main()
