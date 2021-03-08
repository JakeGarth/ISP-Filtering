import requests
import urllib.request
from website_functions import *
import pydnsbl


def getResponseCodeList():
    websiteList = []
    with open("CopyRight_Telstra.txt") as fp:
        Lines = fp.readlines()
    for line in Lines:
        websiteList.append(line.strip('\n'))


    ourIP = str(getIPAddress())

    AARNFile =  open("testing.txt","w", encoding="utf-8")
    for item in websiteList:
        positionofWWW = item.find('://')

        WebsiteNOHttp = item[positionofWWW+3:]
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
