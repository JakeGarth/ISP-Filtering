import requests
import urllib.request
from website_functions import *
import pydnsbl


def main():

    websiteList = []
    with open("CopyRight_Telstra.txt") as fp:
        Lines = fp.readlines()
    for line in Lines:
        websiteList.append(line.strip('\n'))


    ourIP = str(getIPAddress())

    AARNFile =  open(ourIP,"w", encoding="utf-8")
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
        AARNFile.write(item + "," + str(responseCODE) + "\n")
    AARNFile.close()


    print(getIPAddress())

    requestWebsite("www.google.com")


if __name__ == "__main__":
    main()
