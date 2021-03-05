import requests
from bs4 import BeautifulSoup
from bs4.element import Comment
import socket



def requestWebsite(websiteURL):
    r = requests.get("https://"+websiteURL, auth=('user', 'pass'))
    print(r.status_code)
    print(r.headers['content-type'])
    results = {}
    results['RespondeCode'] = str(r.status_code)
    return results



    #"https://www.judgments.fedcourt.gov.au/judgments/Judgments/fca/single/2020/2020fca0769"

def tag_visible(element):
    if element.parent.name in ['style', 'script', 'head', 'title', 'meta', '[document]']:
        return False
    if isinstance(element, Comment):
        return False
    return True


def text_from_html(body):
    soup = BeautifulSoup(body, 'html.parser')
    texts = soup.findAll(text=True)
    visible_texts = filter(tag_visible, texts)
    return u" ".join(t.strip() for t in visible_texts)


def getWebsitesFromText(text):
    textSplit = text.split()
    httpList = []
    for word in textSplit:
        if "http://" in word:
            httpList.append(word)

        if "https://" in word:
            httpList.append(word)


    return httpList


def getIPAddress():
    hostname = socket.gethostname()
    IPAddr = socket.gethostbyname(hostname)
    return IPAddr
