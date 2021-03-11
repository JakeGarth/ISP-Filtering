import requests
from bs4 import BeautifulSoup
from bs4.element import Comment
import socket
from scapy.all import *
import dns.resolver



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


def getIPAddressOfDomain(websiteURL):

    try:
        result = socket.gethostbyname_ex(websiteURL)
        IPaddress = str(result[2]).replace(',',";")
    except Exception as e:
        IPaddress = str(e)

    return IPaddress


def getIPAddress():
    hostname = socket.gethostname()
    IPAddr = socket.gethostbyname(hostname)
    return IPAddr


def CompareDNSResults(website): #this may be legacy...might use the change DNS in the future
    dns_resolver = dns.resolver.Resolver()
    DNSList = [dns_resolver.nameservers[0]]
    #DNSList = [dns_resolver.nameservers[0],'8.8.8.8','1.1.1.1'] #cloudflare and google's DNS

    for DNS_Address in DNSList:
        print(DNS)

        ans, unans = traceroute(DNS_Address,l4=UDP(sport=RandShort())/DNS(qd=DNSQR(qname=website)),maxttl=15)
        #ans, unans = traceroute(DNS,l4=UDP(sport=RandShort())/DNS(qd=DNSQR(qname='google.com')),maxttl=15)
        print("Number of hops:")
        print(ans[TCP])
        for snd, _ in ans[TCP]:
            print(type(snd))
            print(snd, _)
            print(type(snd[IP]))
            print(snd[IP])
            print(type(snd[IP].ttl))
            print(snd[IP].ttl)
            print("what")

        #print((ans[TCP]))
        #print(type(ans))
        #print(ans)
        #print(type(unans))
        #print(unans)
        #for snd, rcv in ans:
        #    print(snd.ttl, rcv.src, snd.sent_time, rcv.time)



def DNSTraceroute(DNSServerAddress):

    ans, unans = traceroute(DNSServerAddress,l4=UDP(sport=RandShort())/DNS(qd=DNSQR(qname="cisco.com")),maxttl=15)
    ans.graph()
    return ans, unans

def getTraceRouteList(host):

    print("Traceroute", host)
    flag = True
    ttl=1
    hops = []
    while flag:
        ans, unans = sr(IP(dst=host,ttl=ttl)/ICMP(), timeout = 10)
        try:
            gotdata = ans.res[0][1]
        except IndexError:
            gotdata = 'null'
            hops = ['Error in Traceroute']
            return hops

        if ans.res[0][1].type == 0: # checking for  ICMP echo-reply
            flag = False
        else:
            hops.append(ans.res[0][1].src) # storing the src ip from ICMP error message
            ttl +=1
        #print("ans.res:")
        #print(ans.res) #Use this to  see the src and destination of each request, this lets u see the hops working in more details
    i = 1
    for hop in hops:
        print(i, " " + hop)
        i+=1
    return hops


def scapyTracerouteWithSR(domain):
    try:
        ans, unans = sr(IP(dst=domain, ttl=(1,25),id=RandShort())/TCP(flags=0x2), timeout = 2)
    except Exception as e:
        return [str(e)]
    hops = []
    for snd,rcv in ans:
        print(snd.ttl, rcv.src, isinstance(rcv.payload, TCP))

        if len(hops) > 0:
            if not isinstance(rcv.payload, TCP) or hops[-1] != rcv.src:
                hops.append(rcv.src)
        else:
            if not isinstance(rcv.payload, TCP):
                hops.append(rcv.src)

    return hops
