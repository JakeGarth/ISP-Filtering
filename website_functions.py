import requests
from bs4 import BeautifulSoup
from bs4.element import Comment
import socket
from scapy.all import *
import dns.resolver
from nslookup import Nslookup
import ipaddress
from detect_blockpages import *


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



def requestWebsite(websiteURL, http, https):
    print("Website URL: "+websiteURL)
    protocol = "This is broken"
    if(https == True):
        protocol = "https"
    if(http == True):
        protocol = "http"
    r = requests.get(protocol+"://"+websiteURL, auth=('user', 'pass'))

    results = {}
    results['RespondeCode'] = str(r.status_code)
    results['BlockPage'] = detectBlockPage(text_from_html(r.text))
    results['CloudflareBlockPage'] = detectCloudFlare(text_from_html(r.text))
    return results

def getIPResponseCodeAndText(IPAddress):
    if IPAddress == '' or IPAddress == None:
        return "NaN"

    try:

        r = requests.get('http://'+IPAddress)

        return {'Response_Code': r.status_code, 'Visible_Text': text_from_html(r.text)}
    except Exception as e:
        exce = str(e).replace(',',";")
        return exce

def IPResponseCodesAndText(IPList):
    responseCodeList = []
    blockPageList = []
    cloudFlareBlockPageList = []

    for IP in IPList:
        response = getIPResponseCodeAndText(IP)
        responseCodeList.append(response.get('Response_Code'))
        blockPageList.append(detectBlockPage(response.get('Visible_Text')))
        cloudFlareBlockPageList.append(detectCloudFlare(response.get('Visible_Text')))



    return {'responseCodeList':responseCodeList, 'blockPageList':blockPageList, 'cloudFlareBlockPageList':cloudFlareBlockPageList}


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

        IPAddressList = result[2]
        IPaddressString = str(result[2]).replace(',',";")

    except Exception as e:
        IPaddressString = str(e)
        IPaddressString.replace(',',";")
        IPAddressList = ['NaN', 'NaN']

    return IPaddressString, IPAddressList


def getIPAddress():
    hostname = socket.gethostname()
    IPAddr = socket.gethostbyname(hostname)
    return IPAddr


def CompareDNSResults(website): #this may be legacy...might use the change DNS in the future
    dns_resolver = dns.resolver.Resolver()
    DNSList = [dns_resolver.nameservers[0]]
    #DNSList = [dns_resolver.nameservers[0],'8.8.8.8','1.1.1.1'] #cloudflare and google's DNS

    for DNS_Address in DNSList:


        ans, unans = traceroute(DNS_Address,l4=UDP(sport=RandShort())/DNS(qd=DNSQR(qname=website)),maxttl=15)
        #ans, unans = traceroute(DNS,l4=UDP(sport=RandShort())/DNS(qd=DNSQR(qname='google.com')),maxttl=15)
        #print("Number of hops:")
        #print(ans[TCP])
        for snd, _ in ans[TCP]:
            print(type(snd))
            #print(snd, _)
            #print(type(snd[IP]))
            #print(snd[IP])
            #print(type(snd[IP].ttl))
            #print(snd[IP].ttl)
            #print("what")

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
        return [str(e).replace(',',";")]
    hops = []
    for snd,rcv in ans:
        #print(snd.ttl, rcv.src, isinstance(rcv.payload, TCP))

        if len(hops) > 0:
            if not isinstance(rcv.payload, TCP) or hops[-1] != rcv.src:
                hops.append(rcv.src)
        else:
            if not isinstance(rcv.payload, TCP):
                hops.append(rcv.src)

    return hops


def getMyDNS():
    dns_resolver = dns.resolver.Resolver()
    return dns_resolver.nameservers[0]


def getIPSpecificDNS():
    #this is legacy code I think
    answer = sr1(IP(dst='8.8.8.8')/UDP(dport=53)/DNS(rd=1, qd=DNSQR(qname='www.thepacketgeek.com')), verbose=0)

    #print(answer)
    #print(answer[DNS].summary())


def tryingDifferentDNS():
    my_resolver = dns.resolver.Resolver()
    # 8.8.8.8 is Google's public DNS server
    my_resolver.nameservers = ['8.8.8.8']

    answer = my_resolver.query('google.com')

    res = dns.resolver.Resolver(configure=False)
    res.nameservers = [ '8.8.8.8', '2001:4860:4860::8888',
                        '8.8.4.4', '2001:4860:4860::8844' ]
    r = res.query('example.org', 'a')
    #print(r)
    #print(answer)


def listOfDNSs():
    MyDNS = getMyDNS()
    AARNet = "10.127.5.17"
    OptusDNS = "192.168.43.202"
    GoogleDNS = "8.8.8.8"
    Cloudflare = "1.1.1.1"


    DNSList = [MyDNS, AARNet, OptusDNS, GoogleDNS, Cloudflare]
    return DNSList


def resolveIPFromDNS(hostname, DNSList):
    domain = hostname
    compiledList = []
    # set optional Cloudflare public DNS server
    for DNSIP in DNSList:
        dns_query = Nslookup(dns_servers=[DNSIP])

        ips_record = dns_query.dns_lookup(domain)
        #print(ips_record.response_full, ips_record.answer)

        soa_record = dns_query.soa_lookup(domain)
        #print(soa_record.response_full, soa_record.answer)
        tuple = (DNSIP, ips_record.answer)
        compiledList.append(tuple)
        tuple = ()


    return compiledList


def isIPPrivate(ip):
    return ipaddress.ip_address(ip).is_private

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
