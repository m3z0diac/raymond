import requests
import optparse
from termcolor import colored
from time import sleep
import os
import socket
import pyfiglet
from datetime import datetime


def getArg():

    parser = optparse.OptionParser()
    parser.add_option("-u", "--url", dest="url", help="Website Target EX: example.com")
    (options, arg) = parser.parse_args()
    if options.url:
        if options.url[0:4] == "http":
            print("delet http and try again")
            exit(0)
        elif options.url == "":
            print("put the link ")

    return options

options = getArg()
webapp = options.url

def getCMSResults(url,verbose=False):

    try:        
        res=requests.get(f"https://whatcms.org/API/Tech?key=746f350b4b16644cd12fdb77a8ea14155c083cd3269036b30126e423ba0d7d61ffdd4f&url={url}")
    except requests.exceptions.ConnectionError:
        print("Unable To Connect To the Internet.")
        exit(1)
    if res.status_code==200:
        if res.json()["result"]["code"]==101:
            print("INVALID API KEY!.")
            exit(1)
        if res.json()["result"]["code"]==120:
            tts=float(res.json()["retry_in_seconds"])
            if verbose:
                print(f"Maxium API Request Reached. Trying Again in {tts} seconds.  ")
            time.sleep(tts)
            return getCMSResults(url,verbose)
        if verbose:
            print(res.text)
        cms=None
        infos = res.json()["results"]
        print(f"-------{url} Technologie Informations-------\n")
        wp = False
        try:
            for i in range(len(infos)):
                print(f"	{infos[i]['name']}")
                sleep(0.1)
                if infos[i]['name'] == "WordPress":
                    wp = True
                    if (infos[i]['version']):
                        wpv = infos[i]['version']
                    else: wpv = ""
            print("--------------------------------")
            if wp:
                wpFucker(f"https://{url}")
                print("Trying catch WordPress Version ...")
                if wp != "":
                    print(f"WordPress Version Detected {wpv}\n\n")
                    print("Search For WordPress Version Vurnabaletys ...")
                    vuln = requests.get(f"https://wpvulndb.com/api/v2/wordpresses/{wpv}")
                    if "Error" not in vuln.text:
                        print(vuln.text)
                    else:
                        print(f"[-] Can't search for WordPress {wpv} vulnerabilities")
                else: print("WordPress Version Not Detected\n\n")
        except:
            pass

        if len(res.json()["meta"]) >0:
            sinfos = res.json()["meta"]["social"]
            print("**************************************************************")
            print(f"\n-------{url} Social Media Informations-------\n")
            for i in range(len(sinfos)):
                print(f"{sinfos[i]['network']} ==> {sinfos[i]['url']}")
                if (sinfos[i]['network'] == "instagram"):
                    name = sinfos[i]['profile']
            print("\n\n")
        useRecon(name)

def admin(url, wordlist):
    print("-------Admin Panel Enumeration-------")
    with open(wordlist, "r") as admins:
        data = admins.read().split(",")
        for admin in data:
            try:
                path = f"http://{url}/{admin}"
                request = requests.get(path)
                if request.status_code == 200 and "login" in request.text:
                    print("[+] Admin panel Found")
                    print(f"{path}\n")
                    break
            except:
                pass

def useRecon(user_):

    links = {
        'instagram' :f'https://www.instagram.com/{user_}',
        'facebook'  :f'https://www.facebook.com/{user_}',
        'twitter'   :f'https://www.twitter.com/{user_}',
        'youtube'   :f'https://www.youtube.com/{user_}',
        'blogger'   :f'https://{user_}.blogspot.com',
        'reddit'    :f'https://www.reddit.com/user/{user_}',
        'pinterest' :f'https://www.pinterest.com/{user_}',
        'github'    :f'https://www.github.com/{user_}',
        'tumblr'    :f'https://{user_}.tumblr.com',
        'flickr'    :f'https://www.flickr.com/people/{user_}',
        'vimeo'     :f'https://vimeo.com/{user_}',
        'soundcloud':f'https://soundcloud.com/{user_}',
        'disqus'    :f'https://disqus.com/{user_}',
        'medium'    :f'https://medium.com/@{user_}',
        'devianart' :f'https://{user_}.deviantart.com',
        'vk'        :f'https://vk.com/{user_}',
        'about.me'  :f'https://about.me/{user_}',
        'imgur'     :f'https://imgur.com/user/{user_}',
        'slideshare':f'https://slideshare.net/{user_}',
        'spotify'   :f'https://open.spotify.com/user/{user_}',
        'scribd'    :f'https://www.scribd.com/{user_}',
        'badoo'     :f'https://www.badoo.com/en/{user_}',
        'patreon'   :f'https://www.patreon.com/{user_}',
        'bitbucket' :f'https://bitbucket.org/{user_}',
        'dailymotion':f'https://www.dailymotion.com/{user_}',
        'etsy'      :f'https://www.etsy.com/shop/{user_}',
        'cashme'    :f'https://cash.me/{user_}',
        'behance'   :f'https://www.behance.net/{user_}',
        'goodreads' :f'https://www.goodreads.com/{user_}',
        'instructables':f'https://www.instructables.com/member/{user_}',
        'keybase'   :f'https://keybase.io/{user_}',
        'kongregate':f'https://kongregate.com/accounts/{user_}',
        'livejournal':f'https://{user_}.livejournal.com',
        'angellist' :f'https://angel.co/{user_}',
        'last.fm'   :f'https://last.fm/user/{user_}',
        'dribbble'  :f'https://dribbble.com/{user_}',
        'codeacademy':f'https://www.codecademy.com/{user_}',
        'gravatar'  :f'https://en.gravatar.com/{user_}',
        'foursquare':f'https://foursquare.com/{user_}',
        'gumroad'   :f'https://www.gumroad.com/{user_}',
        'newgrounds':f'https://{user_}.newgrounds.com',
        'wattpad'   :f'https://www.wattpad.com/user/{user_}',
        'canva'     :f'https://www.canva.com/{user_}',
        'creativemarket':f'https://creativemarket.com/{user_}',
        'trakt'     :f'https://www.trakt.tv/users/{user_}',
        '500px'     :f'https://500px.com/{user_}',
        'buzzfeed'  :f'https://buzzfeed.com/{user_}',
        'tripadvisor':f'https://tripadvisor.com/members/{user_}',
        'hubpages'  :f'https://{user_}.hubpages.com',
        'contently' :f'https://{user_}.contently.com',
        'houzz'     :f'https://houzz.com/user/{user_}',
        'blip.fm'   :f'https://blip.fm/{user_}',
        'wikipedia' :f'https://www.wikipedia.org/wiki/User:{user_}',
        'codementor':f'https://www.codementor.io/{user_}',
        'reverbnation':f'https://www.reverbnation.com/{user_}',
        'designspiration65':f'https://www.designspiration.net/{user_}',
        'bandcamp'  :f'https://www.bandcamp.com/{user_}',
        'colourlovers':f'https://www.colourlovers.com/love/{user_}',
        'ifttt'     :f'https://www.ifttt.com/p/{user_}',
        'slack'     :f'https://{user_}.slack.com',
        'okcupid'   :f'https://www.okcupid.com/profile/{user_}',
        'trip'      :f'https://www.trip.skyscanner.com/user/{user_}',
        'ello'      :f'https://ello.co/{user_}',
        'hackerone' :f'https://hackerone.com/{user_}',
        'freelancer':f'https://www.freelancer.com/u/{user_}'
    }
    for social, url in links.items():
        request = requests.get(f"{url}")
        if request.status_code == 200:
            print(f"{social} : {url}")
            



def checkRobots(url):
    request = requests.get(f"http://{url}/robots.txt")
    print("-------Checking /robots.txt-------\n")
    sleep(5)
    if request.status_code == 200:
        print(f"[+] http://{url}/robots.txt Found\n")
        print("**** trying reading content ****\n")
        try:
            print(request.text)
        except:
            print("[-] can't reading the content of robots.txt")
    else:
        print("[-] robots.txt Not Exist")


def wpFucker(url):

    print("Trying catch license.txt ...")
    license_req = requests.get(f"{url}/license.txt")
    if license_req.status_code == 200:
        print(f"[+] License.txt Found : {url}/license.txt\n\n")
    else:
        print(f"[-] License.txt Not Found!\n\n")

    print("Trying catch xmlrpc ...")
    xmlrpc_req = requests.get(f"{url}/xmlrpc.php")
    if "XML-RPC server accepts POST requests only." not in xmlrpc_req.text:
        print(f"[+] XML-RPC interface Available Under {url}/xmlrpc.php\n\n")
    else : print("[-] XML-RPC not Available!\n\n")

    print("Trying catch uploads ...")
    request = requests.get(f"{url}/wp-content/uploads")
    if "/wp-content/uploads" in request.text:
        print(f"[+] Uploads Path Found : {url}/wp-content/uploads\n\n")
    else : print(f"[-] Uploads Path Not Found\n\n")

def IpEnum(url):
    ip = socket.gethostbyname(url)
    print(f"-------Target ip address {ip}-------")
    print(f"Get Informations About {ip}\n")
    ip_req = requests.get(f"https://api.hackertarget.com/geoip/?q={ip}")
    print(f"{ip_req.text}\n\n")

def getHeaders(url):
    print("-------Trying catch Headers-------")
    headers = requests.get(f"https://api.hackertarget.com/httpheaders/?q={url}")
    print(f"{headers.text}\n\n")

def dnsEnum(url):
    print("-------DNS lockup-------")
    dns_req = requests.get(f"https://api.hackertarget.com/dnslookup/?q={url}")
    dns_infos = dns_req.text.split("\n")
    print(f"{dns_infos[-1]}\n\n")

def subNet(url):
    print("-------Sub Networks (Host Range) Scaning-------")
    subnet_req = requests.get(f"https://api.hackertarget.com/subnetcalc/?q={url}")
    print(f"{subnet_req.text}\n\n")

def subDomainsEnum(url):
    print("-------Trying catch subdomains and hosts-------")
    print("-" * 15)
    Hosts = requests.get(f"https://www.threatcrowd.org/searchApi/v2/domain/report/?domain=={url}")
    data = Hosts.json()
    print(f"{len(data)} Subdomains Found")
    sleep(1)
    for host in data:
        print(f"{host}")
        sleep(0.2)

def PortScann(url):
    print("-------Scan Commun Ports-------")
    scan_req = requests.get(f"https://api.viewdns.info/portscan/?host={url}&apikey=de235d422bf3f5cc02ace82856bc90b087c96fc9&output=json")
    data = scan_req.json()
    ports = data['response']['port']
    for i in range(len(ports)):
        if ports[i]['status'] == "open":
            print(f"[+] port {ports[i]['number']} is {ports[i]['status']} {ports[i]['service']}")
            sleep(0.1)


def serverEnum(url):
    print("-------The hosted Websites on the server-------")
    srvscan = requests.get(f"https://api.viewdns.info/reverseip/?host={url}&apikey=de235d422bf3f5cc02ace82856bc90b087c96fc9&output=json")
    data = srvscan.json()
    count = data['response']['domain_count']
    if count != 0:
        domains = data['response']['domains']
        print(f"{count} web application Found")
        for i in range(0, int(count)):
            print(f"{domains[i]['name']} Last update {domains[i]['last_resolved']}")
            sleep(0.1)


def banner(url):
    print("-" * 50)
    ascii_banner = pyfiglet.figlet_format("Raymond")
    print(ascii_banner)
    print("Scanning Target: " + url)
    print("Scanning started at:" + str(datetime.now()))
    print("-" * 50)



def HandelOpts():
    banner(webapp)
    user_options = """
    [1] - Full scan
    [2] - CMS scan (social media accounts - riscky paths scan - user recon ...)
    [3] - Get web application request Headers
    [4] - Robots page scan
    [5] - DNS Enumeration
    [6] - Get all hosts on the target Server
    [7] - Scan commun ports
    [8] - Sub network information
    [9] - Ip address information
    [10]- Subdomains Enumeration (not all just about 50 %)
    [11]- Brute Force admin panel page
    [12]- Username rcon (check 65 website accounts ...)
    [0] - Exit Raymond Tool
    """
    try:
        user_input = int(input(user_options))
    except Exception:
        print("choose a number between 0 - 11")
    choices = list(range(0, 12))
    if user_input in choices:
        if user_input == 1:
            getCMSResults(webapp)
            print("*" * 50)
            getHeaders(webapp)
            print("*" * 50)
            checkRobots(webapp)
            print("*" * 50)
            dnsEnum(webapp)
            print("*" * 50)
            serverEnum(webapp)
            print("*" * 50)
            PortScann(webapp)
            print("*" * 50)
            subNet(webapp)
            print("*" * 50)
            IpEnum(webapp)
            print("*" * 50)
            subDomainsEnum(webapp)
            print("*" * 50)
            admin(webapp,"files/admins.ini")
            print("*" * 50)
        elif user_input == 2:
            getCMSResults(webapp)
        elif user_input == 3:
            getHeaders(webapp)
        elif user_input == 4:
            checkRobots(webapp)
        elif user_input == 5:
            dnsEnum(webapp)
        elif user_input == 6:
            serverEnum(webapp)
        elif user_input == 7:
            PortScann(webapp)
        elif user_input == 8:
            subNet(webapp)
        elif user_input == 9:
            IpEnum(webapp)
        elif user_input == 10:
            subDomainsEnum(webapp)
        elif user_input == 11:
            admin(webapp,"files/admins.ini")
        elif user_input == 12:
            userTarget = input("target username: ")
            useRecon(userTarget)
        elif user_input == 0:
            print("Scanning Finiched at:" + str(datetime.now()))
            exit(0)
    else:
        print("Uknowne option.")
        print(user_options)
try:
    HandelOpts()
except Exception:
    pass

