import re
from patterns import *
from datetime import datetime
import time
from googlesearch import search
import requests
from bs4 import BeautifulSoup
import whois
from urllib.parse import urlparse
import socket

def having_ip_address(url):
    ip_address_pattern = ipv4_pattern + "|" + ipv6_pattern
    match = re.search(ip_address_pattern, url)
    return -1 if match else 1

def url_length(url):
    if len(url)<54 :
        return 1
    if 54<= len(url) <=75:
        return 0
    return -1

def shortening_service(url):
    match = re.search(shortening_services, url)
    return -1 if match else 1

def having_at_symbol(url):
    match = re.search('@', url)
    return -1 if match else 1

def double_slash_check(url):
    last_double_slash = url.rfind('//')
    return -1 if last_double_slash > 6 else 1

def counting_dots(url):
    
    if having_ip_address(url) == -1:
        match = re.search(
            '(([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.'
            '([01]?\\d\\d?|2[0-4]\\d|25[0-5]))|(?:[a-fA-F0-9]{1,4}:){7}[a-fA-F0-9]{1,4}',
            url)
        pos = match.end()
        url = url[pos:]
    num_dots = [x.start() for x in re.finditer(r'\.', url)]
    if len(num_dots) <= 3:
        return 1
    elif len(num_dots) == 4:
        return 0
    else:
        return -1

def detect_https_http(url):
    match = re.search(http_https, url)
    if match and match.start() == 0:
        url = url[match.end():]
    match = re.search('http|https', url)
    return -1 if match else 1

def google_index(url):
    site = search(url, 5)
    return 1 if site else -1

def get_hostname_from_url(url):
    # Initialize hostname with a default value
    hostname = url
    
    try:
        parsed_url = urlparse(url)
        # Update hostname with the parsed netloc if it's valid
        if parsed_url.netloc:
            hostname = parsed_url.netloc
    except Exception as e:
        print(f"Error extracting hostname: {e}")
    
    return hostname

def prefix_suffix(domain):
    match = re.search('-', domain)
    return -1 if match else 1

def domain_registration_length(domain):
    # this function will be seen later
    expiration_date = domain.expiration_date
    today = time.strftime('%Y-%m-%d')
    today = datetime.strptime(today, '%Y-%m-%d')

    registration_length = 0
    if expiration_date:
        registration_length = abs((expiration_date - today).days)
    return -1 if registration_length / 365 <= 1 else 1

def favicon(url, soup, domain):
    for head in soup.find_all('head'):
        for link in soup.find_all('link', href=True):
            dots = [x.start() for x in re.finditer(r'\.', link['href'])]
            return 1 if url in link['href'] or len(dots) == 1 or domain in link['href'] else -1
    return 1

def request_url(url, soup, domain):
    i = 0
    success = 0
    for img in soup.find_all('img', src=True):
        dots = [x.start() for x in re.finditer(r'\.', img['src'])]
        if url in img['src'] or domain in img['src'] or len(dots) == 1:
            success += 1
        i += 1

    for audio in soup.find_all('audio', src=True):
        dots = [x.start() for x in re.finditer(r'\.', audio['src'])]
        if url in audio['src'] or domain in audio['src'] or len(dots) == 1:
            success += 1
        i += 1

    for embed in soup.find_all('embed', src=True):
        dots = [x.start() for x in re.finditer(r'\.', embed['src'])]
        if url in embed['src'] or domain in embed['src'] or len(dots) == 1:
            success += 1
        i += 1

    for iframe in soup.find_all('iframe', src=True): 
        dots = [x.start() for x in re.finditer(r'\.', iframe['src'])]
        if url in iframe['src'] or domain in iframe['src'] or len(dots) == 1:
            success += 1
        i += 1

    if i == 0:
        return 1

    percentage = success / float(i) * 100

    if percentage < 22.0:
        return 1
    elif 22.0 <= percentage < 61.0:
        return 0
    else:
        return -1

def url_of_anchor(url, soup, domain):
    i = 0
    unsafe = 0
    for a in soup.find_all('a', href=True):
        # 2nd condition was 'JavaScript ::void(0)' but we put JavaScript because the space between javascript and ::
        # might not be
        # there in the actual a['href']
        if "#" in a['href'] or "javascript" in a['href'].lower() or "mailto" in a['href'].lower() or not (
                url in a['href'] or domain in a['href']):
            unsafe = unsafe + 1
        i = i + 1
        # print a['href']
    try:
        percentage = unsafe / float(i) * 100
    except:
        return 1
    if percentage < 31.0:
        return 1
        # return percentage
    elif 31.0 <= percentage < 67.0:
        return 0
    else:
        return -1

def links_in_tags(url, soup, domain):
    i = 0
    success = 0
    for link in soup.find_all('link', href=True):
        dots = [x.start() for x in re.finditer(r'\.', link['href'])]
        if url in link['href'] or domain in link['href'] or len(dots) == 1:
            success = success + 1
        i = i + 1

    for script in soup.find_all('script', src=True):
        dots = [x.start() for x in re.finditer(r'\.', script['src'])]
        if url in script['src'] or domain in script['src'] or len(dots) == 1:
            success = success + 1
        i = i + 1
    try:
        percentage = success / float(i) * 100
    except:
        return 1

    if percentage < 17.0:
        return 1
    elif 17.0 <= percentage < 81.0:
        return 0
    else:
        return -1

def sfh(url, soup, domain):
    for form in soup.find_all('form', action=True):
        if form['action'] == "" or form['action'] == "about:blank":
            return -1
        elif url not in form['action'] and domain not in form['action']:
            return 0
        else:
            return 1
    return 1

def submitting_to_email(soup):
    for form in soup.find_all('form', action=True):
        return -1 if "mailto:" in form['action'] else 1
    # In case there is no form in the soup, then it is safe to return 1.
    return 1

def abnormal_url(domain, url):
    hostname = domain.name
    match = re.search(hostname, url)
    return 1 if match else -1

def i_frame(soup):
    for iframe in soup.find_all('iframe', width=True, height=True, frameborder=True):
        # Even if one iframe satisfies the below conditions, it is safe to return -1 for this method.
        if iframe['width'] == "0" and iframe['height'] == "0" and iframe['frameborder'] == "0":
            return -1
        if iframe['width'] == "0" or iframe['height'] == "0" or iframe['frameborder'] == "0":
            return 0
    # If none of the iframes have a width or height of zero or a frameborder of size 0, then it is safe to return 1.
    return 1

def age_of_domain(domain):
    creation_date = domain.creation_date
    ageofdomain = 0
    
    if creation_date:
        # Calculate the age of the domain in days
        ageofdomain = abs((datetime.now() - creation_date).days)
    
    # Convert days to months (approximation by dividing by 30)
    return -1 if ageofdomain / 30 < 6 else 1

def statistical_report(url, hostname):
    try:
        ip_address = socket.gethostbyname(hostname)
    except socket.gaierror:
        return -1
    
    # URLs and IP addresses that are potentially malicious
    url_match = re.search(r'at\.ua|usa\.cc|baltazarpresentes\.com\.br|pe\.hu|esy\.es|hol\.es|sweddy\.com|myjino\.ru|96\.lt|ow\.ly', url)
    ip_match = re.search(r'146\.112\.61\.108|213\.174\.157\.151|121\.50\.168\.88|192\.185\.217\.116|78\.46\.211\.158|'
                         r'181\.174\.165\.13|46\.242\.145\.103|121\.50\.168\.40|83\.125\.22\.219|46\.242\.145\.98|'
                         r'107\.151\.148\.44|107\.151\.148\.107|64\.70\.19\.203|199\.184\.144\.27|107\.151\.148\.108|'
                         r'107\.151\.148\.109|119\.28\.52\.61|54\.83\.43\.69|52\.69\.166\.231|216\.58\.192\.225|'
                         r'118\.184\.25\.86|67\.208\.74\.71|23\.253\.126\.58|104\.239\.157\.210|175\.126\.123\.219|'
                         r'141\.8\.224\.221|10\.10\.10\.10|43\.229\.108\.32|103\.232\.215\.140|69\.172\.201\.153|'
                         r'216\.218\.185\.162|54\.225\.104\.146|103\.243\.24\.98|199\.59\.243\.120|31\.170\.160\.61|'
                         r'213\.19\.128\.77|62\.113\.226\.131|208\.100\.26\.234|195\.16\.127\.102|195\.16\.127\.157|'
                         r'34\.196\.13\.28|103\.224\.212\.222|172\.217\.4\.225|54\.72\.9\.51|192\.64\.147\.141|'
                         r'198\.200\.56\.183|23\.253\.164\.103|52\.48\.191\.26|52\.214\.197\.72|87\.98\.255\.18|'
                         r'209\.99\.17\.27|216\.38\.62\.18|104\.130\.124\.96|47\.89\.58\.141|78\.46\.211\.158|'
                         r'54\.86\.225\.156|54\.82\.156\.19|37\.157\.192\.102|204\.11\.56\.48|110\.34\.231\.42', ip_address)
    
    if url_match or ip_match:
        return -1
    else:
        return 1


def get_features(url):
    # Initialize soup with a default value
    soup = BeautifulSoup('<html><body></body></html>', 'html.parser')

    try:
        # Fetching the HTML content from the URL
        response = requests.get(url)
        response.raise_for_status()  # Raise an HTTPError for bad responses
        # Update soup with the fetched HTML content
        soup = BeautifulSoup(response.text, 'html.parser')
    except requests.RequestException as e:
        print(f"Request error: {e}")

    # Extract hostname from URL
    hostname = get_hostname_from_url(url)

    dns = 1
    try:
        domain_info = whois.whois(hostname)
    except Exception as e:
        print(f"WHOIS query error: {e}")
        dns = -1

    #l = request_url(url, soup, hostname)
    print(l)

get_features("https://moonbqg.info")

    




        
    

