import csv
import re
import socket
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime

import dns.resolver, dns.rdatatype
import requests
from bs4 import BeautifulSoup
from collections import Counter
import whois
from datetime import datetime
import time
import csv
import ssl
import socket
from urllib.parse import urlparse
import pandas as pd
import random

# Define input files and output file
phishing_file = "phishing.csv"
non_phishing_file = "non_phishing.csv"
output_file = "merged_dataset.csv"


# Function to generate a random user agent
def generate_user_agent():
    return f"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{random.randint(63, 100)}.0.{random.randint(1000, 4000)}.0 Safari/537.36"


headers = {
    "User-Agent": generate_user_agent()
}


def make_request(url: str, headers: dict, timeout: int, retries: int) -> requests.Response:
    for i in range(retries):
        try:
            response = requests.get(url, headers=headers, timeout=timeout, allow_redirects=True)
            response.raise_for_status()
            return response
        except requests.exceptions.RequestException as e:
            retry_delay = 2**i
            print(f'\033[34mRequestException for {url}: {e}. Retrying in {retry_delay} seconds...\033[0m')
            time.sleep(retry_delay)
        except Exception as e:
            print(f'\033[31mError making request for {url}: {e}\033[0m')
            return None
    print(f'\033[31mFailed to make request after {retries} retries.\033[0m')
    return None


def get_certificate_info(url: str) -> tuple[str, int]:
    """
    Returns the issuer and age of the certificate if found. None, None otherwise
    """

    try:
        if not url.startswith("https://"):
            raise ValueError("URL must use HTTPS protocol")

        hostname = url.split("https://")[1].split("/")[0]
        ip_addresses = socket.getaddrinfo(hostname, 443)
        ip_address = ip_addresses[0][4][0]

        context = ssl.create_default_context()
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        ssl_conn = context.wrap_socket(sock, server_hostname=hostname)
        ssl_conn.connect((ip_address, 443))
        cert = ssl_conn.getpeercert()

        if 'notAfter' not in cert:
            raise ValueError("Certificate information not found")

        issuer = cert['issuer'][0][0][1]
        not_after = cert['notAfter']

        not_after_date = datetime.strptime(not_after, '%b %d %H:%M:%S %Y %Z')
        certificate_age = (datetime.now() - not_after_date).days

        return issuer, certificate_age

    except Exception as e:
        print(f"get_certificate_info error: {str(e)}")

    return None, None



def extract_server_version_from_text(text):
    """
    Extracts the server or CMS version information from the given text (headers or page source).
    Returns a tuple (label, version) where:
    - label: Numeric identifier for the software type.
    - version: Extracted version string.
    Returns (-1, None) if no match is found.
    """
    software_mapping = {
        "PHP": 1,
        "Apache": 2,
        "nginx": 3,
        "IIS": 4,
        "LiteSpeed": 5,
        "Caddy": 6,
        "OpenResty": 7,
        "Tomcat": 8,
        "Jetty": 9,
        "JBoss": 10,
        "Node.js": 11,
        "Express": 12,
        "Drupal": 13,
        "WordPress": 14,
        "Joomla!": 15,
        "Magento": 16,
        "Shopify": 17,
        "Prestashop": 18
    }

    patterns = [
        (r'PHP\/([\d.]+)', "PHP"),
        (r'Apache\/([\d.]+)', "Apache"),
        (r'nginx\/([\d.]+)', "nginx"),
        (r'IIS\/([\d.]+)', "IIS"),
        (r'LiteSpeed\/([\d.]+)', "LiteSpeed"),
        (r'Caddy\/([\d.]+)', "Caddy"),
        (r'OpenResty\/([\d.]+)', "OpenResty"),
        (r'Tomcat\/([\d.]+)', "Tomcat"),
        (r'Jetty\/([\d.]+)', "Jetty"),
        (r'JBoss\/([\d.]+)', "JBoss"),
        (r'Node\.js\/([\d.]+)', "Node.js"),
        (r'Express\/([\d.]+)', "Express"),
        (r'\bDrupal\s*([\d.]+)', "Drupal"),
        (r'\bWordPress\s*([\d.]+)', "WordPress"),
        (r'\bJoomla!\s*([\d.]+)', "Joomla!"),
        (r'\bMagento\s*([\d.]+)', "Magento"),
        (r'\bShopify\s*([\d.]+)', "Shopify"),
        (r'\bPrestashop\s*([\d.]+)', "Prestashop")
    ]

    for pattern, software_type in patterns:
        match = re.search(pattern, text, re.IGNORECASE)
        if match:
            version = match.group(1)  # Extract version number
            label = software_mapping[software_type]
            return label, version

    return -1, None  # Default if no match is found


def extract_server_version(url):
    """
    Extracts server version information from both headers and page source of the given URL.
    Returns a tuple (label, version) where:
    - label: Numeric identifier for the software type.
    - version: Extracted version string.
    Returns (-1, None) if no match is found.
    """
    try:
        response = requests.get(url, timeout=10,
                                headers={"User-Agent": "Mozilla/5.0"})

        # Check server version in headers
        server_header = response.headers.get('Server', '')
        label, version = extract_server_version_from_text(server_header)
        if label != -1:
            print(f"Found server version in headers: Label={label}, Version={version}")
            return label, version

        # Check server version in page source
        page_source = response.text
        label, version = extract_server_version_from_text(page_source)
        if label != -1:
            print(f"Found server version in page source: Label={label}, Version={version}")
            return label, version

    except requests.RequestException as e:
        print(f"Error accessing {url}: {e}")

    return -1, None  # Default if no match is found


def request_url_percentage(soup: BeautifulSoup, domain: str) -> float:
    """
    Returns the percentage of external domains in the URL
    """
    links = [link.get('href') for link in soup.find_all('a')]
    images = [img.get('src') for img in soup.find_all('img')]
    videos = [video.get('src') for video in soup.find_all('video')]
    sounds = [sound.get('src') for sound in soup.find_all('audio')]
    external_links = []

    for link in links + images + videos + sounds:
        if link is None:
            continue
        parsed_domain = urlparse(link).netloc
        if parsed_domain != '' and parsed_domain != domain:
            external_links.append(link)

    external_domains = [urlparse(link).netloc for link in external_links]
    domain_counts = Counter(external_domains)

    total_links = len(external_domains)
    if total_links == 0:
        return 1
    external_links_count = domain_counts[domain]

    return (external_links_count / total_links)


def dns_record(domain: str) -> tuple[int, int, int]:
    """
    Returns TTL, IP address count and TXT record presence in a tuple of integers.
    Returns None, None, None if dns record not found.
    """
    try:
        answers = dns.resolver.resolve(domain)
        TTL = answers.rrset.ttl
        IP_addresses = len(answers)
        TXT_records = any(answer.rdtype == dns.rdatatype.TXT for answer in answers)
        TXT_records = 1 if TXT_records else 0

        return TTL, IP_addresses, TXT_records
    except dns.resolver.NXDOMAIN:
        return None, None, None
    except Exception as e:
        print(f"dns_record error: {str(e)}")
        return None, None, None


def count_domain_occurrences(soup: BeautifulSoup, domain: str) -> int:
    """
    Returns the number of occurrences of the domain in the website's page source.
    """
    try:
        domain_count = soup.prettify().count(domain)
        return domain_count
    except Exception as e:
        print(f"count_domain_occurrences: {str(e)}")
        return 0


def domain_registeration_length(w: whois.WhoisEntry) -> int:
    """"
    Returns the number of days since the domain was registered, None if error
    """
    try:
        domain = w.domain_name
        expiration_date = w.expiration_date
        if type(expiration_date) == list:
            expiration_date = expiration_date[0]
        if expiration_date is not None:
            time_to_expire = (expiration_date - datetime.now()).days
            return time_to_expire
        else:
            return 0
    except Exception as e:
        print('domain_registeration_length error: ' + str(e))
        return None


def abnormal_url(url: str, w: whois.WhoisEntry) -> int:
    """
    Returns 1 if the hostname is not in the URL, 0 otherwise.
    """
    host_name = w.domain.split('.')[0]
    if host_name not in url:
        return 1
    else:
        return 0


def age_of_domain(w: whois.WhoisEntry) -> int:
    """
    Returns the age of domain in days, None if error
    """
    try:
        creation_date = w.creation_date

        if creation_date is None:
            # Domain creation date is not available, try using updated_date as a fallback
            updated_date = w.updated_date
            if updated_date is None:
                return -1
            if type(updated_date) == list:
                creation_date = min(updated_date)
            else:
                creation_date = updated_date

        if type(creation_date) == list:
            creation_date = min(creation_date)

        num_days = (datetime.now() - creation_date).days

        return num_days
    except Exception as e:
        print('age_of_domain error: ' + str(e))
        return None


# Function to process and extract features for a single URL
def process_url(url, label):

    try:
        response = make_request(url, headers, timeout=10, retries=3)
        if response is None:
            return
    except Exception as e:
        print(f'Error making request: {e}')
        return
    issuer, certificate_age = get_certificate_info(url)
    server_label, server_version = extract_server_version(url)

    try:
        soup = BeautifulSoup(response.content, 'html.parser')
        parsed_url = urlparse(url)
        domain = parsed_url.netloc
        request_url_percentage_value = request_url_percentage(soup, domain)
        TTL, ip_address_count, TXT_record = dns_record(domain)
        count_domain_occurrences_value = count_domain_occurrences(soup, domain)
    except Exception as e:
        print('urlparse error, double check your code: ' + str(e))
        return

    try:
        w = whois.whois(domain)
        domain_registeration_length_value = domain_registeration_length(w)
        abnormal_url_value = abnormal_url(url, w)
        age_of_domain_value = age_of_domain(w)
    except Exception as e:
        print('whois error: ' + str(e))
        domain_registeration_length_value = None
        abnormal_url_value = None
        age_of_domain_value = None


    return [url, server_label, server_version, request_url_percentage_value, count_domain_occurrences_value, TTL, ip_address_count, TXT_record, issuer, certificate_age, domain_registeration_length_value, abnormal_url_value, age_of_domain_value, label]


# Function to process a dataset
def process_dataset(input_file, label):
    results = []
    with open(input_file, "r") as infile:
        reader = csv.reader(infile)
        next(reader, None)  # Skip header if present
        urls = [row[0] for row in reader if row]

    # Use ThreadPoolExecutor for multithreaded processing
    with ThreadPoolExecutor(max_workers=10) as executor:
        for result in executor.map(lambda url: process_url(url, label), urls):
            if result:
                results.append(result)
    return results


# Main function to process both datasets and merge
def main():
    # Process phishing dataset (label=1)
    print("Processing phishing dataset...")
    phishing_data = process_dataset(phishing_file, label=1)

    # Process non-phishing dataset (label=0)
    print("Processing non-phishing dataset...")
    non_phishing_data = process_dataset(non_phishing_file, label=0)

    # Merge datasets
    all_data = phishing_data + non_phishing_data

    # Write merged dataset to output file
    with open(output_file, "w", newline="") as outfile:
        writer = csv.writer(outfile)
        # Write header (update based on your features)
        writer.writerow(
            ["url", "server_label", "server_version", "request_url_percentage", "count_domain_occurrences", "TTL", "ip_address_count", "TXT_record", "issuer", "certificate_age", "domain_registeration_length", "abnormal_url", "age_of_domain", "label"])
        writer.writerows(all_data)

    print(f"Merged dataset saved to {output_file}")


if __name__ == "__main__":
    main()
