from urllib.parse import urlparse
import sys
def check(url):
    """
    Checks if any part of a URL's domain name is Punycode encoded.
    """
    parsed_url = urlparse(url)
    hostname = parsed_url.hostname
    if hostname:
        domain_parts = hostname.split('.')
        for part in domain_parts:
            if part.startswith('xn--'):
                return True
    return False

print(check(sys.argv[1]))