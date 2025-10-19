import whois
import sys
from datetime import datetime

def dom_age(url):
    try:
        name = url.split('//')[-1].split('/')[0]
        info = whois.whois(name)
        if info.creation_date:
            if isinstance(info.creation_date,list):
                date = info.creation_date[0]
            else:
                date = info.creation_date
            today = datetime.now()
            age = datetime.date(today) - datetime.date(date)
            return age
        else:
            return 'could not find creation date'
    except TimeoutError:
        return 'timeout'