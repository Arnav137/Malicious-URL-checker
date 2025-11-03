from deceptive_characters import check
from domain_age import dom_age
from redirect_chain import redirect_chain
import sys

url = sys.argv[1]
print('Domain age -',dom_age(url),'years')
print('Reputation -',)
print('Deceptive characters -',check(url))
print('Link Extraction -')
print('Redirection Chain:')
chain = redirect_chain(url)
print('(URL,status code)')
for i in chain:
    print('("',i[0],'",',i[1],')')
