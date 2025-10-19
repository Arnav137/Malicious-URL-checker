import requests

def redirect_chain(url):
    response = requests.get(url, allow_redirects=True)
    red_list = []
    if response.history:
        for i in enumerate(response.history):
            red_list.append((i[1].url,i[1].status_code))
        red_list.append((response.url,response.status_code))
        return red_list
    else:
        return [(response.url,response.status_code)]
        