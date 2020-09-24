import urllib3
import re

http = urllib3.PoolManager()

def test():
    #url = "https://www.google.com/search?q=MSIL&oq=MSIL&aqs=chrome..69i57j35i39j0l3j69i60l2j69i61.3671j0j7&sourceid=chrome&ie=UTF-8"
    url = "https://howtofix.guide/trojan-psw-msil-agensla/"
    result = http.request(method = "GET", url = url ,headers = {"user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/84.0.4147.135 Safari/537.36"})
    print(result.data.decode("UTF-8"))
    with open("./Agensla3.html","wb") as f :
        f.write(result.data)
test()