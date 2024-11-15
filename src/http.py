import http.client
import random

URL_SIZE = 4096
USERAGENT_SIZE = 150

class Url:
    def __init__(self, protocol="", host="", path=""):
        self.protocol = protocol
        self.host = host
        self.path = path

class UrlArray:
    def __init__(self):
        self.size = 0
        self.urls = []

def get_url(file):
    buffer = file.readline().strip()
    u = Url()
    if len(buffer) > 4:
        parts = buffer.split("://")
        if len(parts) == 2:
            u.protocol = parts[0]
            host_path = parts[1].split("/", 1)
            u.host = host_path[0]
            if len(host_path) == 2:
                u.path = host_path[1]
    return u

def read_urls(urlfilename, verbose):
    urllist = []
    with open(urlfilename, "r") as file:
        for line in file:
            u = get_url(file)
            if u.path:
                urllist.append(u)
    if verbose:
        print("The URLs are:")
        for url in urllist:
            print(f"{url.host}/{url.path}")
    url_array = UrlArray()
    url_array.size = len(urllist)
    url_array.urls = urllist
    return url_array

def build_request(nurl, nref, nuseragent, urls, useragents):
    host = urls.urls[nurl].host
    path = urls.urls[nurl].path
    useragent = useragents[nuseragent]
    request = f"GET /{path} HTTP/1.0\r\nHost: {host}\r\nUser-agent: {useragent}\r\n"
    request += "Accept: text/xml,application/xml,application/xhtml+xml,text/html;q=0.9,text/plain;q=0.8,image/png,*/*;q=0.5\r\n"
    request += "Accept-Language: en-us,en;q=0.5\r\n"
    request += "Accept-Encoding: gzip,deflate\r\n"
    request += "Accept-Charset: ISO-8859-1,utf-8;q=0.7,*;q=0.7\r\n"
    if nref >= 0:
        referer = f"Referer: {urls.urls[nref].host}/{urls.urls[nref].path}\r\n"
        request += referer
    request += "Connection: close\r\n\r\n"
    return request

def read_useragents(useragentfilename):
    useragents = []
    with open(useragentfilename, "r") as file:
        for line in file:
            useragents.append(line.strip())
    return useragents
