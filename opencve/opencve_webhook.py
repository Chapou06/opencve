import requests



class webhook_constructor:

    def newhookurl(self, nhookurl):
        self.hookurl = nhookurl
        return self
    def text(self, mtext):
            self.payload["text"] = mtext
            return self
    def send(self):
        headers = {"Content-Type": "text/html"}
        r = requests.post(
            self.hookurl,
            json=self.payload,
            headers=headers,
            proxies=self.proxies,
            timeout=self.http_timeout,
            verify=self.verify,
        )
    def __init__(self, hookurl, http_proxy=None, https_proxy=None, http_timeout=60, verify=None):
        self.payload = {}
        self.hookurl = hookurl
        self.proxies = {}
        self.http_timeout = http_timeout
        self.verify = verify
        self.last_http_response = None
        

def send_opencve_alert(alerts,user):    
    
    webhook = webhook_constructor(user.webhook_url)
    webhook.text(alerts)
    webhook.send()


    

#send_opencve_alert("<html><title>Test</title><body><h1 style='font-weight: bold; color: red;'>Hello from the other side.</h1><p style='padding: 10px; background-color: #eee; border-radius: 10px;'>This is a paragraph</p></body></html>")
