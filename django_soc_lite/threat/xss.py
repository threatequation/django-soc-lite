from ..threat.middleware import *
import bleach
from .. import url_coder, rule_checker, HTML_Escape
from ..threat.log_generator import send
def send_log(request, query, description):
    send(request, "XSS", str(query), request.path, 'input validation and white+black list testing', description)

class XSSMiddleware(object):
    def __init__(self, request):
        self.request = request
        if self.request.method == 'GET':
            self.get_method()
        if self.request.method == 'POST':
            self.post_method()

    def get_method(self):
        query = self.request.META.get('QUERY_STRING')
        if query:
            q = QueryDict(query)
            dict = q.dict()
            list = [k for k in dict]
            parameter = list[0]
            org_value = dict[parameter]
            value = url_coder.decoder(str(org_value))                    #decoding/double/decoding
            if rule_checker.xss_filter(str(value)):                      #check attack 
                #print('don')
                send_log(self.request, query,rule_checker.xss_filter(str(value))[1])
                
                return True
            return False
        if not query:
            try:
                path = self.request.path
                import os.path                                    
                org_value = os.path.split(path)[1]                         #last value from path
                value = url_coder.decoder(str(org_value))                   #decoding/double/decoding
                if rule_checker.xss_filter(str(value)):                #check attack
                    send_log(self.request, org_value, rule_checker.xss_filter(str(value))[1])
                    q = bleach.clean(value)
                    if not isinstance(q, str):
                        q = q.encode("utf-8")
 
                    q = HTML_Escape.XSSEncode(q)   
                self.request.path_info = os.path.join(os.path.split(path)[0],q)            #update path
                return True
            except:
                return False  
    def post_method(self):
        self.request.POST = self.request.POST.copy()
        l = [k for k in self.request.POST]
        if not l:
            return
        for i in range(len(l)):
            par = l[i] 
            org_value = self.request.POST.get(par)
            value = url_coder.decoder(str(org_value))
            if rule_checker.xss_filter(str(value)): 
                send_log(self.request, str(par+'='+org_value), rule_checker.xss_filter(str(value))[1]) 
                q = bleach.clean(value)
                if not isinstance(q, str):
                    q = q.encode("utf-8")
                q = HTML_Escape.XSSEncode(q)
                self.request.POST.update({ par: q}) 
