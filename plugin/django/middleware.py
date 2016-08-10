from __future__ import absolute_import, division, print_function

import json
import re
import requests

from datetime import datetime
from plugin import client_id, port, server
from plugin.info import send_client_info
from django.http import QueryDict, HttpResponse
from plugin.HTML_Encode import HTMLEncoding
"""
def add_hooks(run_hook, get_agent_func=None, timer=None):
    try:
        import django
        import django.conf
    except ImportError:
        return None

    hook_templates(run_hook, timer)

    meta = {
        "version": django.get_version(),
    }

    return meta


def hook_templates(run_hook, timer):
    try:
        import django
    except ImportError:
        return
"""
xss_strict = re.compile("((%3C|<)[^\n]+(%3E|>))|((%3C|<)/[^\n]+(%3E|>))|(document.)")
secure_file_format = re.compile("(.)*/(?:$|(.+?)(?:(\.[^.]*$)|$))")       #def FileInjection():

encoding = HTMLEncoding()

class ThreatEquationMiddleware(object):

    #@add_hooks
    #@hook_templates
    def process_request(self, request):
        self.request = request
        self.XSSMiddleware()
        self.INJECTIONMiddleware()
        #self.CSRFMiddleware()
        #self.SESSIONMiddleware()
        #self.CSRFMiddleware()
        #self.CSRFMiddleware()
        
        
    def XSSMiddleware(self):
        query = self.request.META.get('QUERY_STRING')
        if not query:
            return 
        q = QueryDict(query)
        dict = q.dict()
        list = [k for k in dict]
        parameter = list[0]
        value = dict[dict.keys()[0]]
        if xss_strict.search(str(value)):
            """
            url = "http://{0}:{1}/log/new".format(server, port)
            requests.post(url, data={
                "client_id": client_id,
                "timestamp": datetime.utcnow(),
                "data": json.dumps({
                    "event": "XSS attempt",
                    "url": request.path,
                    "query_string": query,
                })
            })
            """    
            #send_client_info()
            self.request.META['QUERY_STRING']=str(parameter+'='+encoding.XSSEncode(value))
        
    def INJECTIONMiddleware(self):
        def SQLInjection():
            self.request.POST = self.request.POST.copy()
            l = [k for k in self.request.POST]
            if not l:
                return False
            par = l[0] 
            value = self.request.POST.get(par)
            # perform operation on value
            re = True
            if re:
                self.request.POST.update({ par: value })
                return True

        def FileInjection():
            query = self.request.META.get('QUERY_STRING') 
            if query is None or query == '':
                return False
            q = QueryDict(query)
            dict = q.dict()
            list = [k for k in dict]
            parameter = list[0]
            value = dict[dict.keys()[0]]
            
            if secure_file_format.search(value):
                """
                url = "http://{0}:{1}/log/new".format(server, port)
                requests.post(url, data={
                    "client_id": client_id,
                    "timestamp": datetime.utcnow(),
                    "data": json.dumps({
                        "event": "XSS attempt",
                        "url": request.path,
                        "query_string": query,
                    })
                })
                """
            self.request.META['QUERY_STRING']=str(parameter)+'='+str(encoding.FileInjectionEncode(value))    
            return True
            
            
        if not SQLInjection():
            FileInjection()
 
