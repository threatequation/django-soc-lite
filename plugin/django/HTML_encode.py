class HTMLEncoding(object):
    def __init__(self):
        pass
    def XSSEncode(self, s):
        htmlCodes = (
            ("'", '&#39;'),
            ('"', '&quot;'),
            ('>', '&gt;'),
            ('<', '&lt;'),
            ('%3C', '&lt;'),
            ('%3E', '&gt;'),
            ('&', '&amp;'),
            ('/', '&#x2F;'),
            ('document.', 'dom'),
        )
        for code in htmlCodes:
            maliciouscode = maliciouscode.replace(code[0], code[1])

        return maliciouscode
        
    def FileInjectionEncode(self, s):
        htmlCodes = (
            (".", ''),
            (' &#183;', ''),
            ('/', ''),
            ('&#47;', ''), 
        )
        for code in htmlCodes:
            path = path.replace(code[0], code[1])

        return path