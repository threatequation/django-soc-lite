# django-soc-lite #

* A security middleware for Django app to Detect OWASP Top Basic and generate report in your dashboard


##with ``pip``:
    
    $ pip install django-soc-lite


Configure to Your APP
=================

    . Add  `django_soc_lite` to your project's `INSTALLED_APPS` in`settings.py` file.
    
    . Add the following middleware to your project's `MIDDLEWARE_CLASSES` in `settings.py` file:
    
      ``'django_soc_lite.threat.middleware.ThreatEquationMiddleware',``
      
      
Include your Product_key and Api key (without this step, plugin will not work)
================= 

    . in your `settings.py` file place your keys in anywhere.

         THREAT_EQUATION_PRODUCT_KEY = <your product_id>
         THREAT_EQUATION_API_KEY = <your api_key>

    . example-

         THREAT_EQUATION_PRODUCT_KEY = 'aaaaabbbbb'
         THREAT_EQUATION_API_KEY = '1111111111999999999999xxxxxxxxxxxxxxxxx'


## Features ##

1. SQL injection Attack
3. XSS Attack
4. Insecure File Access


### Who do I talk to? ###

* contact@threatequation.com