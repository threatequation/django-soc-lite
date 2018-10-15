from functools import wraps

from django.http import HttpResponseNotAllowed
from django.utils.decorators import available_attrs
from django.utils.log import getLogger

from flags import WRONG_METHOD
from signals import warning


logger = getLogger('django.request')


def require_http_methods(request_method_list):
    """Like the Django decorators, but they also raise a warning."""
    def decorator(func):
        @wraps(func, assigned=available_attrs(func))
        def inner(request, *args, **kwargs):
            if request.method not in request_method_list:
                # Raise our warning.
                warning.send(sender=require_http_methods, flag=WRONG_METHOD,
                             message=u'%s not allowed' % request.method,
                             values=[request_method_list])
                logger.warning('Method Not Allowed (%s): %s',
                               request.method, request.path,
                               extra={
                                    'status_code': 405,
                                    'request': request
                               })
                return HttpResponseNotAllowed(request_method_list)
            return func(request, *args, **kwargs)
        return inner
    return decorator