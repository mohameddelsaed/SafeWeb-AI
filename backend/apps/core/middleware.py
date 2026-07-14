import uuid
import contextvars
import logging

request_id_ctx = contextvars.ContextVar('request_id', default=None)

class RequestIDMiddleware:
    """
    Middleware that adds a unique X-Request-ID header to every request and 
    makes it available to the logging formatter via contextvars.
    """
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        request_id = request.headers.get('X-Request-ID')
        if not request_id:
            request_id = str(uuid.uuid4())
        
        request.request_id = request_id
        
        # Set the context variable
        token = request_id_ctx.set(request_id)
        
        try:
            response = self.get_response(request)
        finally:
            request_id_ctx.reset(token)

        # Include request ID in the response headers
        response['X-Request-ID'] = request_id
        return response


class RequestIDLogFilter(logging.Filter):
    """
    Adds request_id to log records.
    """
    def filter(self, record):
        record.request_id = request_id_ctx.get()
        return True


class SecurityHeadersMiddleware:
    """
    Adds Content-Security-Policy header to every response.
    """
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        response = self.get_response(request)
        # Add basic CSP
        csp = (
            "default-src 'self'; "
            "img-src 'self' data: https:; "
            "font-src 'self' data: https:; "
            "style-src 'self' 'unsafe-inline' https:; "
            "connect-src 'self' https: wss:; "
            "script-src 'self';"
        )
        response['Content-Security-Policy'] = csp
        return response
