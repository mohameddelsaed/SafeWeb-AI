from rest_framework.views import exception_handler
from rest_framework.response import Response
from rest_framework import status
import logging

logger = logging.getLogger(__name__)


def custom_exception_handler(exc, context):
    """Custom exception handler for consistent error response format."""
    response = exception_handler(exc, context)

    if response is not None:
        error_code = exc.__class__.__name__
        message = 'An error occurred.'
        details = {}

        if isinstance(response.data, dict):
            if 'detail' in response.data:
                message = str(response.data.pop('detail'))
            details = response.data
        elif isinstance(response.data, list):
            if response.data:
                message = str(response.data[0])
        
        response.data = {
            'error_code': getattr(exc, 'default_code', error_code).upper(),
            'message': message,
            'details': details,
        }
    else:
        logger.exception('Unhandled exception', exc_info=exc)
        response = Response(
            {
                'error_code': 'INTERNAL_SERVER_ERROR',
                'message': 'An internal server error occurred.',
                'details': {}
            },
            status=status.HTTP_500_INTERNAL_SERVER_ERROR,
        )

    return response
