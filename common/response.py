from rest_framework.response import Response


def build_response(message, data=None, errors=None, status=200, **kwargs):
    response_result = {
        "status": status,
        "message": message,
        "data": data,
        "errors": errors,
        **kwargs
    }
    return Response(response_result, status=status)
