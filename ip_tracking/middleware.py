from django.http import HttpResponseForbidden
from django.utils.timezone import now
from .models import RequestLog, BlockedIP


class IPLogMiddleware:
    """
    Middleware to log IP address, timestamp, and request path
    for every incoming request, and block blacklisted IPs.
    """

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        ip_address = self.get_client_ip(request)

        # Block request if IP is blacklisted
        if BlockedIP.objects.filter(ip_address=ip_address).exists():
            return HttpResponseForbidden("Your IP has been blocked.")

        # Log request
        RequestLog.objects.create(
            ip_address=ip_address,
            timestamp=now(),
            path=request.path
        )

        return self.get_response(request)

    def get_client_ip(self, request):
        """Extract client IP address from request headers or META"""
        x_forwarded_for = request.META.get("HTTP_X_FORWARDED_FOR")
        if x_forwarded_for:
            return x_forwarded_for.split(",")[0].strip()
        return request.META.get("REMOTE_ADDR")
