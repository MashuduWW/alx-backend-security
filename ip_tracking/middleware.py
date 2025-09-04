from django.http import HttpResponseForbidden
from django.utils.timezone import now
from django.core.cache import cache
from ipgeolocation import IpGeoLocation
from .models import RequestLog, BlockedIP


class IPLogMiddleware:
    """
    Middleware to log IP address, timestamp, request path,
    and geolocation data (country, city).
    Blocks blacklisted IPs.
    """

    def __init__(self, get_response):
        self.get_response = get_response
        self.geo = IpGeoLocation()

    def __call__(self, request):
        ip_address = self.get_client_ip(request)

        # Block request if IP is blacklisted
        if BlockedIP.objects.filter(ip_address=ip_address).exists():
            return HttpResponseForbidden("Your IP has been blocked.")

        # Fetch geolocation data (cached for 24h)
        cache_key = f"geo:{ip_address}"
        geo_data = cache.get(cache_key)

        if not geo_data:
            try:
                response = self.geo.get(ip_address)
                country = response.get("country_name", "")
                city = response.get("city", "")
                geo_data = {"country": country, "city": city}
                cache.set(cache_key, geo_data, timeout=60 * 60 * 24)  # 24 hours
            except Exception:
                geo_data = {"country": "", "city": ""}

        # Log request
        RequestLog.objects.create(
            ip_address=ip_address,
            timestamp=now(),
            path=request.path,
            country=geo_data.get("country", ""),
            city=geo_data.get("city", "")
        )

        return self.get_response(request)

    def get_client_ip(self, request):
        """Extract client IP address from request headers or META"""
        x_forwarded_for = request.META.get("HTTP_X_FORWARDED_FOR")
        if x_forwarded_for:
            return x_forwarded_for.split(",")[0].strip()
        return request.META.get("REMOTE_ADDR")
