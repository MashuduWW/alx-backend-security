from celery import shared_task
from django.utils.timezone import now, timedelta
from django.db.models import Count
from .models import RequestLog, SuspiciousIP


@shared_task
def detect_suspicious_ips():
    """
    Detect IPs making too many requests (100+/hour)
    or accessing sensitive paths (/admin, /login).
    Flags them in SuspiciousIP model.
    """
    one_hour_ago = now() - timedelta(hours=1)

    # Rule 1: IPs with more than 100 requests in the last hour
    heavy_hitters = (
        RequestLog.objects.filter(timestamp__gte=one_hour_ago)
        .values("ip_address")
        .annotate(request_count=Count("id"))
        .filter(request_count__gt=100)
    )

    for entry in heavy_hitters:
        ip = entry["ip_address"]
        SuspiciousIP.objects.get_or_create(
            ip_address=ip,
            defaults={"reason": f"Excessive requests: {entry['request_count']} in the last hour"},
        )

    # Rule 2: IPs hitting sensitive paths
    sensitive_paths = ["/admin", "/login"]
    flagged = RequestLog.objects.filter(
        timestamp__gte=one_hour_ago,
        path__in=sensitive_paths
    ).values("ip_address").distinct()

    for entry in flagged:
        ip = entry["ip_address"]
        SuspiciousIP.objects.get_or_create(
            ip_address=ip,
            defaults={"reason": "Accessed sensitive path (/admin or /login)"},
        )
