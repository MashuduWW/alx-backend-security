def user_or_ip(request):
    if request.user.is_authenticated:
        return str(request.user.pk)  # Use user ID
    return request.META.get("REMOTE_ADDR")  # Fall back to IP
