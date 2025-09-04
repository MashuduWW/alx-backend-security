from django.http import JsonResponse
from ratelimit.decorators import ratelimit
from .utils import user_or_ip


@ratelimit(key="ip", rate="5/m", method="POST", block=True)  # Anonymous fallback
@ratelimit(key=user_or_ip, rate="10/m", method="POST", block=True)
def login_view(request):
    if request.method == "POST":
        # Example dummy login logic
        username = request.POST.get("username")
        password = request.POST.get("password")

        # Just simulating login for demo purposes
        if username == "admin" and password == "secret":
            return JsonResponse({"status": "success", "message": "Logged in"})
        else:
            return JsonResponse({"status": "error", "message": "Invalid credentials"}, status=401)

    return JsonResponse({"message": "Send POST request with username/password"})
