from rest_framework.permissions import BasePermission

class IsAdmin(BasePermission):
    """
    Allows access only to users with role=1 (admin) or role=3 (member).
    """

    def has_permission(self, request, view):
        return bool(request.user and request.user.is_authenticated and request.user.role in [1])
