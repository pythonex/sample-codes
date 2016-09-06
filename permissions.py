from rest_framework.permissions import BasePermission


class IsUnauthenticated(BasePermission):
    """
    Allows access only to un-authenticated users.
    """

    def has_permission(self, request, view):
        return not request.user or not request.user.is_authenticated()


class IsPrivilegedUser(BasePermission):
    """
    Allows access only to administrators (RenooIT admins or VAR admins).
    """

    def has_permission(self, request, view):
        return request.user and (request.user.is_admin or
                                 request.user.is_var_admin)


class IsVarAdminUser(BasePermission):
    """
    Allows access only to VAR admins.
    """
    def has_permission(self, request, view):
        return request.user and request.user.is_var_admin
