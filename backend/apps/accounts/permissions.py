from rest_framework.permissions import BasePermission


class IsAdmin(BasePermission):
    """Allow access only to admin users."""

    def has_permission(self, request, view):
        return (
            request.user
            and request.user.is_authenticated
            and (request.user.role == 'admin' or request.user.is_superuser)
        )


class IsOwner(BasePermission):
    """Allow access only to the owner of the resource."""

    def has_object_permission(self, request, view, obj):
        if hasattr(obj, 'user'):
            return obj.user == request.user
        return obj == request.user


class IsOrganizationAdmin(BasePermission):
    """Allow access only if the user is an owner or admin of the active organization."""
    def has_permission(self, request, view):
        if not request.user or not request.user.is_authenticated:
            return False
        org = getattr(request, 'organization', None)
        if not org:
            org_id = request.headers.get('X-Organization-ID') or request.META.get('HTTP_X_ORGANIZATION_ID')
            from .models import OrganizationMembership
            if org_id:
                mem = OrganizationMembership.objects.filter(user=request.user, organization_id=org_id).first()
            else:
                mem = OrganizationMembership.objects.filter(user=request.user).first()
            if mem:
                org = mem.organization
                request.organization = org
        if not org:
            return False
        from .models import OrganizationMembership
        membership = OrganizationMembership.objects.filter(user=request.user, organization=org).first()
        return membership and membership.role in ['owner', 'admin']


class CanStartScan(BasePermission):
    """Allow access only if the user is not a viewer in the active organization."""
    def has_permission(self, request, view):
        if not request.user or not request.user.is_authenticated:
            return False
        org = getattr(request, 'organization', None)
        if not org:
            org_id = request.headers.get('X-Organization-ID') or request.META.get('HTTP_X_ORGANIZATION_ID')
            from .models import OrganizationMembership
            if org_id:
                mem = OrganizationMembership.objects.filter(user=request.user, organization_id=org_id).first()
            else:
                mem = OrganizationMembership.objects.filter(user=request.user).first()
            if mem:
                org = mem.organization
                request.organization = org
        if not org:
            return False
        from .models import OrganizationMembership
        membership = OrganizationMembership.objects.filter(user=request.user, organization=org).first()
        return membership and membership.role != 'viewer'

