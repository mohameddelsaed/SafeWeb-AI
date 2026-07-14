import contextvars

_current_organization = contextvars.ContextVar('current_organization', default=None)

def get_current_organization():
    """Returns the currently active organization from the context var."""
    return _current_organization.get()

class OrganizationMiddleware:
    """
    Middleware that extracts the X-Organization-ID header from the request
    and sets it in a context variable for the OrganizationManager to implicitly filter.
    """
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        request.organization = None
        if hasattr(request, 'user') and request.user.is_authenticated:
            org_id = request.headers.get('X-Organization-ID')
            if org_id:
                try:
                    from apps.accounts.models import OrganizationMembership
                    if OrganizationMembership.objects.filter(user=request.user, organization_id=org_id).exists():
                        from apps.accounts.models import Organization
                        org = Organization.objects.get(id=org_id)
                        _current_organization.set(org)
                        request.organization = org
                    else:
                        _current_organization.set(None)
                except Exception:
                    _current_organization.set(None)
            else:
                from apps.accounts.models import OrganizationMembership, Organization
                first_membership = OrganizationMembership.objects.filter(user=request.user).first()
                if first_membership:
                    _current_organization.set(first_membership.organization)
                    request.organization = first_membership.organization
                else:
                    org = request.user.current_organization
                    if not org:
                        org_name = f"{request.user.username or request.user.email}'s Organization"
                        org, _ = Organization.objects.get_or_create(
                            name=org_name,
                            defaults={'owner': request.user}
                        )
                        OrganizationMembership.objects.get_or_create(user=request.user, organization=org, defaults={'role': 'owner'})
                        request.user.current_organization = org
                        request.user.save(update_fields=['current_organization'])
                    _current_organization.set(org)
                    request.organization = org
        else:
            _current_organization.set(None)
            
        return self.get_response(request)
