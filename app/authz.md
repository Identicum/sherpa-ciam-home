# Authorization

This application uses a role-based access control (RBAC) system built on top of OIDC authentication. Roles are read from the authenticated user's access token JWT and enforced at the blueprint level.

## How it works

### Role format

Roles follow the pattern `{environment}_{module}`, for example:

- `desa_deployments`
- `test_clientinfo`
- `prod_checkclients`

The `environment` component is dynamic and comes from the URL path parameter. The `module` component is defined per blueprint.

### Role claim

Roles are read from the access token JWT claim defined by the environment variable `OIDC_ROLES_CLAIM` (default: `sherpa_ciam_home_roles`).

```
OIDC_ROLES_CLAIM=sherpa_ciam_home_roles
```

The claim must contain a list of role strings:

```json
{
  "sherpa_ciam_home_roles": ["desa_deployments", "test_clientinfo"]
}
```

### Unrestricted environments

Environments listed in `UNRESTRICTED_ENVIRONMENTS` are exempt from role checks. Default is `local`.

```
UNRESTRICTED_ENVIRONMENTS=local,sandbox
```

---

## Request flow

```
Incoming request
      │
      ▼
check_session()  (app.before_request in main.py)
      ├─ No token         → unauthenticated, public routes still accessible
      ├─ Token valid      → continue
      └─ Token expired    → attempt refresh
                               ├─ Refresh OK   → continue
                               └─ Refresh fail → IdP logout + session.clear()

      ▼
@utils.require_oidc_login  (decorator on protected routes)
      ├─ No token  → redirect /login
      └─ Token OK  → continue

      ▼
Blueprint.before_request  (per blueprint, e.g. check_deployments_role)
      ├─ environment in UNRESTRICTED_ENVIRONMENTS  → allow
      ├─ utils.hasRole('{environment}_{module}')
      │     ├─ role present in token  → allow
      │     └─ role missing           → 403
```

---

## Adding authorization to a new blueprint

### 1. Add the `before_request` hook

In your blueprint file, add a `before_request` function that builds the role from the `environment` path parameter and the module name:

```python
from flask import Blueprint, request, render_template
import utils

my_feature_bp = Blueprint('my-feature', __name__)

@my_feature_bp.before_request
def check_my_feature_role():
    """Enforce role-based access for all my-feature routes."""
    environment = request.view_args.get('environment')
    if not environment or environment in utils.UNRESTRICTED_ENVIRONMENTS:
        return None
    if not utils.check_role(utils.build_role(environment, 'my-feature')):
        return render_template('403.html', utils=utils), 403
```

### 2. Protect routes with `@utils.require_oidc_login`

Add the authentication decorator to any route that requires a logged-in user:

```python
@my_feature_bp.route('/my-feature/<environment>', methods=['GET'])
@utils.require_oidc_login
def my_feature(environment: str):
    ...
```

---

## Reference

| Component | Location | Responsibility |
|---|---|---|
| `check_session()` | `main.py` | Token validation and silent renewal on every request |
| `make_require_oidc_login()` | `main.py` | Decorator that enforces authentication on a route |
| `make_check_role()` | `main.py` | Function assigned to `utils.check_role` for inline role checks |
| `build_role()` | `utils.py` | Builds `{environment}_{module}` role string |
| `UNRESTRICTED_ENVIRONMENTS` | `utils.py` | Set of environments exempt from role checks |
| `Blueprint.before_request` | each blueprint | Enforces role check for all routes in the blueprint |