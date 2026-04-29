# Test Cases - Sherpa CIAM Home

| ID | Use Case | Steps (high level) | Expected Result |
|---|---|---|---|
| HOME-01 | Initial home load | Open `/` without active session | Home renders with basic menu and Login button |
| HOME-02 | Home with authenticated session | Login and return to `/` | User info and protected menus are visible |
| HOME-03 | Main menu navigation | Open each header option | Each option routes to the correct view |
| HOME-04 | Environment submenu | Expand environment-based menus | Configured environments are listed |
| HOME-05 | Realm submenu | Open Client Info/User Sessions/Change Email | Correct realms are listed per environment |
| HOME-06 | Expired session UX | Simulate session expiration and navigate | Session is cleaned and login is requested (no 500) |
| SEC-01 | Protected route without login | Open a protected route directly | Redirects to login |
| SEC-02 | Restricted route with insufficient role | Open restricted route | Returns `403` |
| LNK-01 | Links by environment | Open `/links/<env>` | Links are visible and valid |
| CI-01 | Client list | Open `/clientinfo/<env>/<realm>` | List/table loads correctly |
| CI-02 | Client detail | Open one client | Details are consistent, no unexpected empty fields |
| CC-01 | Client creation success | Submit valid form | Success confirmation is shown |
| CC-02 | Client creation validation | Submit invalid/missing inputs | Validation is displayed, no 500 |
| CHK-01 | Check Clients execution | Run check for one environment | Result is rendered with data |
| ACT-01 | Clients Activity | Open activity module | View loads and data is coherent |
| TF-01 | Terraform Check page | Open `/terraformcheck/<env>` | View is available and actionable |
| TF-02 | Terraform Check execution | Run check | Diff/results shown without errors |
| TST-01 | Test runs listing | Open `/tests/<env>` | Run history + run action are visible |
| TST-02 | Trigger automated test run | Execute available option | New run is created and listed |
| TST-03 | Test run detail | Open `/tests/<env>/report/<timestamp>` | Tests, statuses, and metadata are visible |
| TST-04 | Failure evidence | Open failed run | Failure screenshots are accessible |
| TST-05 | Report download | Download run JSON report | File downloads with valid structure |
| TST-06 | Prometheus metrics | Open `/tests/<env>/metrics` | Metrics are valid (passed/failed/total/duration) |
| DEP-01 | Deployments by environment | Open `/deployments/<env>` | Expected artifacts are listed |
| DEP-02 | Deployment detail | Open one artifact | Report is visible and status is consistent |
| SES-01 | User sessions list | Open `/user-sessions/<env>/<realm>` | Sessions are listed |
| SES-02 | User session action | Execute available session action | Coherent result is returned |
| CHM-01 | Change Email success | Execute email change | Operation succeeds and feedback is shown |
| CHM-02 | Change Email validation | Trigger invalid input/business error | Proper validation/business message is shown |
| ERR-01 | Non-existing route | Open invalid URL | Error handling is correct |
| LOG-01 | Full logout | Logout from user menu | Local session + IdP logout complete, back to home |
