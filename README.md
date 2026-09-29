# sherpa-ciam-home

## Homepage for sherpa-ciam projects

This Docker Image provides a web app meant to be used as a hub for Keycloak IDP projects

### Features

> Each feature is environment-specific - Meaning that, when accessing it, the resulting displayed data will vary according to whichever environment was selected on the dropdown-list.

#### URL List

Easy Access list of URLs in the project.

#### Client Warnings Dashboard

Displays a detailed list of clients currently sending warnings regarding a specific issue.

#### Clients Activity (WIP)

TBD

#### Client Info Dashboard

Displays a realm-specific list of clients. The user may then select a client to see a table showcasing it's information.

#### Terraform Check Diff Dashboard

Runs `terraform plan` to gather current diff info and displays it in a detailed table.

#### IDP Status

Public traffic-light page (`/status/<environment>`) with the health of the IDP of each environment:

- **Grafana alerts**: the alerting criteria live in Grafana. The page reads the state of the Grafana-managed alert rules (`/api/prometheus/grafana/api/v1/rules`) and shows one item per rule (worst first) with how many nodes are alerted (firing; pending alerts are not counted): green with no alerted nodes, yellow with alerted nodes, red from 50% of the nodes. The item name is the rule annotation `status_title` when present (e.g. a user friendly name in the site language), otherwise the rule title.
- **Automated functional tests**: summary of the latest tests execution, overall and by realm / product, with the same gradient: green with no failed tests, yellow with failed tests, red from 50% of failed tests.

Environments without Grafana only show tests results. Grafana is configured per environment in `home.json`:

```json
"prod": {
    "grafana_url": "http://grafana.example.com:3000",
    "grafana_token": "$env:PROD_GRAFANA_TOKEN"
}
```

- `grafana_token`: Grafana service account token (`Viewer` role is enough to read the alert rules).
