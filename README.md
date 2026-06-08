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

### Environment variables

| `FEATURE_FLAG_LAST_LOGIN_TIME` | When set to `true`, enables client inactivity checks in Check Clients (`checkClientInactivity`) and prioritizes the Keycloak attribute `last.login.time` in Clients Activity. When `false` or unset, behavior matches the pre-CLR-845 default (no inactivity WARN, Elastic-only activity). |
