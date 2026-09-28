import json
import os
import re
import requests
from sherpa.utils.basics import Logger
import utils


STATUS_OK = "ok"
STATUS_WARN = "warn"
STATUS_CRIT = "crit"
STATUS_UNKNOWN = "unknown"
STATUS_SEVERITY = {STATUS_OK: 0, STATUS_UNKNOWN: 1, STATUS_WARN: 2, STATUS_CRIT: 3}

# Alerting criteria live in Grafana: this page only reads the state of the Grafana-managed alert rules and shows,
# for each rule, how many nodes are alerted (firing). Pending alerts are not counted.
NODE_LABEL = "node"
# Optional annotation of the alert rule with the name shown in the page (the rule title is used when missing).
# An annotation does not change the alertname, so notification policies and scripts matching it are not affected.
TITLE_ANNOTATION = "status_title"

# Same gradient for the alerted nodes of a rule and for the failed tests (overall, by realm and by product):
# ok when none, warning below CRIT_RATIO, critical from CRIT_RATIO
CRIT_RATIO = 0.5
# Test case fields (as returned by utils.parse_test_report) used to break down the tests results
TEST_DIMENSIONS = ["realm", "product"]

TEST_REPORTS_DIR = "/data/idp_testing_reports"
RUN_ID_PATTERN = re.compile(r"^[0-9]{8}_[0-9]{6}$")


def getEnvironmentConfig(environment: str, config: dict) -> dict:
    """Returns the configuration of an environment"""
    return config.get("environments", {}).get(environment, {})


def getGrafanaToken(environment: str, config: dict) -> str:
    """Returns the Grafana token of the environment, resolving "$env:VARIABLE" values like utils.getConfig() does for passwords"""
    token = getEnvironmentConfig(environment, config).get("grafana_token", "")
    if isinstance(token, str) and token.startswith("$env:"):
        return os.environ.get(token[5:], "")
    return token if isinstance(token, str) else ""


def isGrafanaConfigured(environment: str, config: dict) -> bool:
    """Returns whether Grafana is configured for the environment (grafana_url + grafana_token)"""
    grafana_url = getEnvironmentConfig(environment, config).get("grafana_url")
    return isinstance(grafana_url, str) and bool(grafana_url) and bool(getGrafanaToken(environment, config))


def getGrafanaAlertRules(logger: Logger, environment: str, config: dict) -> list:
    """Returns the Grafana-managed alert rules of the environment with the state of each instance (node)

    Args:
        logger (Logger): Logger instance
        environment (str): Environment name
        config (dict): JSON configuration

    Returns:
        list: Alert rules, as returned by Grafana's /api/prometheus/grafana/api/v1/rules
    """
    grafana_url = getEnvironmentConfig(environment, config)["grafana_url"].rstrip("/")
    headers = {"Authorization": "Bearer {}".format(getGrafanaToken(environment, config))}
    logger.debug("Getting Grafana alert rules from {} for environment {}", grafana_url, environment)
    response = requests.get("{}/api/prometheus/grafana/api/v1/rules".format(grafana_url), headers=headers, timeout=utils.DEFAULT_TIMEOUT)
    try:
        groups = response.json()["data"]["groups"]
    except (ValueError, KeyError, TypeError):
        groups = None
    if response.status_code != 200 or not isinstance(groups, list):
        raise Exception("Grafana returned HTTP {}: {}".format(response.status_code, response.text[:300]))
    rules = [rule for group in groups if isinstance(group, dict) for rule in group.get("rules") or [] if isinstance(rule, dict)]
    logger.trace("Grafana alert rules: {}", rules)
    return rules


def getInstanceState(state) -> str:
    """Normalizes the state of an alert instance: firing / pending / unknown (NoData, Error) / normal"""
    state = str(state or "").lower()
    if state.startswith("alerting") or state.startswith("firing") or state.startswith("recovering"):
        return "firing"
    if state.startswith("pending"):
        return "pending"
    if "nodata" in state or "error" in state:
        return "unknown"
    return "normal"


def getRatioStatus(affected: int, total: int) -> str:
    """Returns the status of a ratio (alerted nodes, failed tests): ok when none, warning below CRIT_RATIO, critical from it"""
    if total <= 0:
        return STATUS_UNKNOWN
    if affected <= 0:
        return STATUS_OK
    return STATUS_CRIT if affected / total >= CRIT_RATIO else STATUS_WARN


def getAlerts(logger: Logger, rules: list) -> list:
    """Returns, for each Grafana alert rule, how many nodes are alerted

    Args:
        logger (Logger): Logger instance
        rules (list): Grafana alert rules

    Returns:
        list: [{"name": str, "nodes": int, "alerted": int, "status": str}], worst first
    """
    alerts = []
    for rule in rules:
        nodes = {}
        unknown = str(rule.get("health", "ok")).lower() != "ok"
        if unknown:
            logger.warn("Grafana alert rule '{}' health: {} {}", rule.get("name"), rule.get("health"), rule.get("lastError", ""))
        for instance in rule.get("alerts") or []:
            if not isinstance(instance, dict):
                continue
            node = (instance.get("labels") or {}).get(NODE_LABEL)
            state = getInstanceState(instance.get("state"))
            if state == "unknown":
                unknown = True
            if node is None and state != "firing":
                # NoData / Error instances have no node label: they only make the rule unknown
                continue
            node = node or "-"
            nodes[node] = nodes.get(node, False) or state == "firing"
        alerted = sum(1 for firing in nodes.values() if firing)
        status = getRatioStatus(alerted, len(nodes))
        if unknown and alerted == 0:
            status = STATUS_UNKNOWN
        name = (rule.get("annotations") or {}).get(TITLE_ANNOTATION) or rule.get("name") or rule.get("uid") or "-"
        alerts.append({"name": name, "nodes": len(nodes), "alerted": alerted, "status": status})
    alerts.sort(key=lambda a: (-STATUS_SEVERITY[a["status"]], -(a["alerted"] / a["nodes"] if a["nodes"] else 0), a["name"]))
    return alerts


def getAlertsStatus(logger: Logger, environment: str, config: dict) -> dict:
    """Returns the Grafana alerts section of the status"""
    grafana = {"configured": isGrafanaConfigured(environment, config), "error": False}
    alerts = []
    if not grafana["configured"]:
        logger.debug("Grafana not configured for environment {}", environment)
        return {"grafana": grafana, "alerts": alerts}
    try:
        alerts = getAlerts(logger=logger, rules=getGrafanaAlertRules(logger=logger, environment=environment, config=config))
    except Exception as e:
        logger.error("Error getting Grafana alerts for environment {}: {}", environment, e)
        grafana["error"] = True
    return {"grafana": grafana, "alerts": alerts}


def getLatestTestRunId(logger: Logger, environment: str) -> str:
    """Returns the id (directory name) of the latest tests execution with a report, without parsing the reports

    Args:
        logger (Logger): Logger instance
        environment (str): Environment name

    Returns:
        str: Latest tests execution id, or None
    """
    reports_dir = os.path.join(TEST_REPORTS_DIR, environment)
    if not os.path.isdir(reports_dir):
        logger.debug("Test reports path '{}' not found or not configured.", reports_dir)
        return None
    run_ids = [name for name in os.listdir(reports_dir) if RUN_ID_PATTERN.match(name) and os.path.isfile(os.path.join(reports_dir, name, "report.json"))]
    return max(run_ids) if run_ids else None


def getTestReport(environment: str, run_id: str) -> dict:
    """Returns the parsed report.json of a tests execution"""
    with open(os.path.join(TEST_REPORTS_DIR, environment, run_id, "report.json"), "r", encoding="utf-8") as report_file:
        return json.load(report_file)


def getTestReportSummary(report: dict) -> dict:
    """Returns the summary of a test report. Same counting as utils.getTestReports(): "error" outcomes count as failed."""
    attributes = report["data"][0].get("attributes", {})
    summary = attributes.get("summary", {})
    return {
        "exec_option": attributes.get("environment", {}).get("custom_test_env_name", "N/A"),
        "passed": int(summary.get("passed", 0)),
        "failed": int(summary.get("failed", 0)) + int(summary.get("error", 0)),
        "total": int(summary.get("num_tests", 0)),
    }


def getTestsByDimension(logger: Logger, environment: str, run_id: str, report: dict) -> dict:
    """Returns the failed / total tests of each value of the TEST_DIMENSIONS (realm, product), worst first

    Args:
        logger (Logger): Logger instance
        environment (str): Environment name
        run_id (str): Tests execution id
        report (dict): Parsed report.json

    Returns:
        dict: dimension -> [{"name": str, "failed": int, "total": int, "status": str}]
    """
    counts = {dimension: {} for dimension in TEST_DIMENSIONS}
    for case in utils.parse_test_report(logger, report, environment, run_id):
        failed = case.get("outcome") in ("failed", "error")
        for dimension in TEST_DIMENSIONS:
            value = counts[dimension].setdefault(case.get(dimension) or "-", {"failed": 0, "total": 0})
            value["total"] += 1
            value["failed"] += failed
    result = {}
    for dimension, values in counts.items():
        items = [{"name": name, **c, "status": getRatioStatus(c["failed"], c["total"])} for name, c in values.items()]
        items.sort(key=lambda i: (-STATUS_SEVERITY[i["status"]], -i["failed"] / i["total"], i["name"]))
        result[dimension] = items
    return result


def getTestsStatus(logger: Logger, environment: str) -> dict:
    """Returns the summary of the latest tests execution of the environment

    Args:
        logger (Logger): Logger instance
        environment (str): Environment name

    Returns:
        dict: {"status": str, "execution": str, "report_error": bool, "run": dict|None}
    """
    execution = utils.checkTestsScheduled(logger, environment=environment)
    run_id = getLatestTestRunId(logger=logger, environment=environment)
    if not run_id:
        return {"status": STATUS_UNKNOWN, "execution": execution, "report_error": False, "run": None}
    try:
        report = getTestReport(environment=environment, run_id=run_id)
        summary = getTestReportSummary(report)
    except Exception as e:
        logger.error("Could not read test report {}/{}: {}", environment, run_id, e)
        return {"status": STATUS_UNKNOWN, "execution": execution, "report_error": True, "run": None}
    dimensions = {}
    dimensions_error = False
    try:
        dimensions = getTestsByDimension(logger=logger, environment=environment, run_id=run_id, report=report)
    except Exception as e:
        logger.error("Could not break down the tests of report {}/{}: {}", environment, run_id, e)
        dimensions_error = True
    return {
        "status": getRatioStatus(summary["failed"], summary["total"]),
        "execution": execution,
        "report_error": False,
        "run": {"run_id": run_id, "display": utils.getTimestampDisplay(run_id), **summary, "dimensions": dimensions, "dimensions_error": dimensions_error},
    }


def run(logger: Logger, environment: str, config: dict) -> dict:
    """Builds the status of an environment: Grafana alerts (when configured) + latest tests execution

    Args:
        logger (Logger): Logger instance
        environment (str): Environment name
        config (dict): JSON configuration

    Returns:
        dict: Status with alerts and tests
    """
    logger.info("Building status for environment: {}", environment)
    alerts = getAlertsStatus(logger=logger, environment=environment, config=config)
    tests = getTestsStatus(logger=logger, environment=environment)
    return {
        "environment": environment,
        "generated_at": utils.getLocalDatetime(),
        "grafana": alerts["grafana"],
        "alerts": alerts["alerts"],
        "tests": tests,
    }
