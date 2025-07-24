#!/usr/bin/env python3

import argparse
import json
import os
import sys
from sherpa.utils.basics import Logger
from sherpa.utils import terraform
import utils



def parsePlan(logger: Logger, jsonPlan: str) -> list:
	"""Receives a Terraform Plan JSON and returns it as a formatted list of changes

	Args:
		logger (Logger): Logger instance
		jsonPlan (str): Path to JSON file containing the plan.

	Returns:
		list: Formatted list of planned changes
	"""
	with open(jsonPlan, 'r') as f:
		jsonPlanContent = f.read()
	json_plan_data = json.loads(jsonPlanContent)
	changes = []
	if "resource_changes" not in json_plan_data:
		return changes
	for resource_change in json_plan_data["resource_changes"]:
		actions = resource_change.get("change", {}).get("actions", [])
		if actions == ["no-op"]:
			continue
		change_detail = {
			"address": resource_change.get("address"),
			"type": resource_change.get("type"),
			"name": resource_change.get("name"),
			"actions": actions,
			"before": resource_change.get("change", {}).get("before"),
			"after": resource_change.get("change", {}).get("after"),
			"after_unknown": resource_change.get("change", {}).get("after_unknown")
		}
		# For updates, try to create a simple diff for changed values
		if "update" in actions:
			diff = {}
			before_vals = change_detail["before"] or {}
			after_vals = change_detail["after"] or {}
			all_keys = set(before_vals.keys()) | set(after_vals.keys())
			for key in all_keys:
				b = before_vals.get(key)
				a = after_vals.get(key)
				if b != a:
					diff[key] = {"before": b, "after": a}
			change_detail["computed_diff"] = diff
		changes.append(change_detail)
	return changes


def storeParsedPlan(logger: Logger, environment: str, realmName: str, parsedChanges: list, outputFilePath: str):
	"""Saves a parsed list of planned changes (such as the one `gen_tf_report.parse_plan()` returns) to a JSON Plan file

	Args:
		logger (Logger): Logger instance
		environment (str): Environment in which the Plan command was run
		realmName (str): Realm name
		parsedChanges (list): Parsed list of planned changes
		outputFilePath (str): **File** Path in which to save the JSON Plan
	"""
	logger.info("Storing parsed plan for {}/{} into: {}", environment, realmName, outputFilePath)
	current_data = {}
	if os.path.exists(outputFilePath):
		try:
			with open(outputFilePath, 'r') as f:
				current_data = json.load(f)
			if not isinstance(current_data, dict):
				logger.warn("Existing content in {} is not a dictionary. Initializing fresh data structure.".format(outputFilePath))
				current_data = {}
		except json.JSONDecodeError:
			logger.warn("Could not decode existing JSON from {}. Initializing fresh data structure.".format(outputFilePath))
			current_data = {} # Start fresh if file is corrupted
		except Exception as e: # Catch other potential I/O errors
			logger.error("Error reading {}: {}. Initializing fresh data structure.".format(outputFilePath, e))
			current_data = {}

	# Ensure the top-level structure has 'metadata' and 'diff' keys
	if "metadata" not in current_data:
		current_data["metadata"] = {}
	if "diff" not in current_data or not isinstance(current_data["diff"], dict):
		current_data["diff"] = {}

	# Ensure the realm key exists under 'diff' and is a dictionary, then set the data
	current_data["diff"][realmName] = parsedChanges

	try:
		with open(outputFilePath, 'w') as f:
			json.dump(current_data, f, indent=4)
		logger.info("Successfully updated {} for realm '{}'".format(outputFilePath, realmName))
	except Exception as e:
		logger.error("Failed to write updated data to {}: {}".format(outputFilePath, e))


def initializeOutputFile(logger: Logger, outputFilePath: str):
	"""Sets up Plan JSON file with top-level structure (metadata object with timestamp attribute)

	Args:
		logger (Logger): Logger instance
		outputFilePath (str): **File** Path in which to save the JSON Plan
	"""
	metadata = { "timestamp": utils.getLocalDatetime() }
	output_content = { "metadata": metadata }
	with open(outputFilePath, 'w') as f:
		json.dump(output_content, f, indent=4)
	logger.info("Initialized output file: {}".format(outputFilePath))


def processWorkspace(logger: Logger, environment: str, realmType: str, realmFolder: str, workspace: str, workspaceFolder: str, outputFilePath: str, environmentVarFiles: str, config: dict) -> list:
	"""Runs `terraform plan` for a given workspace (in a given realm (in a given environment)) and outputs the parsed resulting Diff report.

	Args:
		logger (Logger): Logger instance
		environment (str): Environment for which the plan report should be made
		realmType (str): Realm type for which the plan report should be made
		realmFolder (str): Realm's directory path, needed for the terraform utility to know where to run commands
		workspace (str): Terraform Workspace to be processed
		workspaceFolder (str): Workspace's `terraform.tfstate.d` directory
		outputFilePath (str): **File** Path in which to save the JSON Plan
		environmentVarFiles (list): List of environment-specific `.tfvars` file paths (should be relative to `realmFolder`) to be supplied in `-var-file` flags
        config (dict): JSON configuration

	Returns:
		list: Parsed Diff Report
	"""
	logger.debug("Processing workspace {} in {} for realm {} in {}.", workspace, workspaceFolder, realmType, realmFolder)
	if not os.path.exists(workspaceFolder):
		logger.error("Workspace directory ({}) does not exist.", workspaceFolder)
		return
	terraform.init(logger, realmFolder)
	terraform.select_workspace(logger, realmFolder, workspace)
	binary_plan = "{}/{}_tfplan.binary".format(realmFolder, workspace)
	instance_var_files = utils.getConfig(logger=logger).get("realms").get(realmType).get(environment).get(workspace).get("var_files", [])
	var_files = environmentVarFiles + instance_var_files
	terraform.plan2binary(logger, realmFolder, binary_plan, var_files)
	jsonPlan = "{}/{}_tfplan.json".format(realmFolder, workspace)
	terraform.show_binary2json(logger, realmFolder, binary_plan, jsonPlan)
	parsedChanges = parsePlan(logger=logger, jsonPlan=jsonPlan)
	realmName = utils.getRealmName(logger=logger, realmType=realmType, environment=environment, workspace=workspace, config=config)
	storeParsedPlan(logger=logger, environment=environment, realmName=realmName, parsedChanges=parsedChanges, outputFilePath=outputFilePath)
	return parsedChanges


def processRealm(logger: Logger, environment: str, realmType: str, realmFolder: str, outputFilePath: str, environmentVarFiles: list, config: dict) -> list:
	"""Will run the Diff Report generation for each worskpace in a given Realm

	Args:
		logger (Logger): Logger instance
		environment (str): Environment in which to run the Report Generation
		realmType (str): Realm type in which to run the Report Generation
		realmFolder (str): Realm's directory path, needed for the terraform utility to know where to run commands
		outputFilePath (str): **File** Path in which to save the JSON Plan
		environmentVarFiles (list): List of environment-specific `.tfvars` file paths (should be relative to `realm_folder`) to be supplied in `-var-file` flags
		config (dict): JSON configuration

	Returns:
		list: Generated Diff Report
	"""
	logger.debug("Processing realm {} in {}.", realmType, realmFolder)
	if not os.path.exists(realmFolder):
		logger.error("{} directory does not exist.", realmFolder)
		return
	process_output = []
	for workspace in utils.getRealmWorkspaces(logger=logger, realmType=realmType, environment=environment, config=config):
		workspace_folder = "{}/terraform.tfstate.d/{}".format(realmFolder, workspace)
		output = processWorkspace(logger, environment, realmType, realmFolder, workspace, workspace_folder, outputFilePath, environmentVarFiles, config=config)
		process_output.append(output)
	return process_output


def run(logger: Logger, objectsPath: str, outputPath: str, environment: str, config: dict) -> list:
	"""Runs Diff Report Generation for a given Environment

	Args:
		logger (Logger): Logger instance
		objectsPath (str): 'Objects' Directory path, used to build `realm_folder` for `process_realm()` params
		outputPath (str): **Directory** Path in which to save the JSON Plan
		environment (str): Environment in which to run Diff Report Generation
		config (dict): JSON configuration

	Returns:
		list: Parsed Diff Report for the provided Environment
	"""
	logger.info("Checking Terraform plans for environment: {}", environment)
	outputFilePath = "{}/terraformcheck_{}.json".format(outputPath, environment)
	initializeOutputFile(logger, outputFilePath)
	environmentVarFiles = utils.getVarFiles(logger=logger, environment=environment, config=config)
	processOutput = []
	for realmType in utils.getRealmTypes(logger=logger, config=config):
		realmFolder = "{}/{}".format(objectsPath, realmType)
		output = processRealm(logger=logger, environment=environment, realmType=realmType, realmFolder=realmFolder, outputFilePath=outputFilePath, environmentVarFiles=environmentVarFiles, config=config)
		processOutput.append(output)
	return processOutput


def main(arguments):
	logger = Logger(os.path.basename(__file__), os.environ.get("LOG_LEVEL"), "/tmp/terraformcheck_report.log")
	parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
	parser.add_argument('objectsPath', type=str, help="Path to terraform objects.")
	parser.add_argument('outputPath', type=str, help="Path to terraformcheck_*.json files.")
	args = parser.parse_args(arguments)
	config = utils.getConfig(logger=logger)
	for environment in utils.getEnvironments(logger=logger, config=config):
		run(logger=logger, objectsPath=args.objectsPath, outputPath=args.outputPath, environment=environment, config=config)
	logger.info("{} finished.".format(os.path.basename(__file__)))


if __name__ == "__main__":
	sys.exit(main(sys.argv[1:]))