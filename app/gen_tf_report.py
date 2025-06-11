#!/usr/bin/env python3

import argparse
from datetime import datetime, timezone
import json
import os
import sys
from utils import getRealms, getEnvironments, getWorkspaces, getVarFiles
from sherpa.utils.basics import Logger
from sherpa.utils import terraform


def parse_plan(logger, json_plan):
	with open(json_plan, 'r') as f:
		json_plan_content = f.read()
	json_plan_data = json.loads(json_plan_content)
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


def store_parsed_plan(logger, environment, realm, workspace, parsed_changes, output_file_path):
	logger.info("Storing parsed plan for {}/{}/{} into: {}", environment, realm, workspace, output_file_path)
	current_data = {}
	if os.path.exists(output_file_path):
		try:
			with open(output_file_path, 'r') as f:
				current_data = json.load(f)
			if not isinstance(current_data, dict):
				logger.warn("Existing content in {} is not a dictionary. Initializing fresh data structure.".format(output_file_path))
				current_data = {}
		except json.JSONDecodeError:
			logger.warn("Could not decode existing JSON from {}. Initializing fresh data structure.".format(output_file_path))
			current_data = {} # Start fresh if file is corrupted
		except Exception as e: # Catch other potential I/O errors
			logger.error("Error reading {}: {}. Initializing fresh data structure.".format(output_file_path, e))
			current_data = {}

	# Ensure the top-level structure has 'metadata' and 'diff' keys
	if "metadata" not in current_data:
		current_data["metadata"] = {}
	if "diff" not in current_data or not isinstance(current_data["diff"], dict):
		current_data["diff"] = {}

	# Ensure the realm key exists under 'diff' and is a dictionary, then set the workspace data
	current_data["diff"].setdefault(realm, {})[workspace] = parsed_changes

	try:
		with open(output_file_path, 'w') as f:
			json.dump(current_data, f, indent=4)
		logger.info("Successfully updated {} for realm '{}', workspace '{}'".format(output_file_path, realm, workspace))
	except Exception as e:
		logger.error("Failed to write updated data to {}: {}".format(output_file_path, e))


def initialize_output_file(logger, output_file_path):
	now_local = datetime.now().astimezone()
	timestamp_str = now_local.strftime("%Y-%m-%dT%H:%M:%S%z")
	metadata = { "timestamp": timestamp_str }
	output_content = { "metadata": metadata }
	with open(output_file_path, 'w') as f:
		json.dump(output_content, f, indent=4)
	logger.info("Initialized output file: {}".format(output_file_path))


def process_workspace(logger, environment, realm, realm_folder, workspace, workspace_folder, output_file_path, var_files):
	logger.debug("Processing workspace {} in {} for realm {} in {}.", workspace, workspace_folder, realm, realm_folder)
	if not os.path.exists(workspace_folder):
		logger.error("Workspace directory ({}) does not exist.", workspace_folder)
		return
	terraform.init(logger, realm_folder)
	terraform.select_workspace(logger, realm_folder, workspace)
	binary_plan = "{}/{}_tfplan.binary".format(realm_folder, workspace)
	terraform.plan2binary(logger, realm_folder, binary_plan, var_files)
	json_plan = "{}/{}_tfplan.json".format(realm_folder, workspace)
	terraform.show_binary2json(logger, realm_folder, binary_plan, json_plan)
	parsed_changes = parse_plan(logger, json_plan)
	store_parsed_plan(logger, environment, realm, workspace, parsed_changes, output_file_path)
	return parsed_changes


def process_realm(logger, environment, realm, realm_folder, output_file_path, var_files):
	logger.debug("Processing realm {} in {}.", realm, realm_folder)
	if not os.path.exists(realm_folder):
		logger.error("{} directory does not exist.", realm_folder)
		return
	process_output = []
	for workspace in getWorkspaces(logger, realm, environment):
		workspace_folder = "{}/terraform.tfstate.d/{}".format(realm_folder, workspace)
		output = process_workspace(logger, environment, realm, realm_folder, workspace, workspace_folder, output_file_path, var_files)
		process_output.append(output)
	return process_output


def run(logger, objects_path, output_path, environment):
	logger.info("Checking Terraform plans for environment: {}", environment)
	output_file_path = "{}/terraform_check_{}.json".format(output_path, environment)
	initialize_output_file(logger, output_file_path)
	var_files = getVarFiles(logger, environment)
	process_output = []
	for realm in getRealms(logger):
		realm_folder = "{}/{}".format(objects_path, realm)
		output = process_realm(logger, environment, realm, realm_folder, output_file_path, var_files)
		process_output.append(output)
	return process_output


def main(arguments):
	logger = Logger(os.path.basename(__file__), os.environ.get("LOG_LEVEL"), "/tmp/terraform_check.log")
	environments = getEnvironments(logger)
	parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
	parser.add_argument('environment', type=str.lower, help="Enter environment ({}).".format(", ".join(environments)))
	parser.add_argument('objects_path', type=str, help="Path to terraform objects.")
	parser.add_argument('output_path', type=str, help="Path to terraform_check_*.json files.")
	args = parser.parse_args(arguments)
	run(logger, args.objects_path, args.output_path, args.environment)
	logger.info("{} finished.".format(os.path.basename(__file__)))


if __name__ == "__main__":
	sys.exit(main(sys.argv[1:]))