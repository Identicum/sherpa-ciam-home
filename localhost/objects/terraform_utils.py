#!/usr/bin/env python3

import os
from sherpa.utils import os_cmd
from sherpa.utils.basics import Logger


def terraform_init(logger, realm_folder):
	if not os.path.exists(realm_folder):
		logger.error("{} directory does not exist.", realm_folder)
		return
	cmd = "cd {} && terraform init -upgrade -no-color > /dev/null".format(realm_folder)
	logger.debug("Executing '{}'", cmd)
	os_cmd.execute_in_bash(cmd, logger)
	# ToDo: check if terraform init was successful


def terraform_select_workspace(logger, realm_folder, workspace):
	cmd = "cd {} && terraform workspace select {}".format(realm_folder, workspace)
	logger.debug("Executing '{}'", cmd)
	os_cmd.execute_in_bash(cmd, logger)
	# ToDo: check if terraform select was successful


def terraform_create_workspace(logger, realm_folder, workspace):
	if not os.path.exists("{}/terraform.tfstate.d/{}".format(realm_folder, workspace)):
		cmd = "cd {} && terraform workspace new {}".format(realm_folder, workspace)
		logger.debug("Executing '{}'", cmd)
		os_cmd.execute_in_bash(cmd, logger)
		# ToDo: check if terraform create was successful
	else:
		logger.debug("Workspace '{}' already exists in '{}'", workspace, realm_folder)


def terraform_local_apply(logger, realm_folder):
	cmd = "cd {} && terraform apply --auto-approve".format(realm_folder)
	logger.debug("Executing '{}'", cmd)
	os_cmd.execute_in_bash(cmd, logger)
	# ToDo: check if terraform apply was successful


def terraform_local_delete_state(logger, realm_folder, workspace):
	logger.debug("Deleting terraform state (terraform destroy is never executed in local)")
	cmd = "rm -f {}/terraform.tfstate.d/{}/terraform.tfstate".format(realm_folder, workspace)
	logger.debug("Executing '{}'", cmd)
	os_cmd.execute_in_bash(cmd, logger)
	# ToDo: check if delete was successful


def terraform_binary_plan(logger, realm_folder, binary_plan):
	cmd = "cd {} && terraform plan -out={} -no-color > /dev/null".format(realm_folder, binary_plan)
	logger.debug("Executing '{}'", cmd)
	os_cmd.execute_in_bash(cmd, logger)
	# ToDo: check if terraform plan was successful


def terraform_show_binary2json(logger, realm_folder, binary_plan, json_plan):
	cmd = "cd {} && terraform show -json {} > {}".format(realm_folder, binary_plan, json_plan)
	logger.debug("Executing '{}'", cmd)
	os_cmd.execute_in_bash(cmd, logger)
	# ToDo: check if terraform show was successful