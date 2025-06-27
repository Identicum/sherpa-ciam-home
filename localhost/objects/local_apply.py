#!/usr/bin/env python3

import os
import sys
from sherpa.utils import os_cmd
from sherpa.utils import terraform
from sherpa.utils.basics import Logger

sys.path.insert(1, "/app/")
from utils import getRealmTypes, getWorkspaces, getData


def main(arguments):
	logger = Logger(os.path.basename(__file__), os.environ.get("LOG_LEVEL"), "/tmp/localhost_apply.log")
	environment = "local"
	objects_path = "/terraform-objects"
	env_var_files = ["../env/local.tfvars", "../env/local_secrets.tfvars"]
	for realm_type in getRealmTypes(logger):
		realm_folder = "{}/{}".format(objects_path, realm_type)
		logger.trace("Processing realm: {}, folder: {}", realm_type, realm_folder)
		terraform.init(logger, realm_folder)
		for workspace in getWorkspaces(logger, realm_type, environment):
			logger.trace("Processing workspace: {} for realm_type: {}", workspace, realm_type)
			terraform.delete_workspace_state(logger, realm_folder, workspace)
			terraform.create_workspace(logger, realm_folder, workspace)
			terraform.select_workspace(logger, realm_folder, workspace)
			instance_var_files = getData().get("realms").get(realm_type).get(environment).get(workspace).get("var_files", [])
			var_files = env_var_files + instance_var_files
			terraform.apply(logger, realm_folder, var_files)

	logger.info("{} finished.".format(os.path.basename(__file__)))


if __name__ == "__main__":
	sys.exit(main(sys.argv[1:]))