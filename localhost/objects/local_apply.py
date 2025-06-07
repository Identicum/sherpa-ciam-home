#!/usr/bin/env python3

import os
import sys
from sherpa.utils import os_cmd
from sherpa.utils.basics import Logger
from terraform_utils import terraform_init, terraform_create_workspace, terraform_select_workspace, terraform_local_apply, terraform_local_delete_state


def get_realms(logger, environment):
	logger.trace("get_realms({})".format(environment))
	return ["customers", "employees", "master"]


def get_workspaces(logger, environment, realm):
	logger.trace("get_realms({}, {})".format(environment, realm))
	return ["local_default"]


def main(arguments):
	logger = Logger(os.path.basename(__file__), "DEBUG", "/tmp/localhost_apply.log")
	environment = "local"
	objects_path = "/usr/home/objects"
	for realm in get_realms(logger, environment):
		realm_folder = "{}/{}".format(objects_path, realm)
		terraform_init(logger, realm_folder)
		for workspace in get_workspaces(logger, environment, realm):
			terraform_local_delete_state(logger, realm_folder, workspace)
			terraform_create_workspace(logger, realm_folder, workspace)
			terraform_select_workspace(logger, realm_folder, workspace)
			terraform_local_apply(logger, realm_folder)

	logger.info("{} finished.".format(os.path.basename(__file__)))


if __name__ == "__main__":
	sys.exit(main(sys.argv[1:]))