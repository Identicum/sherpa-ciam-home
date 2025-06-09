#!/usr/bin/env python3

import os
import sys
from sherpa.utils import os_cmd
from sherpa.utils import terraform
from sherpa.utils.basics import Logger


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
		terraform.init(logger, realm_folder)
		for workspace in get_workspaces(logger, environment, realm):
			terraform.delete_workspace_state(logger, realm_folder, workspace)
			terraform.create_workspace(logger, realm_folder, workspace)
			terraform.select_workspace(logger, realm_folder, workspace)
			terraform.apply(logger, realm_folder)

	logger.info("{} finished.".format(os.path.basename(__file__)))


if __name__ == "__main__":
	sys.exit(main(sys.argv[1:]))