#!/usr/bin/env python3

import os
from sherpa.utils import terraform
from sherpa.utils.basics import Logger
import sys

sys.path.insert(1, "/app/")
import utils


def main(arguments):
	logger = Logger(os.path.basename(__file__), os.environ.get("LOG_LEVEL"), "/tmp/localhost_apply.log")
	environment = "local"
	objectsPath = "/terraform-objects"
	environmentVarFiles = ["../env/local.tfvars", "../env/local_secrets.tfvars"]
	config = utils.getConfig(logger)
	for realmType in utils.getRealmTypes(logger=logger, config=config):
		realmFolder = "{}/{}".format(objectsPath, realmType)
		logger.trace("Processing realm: {}, folder: {}", realmType, realmFolder)
		terraform.init(logger, realmFolder)
		for workspace in utils.getRealmWorkspaces(logger=logger, realmType=realmType, environment=environment, config=config):
			logger.trace("Processing workspace: {} for realmType: {}", workspace, realmType)
			terraform.delete_workspace_state(logger=logger, objectsFolder=realmFolder, workspace=workspace)
			terraform.create_workspace(logger=logger, objectsFolder=realmFolder, workspace=workspace)
			terraform.select_workspace(logger=logger, objectsFolder=realmFolder, workspace=workspace)
			instanceVarFiles = utils.getConfig(logger=logger).get("realms").get(realmType).get(environment).get(workspace).get("var_files", [])
			varFiles = environmentVarFiles + instanceVarFiles
			terraform.apply(logger=logger, objectsFolder=realmFolder, varFiles=varFiles)

	logger.info("{} finished.".format(os.path.basename(__file__)))


if __name__ == "__main__":
	sys.exit(main(sys.argv[1:]))