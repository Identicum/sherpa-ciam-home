#!/usr/bin/env python3

import argparse
import json
import os
import sys
from sherpa.utils.basics import Logger
import utils



def run(logger: Logger, outputPath: str, environment: str, data: dict) -> list:
	"""Runs Clients activity report generation

	Args:
		logger (Logger): Logger instance
		outputPath (str): **Directory** Path in which to save the JSON output
		environment (str): Environment in which to run Diff Report Generation
        data (dict): JSON configuration

	Returns:
		str: Process output
	"""
	logger.info("Getting Clients activity for environment: {}", environment)
	output_file_path = "{}/clientsactivity_{}.json".format(outputPath, environment)
	metadata = { "timestamp": utils.getLocalDatetime() }
	output_content = { "metadata": metadata, "activity": {} }
	for realmName in utils.getRealms(logger=logger, environment=environment, data=data):
		logger.debug("Getting Clients activity for realm: {}", realmName)
		realm_activity = []
		elastic = utils.getElastic(logger=logger, environment=environment, data=data)
		if not elastic:
			last_activity = "No Elastic configuration"
		for client in utils.getClients(logger=logger, environment=environment, realmName=realmName, data=data):
			if elastic:
				last_activity = utils.getClientLastActivity(logger=logger, elastic=elastic, realmName=realmName, client_id=client["clientId"])
			client_activity = {
				"client_id": client["clientId"],
                "name": client.get("name", ""),
                "enabled": client["enabled"],
                "last_activity": last_activity
            }
			realm_activity.append(client_activity)
		output_content["activity"][realmName] = realm_activity
	logger.info("Storing activity into: {}", output_file_path)
	with open(output_file_path, 'w') as f:
		json.dump(output_content, f, indent=4)
	return ""


def main(arguments):
	logger = Logger(os.path.basename(__file__), os.environ.get("LOG_LEVEL"), "/tmp/clientsactivity_report.log")
	parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
	parser.add_argument('outputPath', type=str, help="Path to clientsactivity_*.json files.")
	args = parser.parse_args(arguments)
	data = utils.getData(logger=logger)
	for environment in utils.getEnvironments(logger=logger, data=data):
		run(logger=logger, outputPath=args.outputPath, environment=environment, data=data)
	logger.info("{} finished.".format(os.path.basename(__file__)))


if __name__ == "__main__":
	sys.exit(main(sys.argv[1:]))