#!/usr/bin/env python3

import argparse
import json
import os
import sys
from sherpa.utils.basics import Logger
import utils



def run(logger: Logger, output_path: str, environment: str) -> list:
	"""Runs Clients activity report generation

	Args:
		logger (Logger): Logger instance
		output_path (str): **Directory** Path in which to save the JSON output
		environment (str): Environment in which to run Diff Report Generation

	Returns:
		str: Process output
	"""
	logger.info("Getting Clients activity for environment: {}", environment)
	output_file_path = "{}/clientsactivity_{}.json".format(output_path, environment)
	metadata = { "timestamp": utils.getLocalDatetime() }
	output_content = { "metadata": metadata, "activity": {} }
	for realmName in utils.getRealms(logger, environment):
		logger.debug("Getting Clients activity for realm: {}", realmName)
		realm_activity = []
		elastic = utils.getElastic(logger, environment)
		if not elastic:
			last_activity = "No Elastic configuration"
		for client in utils.getClients(environment, realmName):
			if elastic:
				last_activity = utils.getClientLastActivity(logger=logger, env=environment, elastic=elastic, realmName=realmName, client_id=client["clientId"])
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
	parser.add_argument('output_path', type=str, help="Path to clientsactivity_*.json files.")
	args = parser.parse_args(arguments)
	for environment in utils.getEnvironments(logger):
		run(logger, args.output_path, environment)
	logger.info("{} finished.".format(os.path.basename(__file__)))


if __name__ == "__main__":
	sys.exit(main(sys.argv[1:]))