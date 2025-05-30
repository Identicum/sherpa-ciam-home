import json
import os
from sherpa.utils.basics import Properties
from sherpa.utils.basics import Logger
from sherpa.keycloak.keycloak_lib import SherpaKeycloakAdmin

logger = Logger(os.path.basename(__file__), "DEBUG", "/tmp/python-flask.log")
properties = Properties("/local.properties", "/local.properties")

def get_data():
    try:
        with open('/data/data.json', 'r') as f:
            return json.load(f)
    except FileNotFoundError:
        # ToDo: Handle cases where the file does not exist
        return {}
    except json.JSONDecodeError:
        # ToDo: Handle cases where JSON is invalid
        return {}

def getRealms():
    data = get_data()
    return list(data.get("realms", {}).keys())

def getEnvironments():
    data = get_data()
    return list(data.get("environments", {}).keys())

# def getKeycloakUrl(env):
#     data = get_data()
#     return data.get("environments", {}).get(env, {}).get("keycloak_url", "")

def getKeycloakAdmin(env, realm):
    data = get_data()
    kc_admin = SherpaKeycloakAdmin(
            logger=logger, 
            local_properties=properties, 
            server_url=data.get("environments", {}).get(env, {}).get("keycloak_url", ""), 
            client_id=data.get("environments", {}).get(env, {}).get("client_id", ""), 
            client_secret_key=data.get("environments", {}).get(env, {}).get("client_secret", ""), 
            realm_name=realm, 
            verify=False
        )
    return kc_admin

def getClients(env, realm):
    kc_admin = getKeycloakAdmin(env, realm)
    if not kc_admin:
        return []
    try:
        clients = kc_admin.get_clients()
        return clients
    except Exception as e:
        logger.error("Error fetching clients for {}/{}: {}", env, realm, e)
        return []

def getClient(env, realm, client_id):
    kc_admin = getKeycloakAdmin(env, realm)
    if not kc_admin:
        return []
    try:
        client_keycloak_id = kc_admin.get_client_id(client_id)
        client = kc_admin.get_client(client_keycloak_id)
        return client
    except Exception as e:
        logger.error("Error fetching client for {}/{}/{}: {}", env, realm, client_id, e)
        return []