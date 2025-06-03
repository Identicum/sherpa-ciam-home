from flask import Blueprint, render_template
from utils import *

checkclients_bp = Blueprint('checkclients', __name__)

@checkclients_bp.route('/checkclients/<env>', methods=["GET"])
def checkclientsEnv(env):
    warns = getEnvWarns(env)
    logger.trace("checkclients({}). warns: {}", env, warns)
    return render_template('checkclients.html', realms=getRealms(), environments=getEnvironments(), env=env, warns=warns, realmName="All Realms")

@checkclients_bp.route('/checkclients/<env>/<realmName>', methods=["GET"])
def checkclientsEnvRealm(env, realmName):
    warns = getRealmWarns(env, realmName)
    logger.trace("checkclients({}). warns: {}", env, warns)
    return render_template('checkclients.html', realms=getRealms(), environments=getEnvironments(), env=env, warns=warns, realmName=realmName)


def getEnvWarns(env):
    envWarns = []
    for realmName in getRealms():
        realmWarns = getRealmWarns(env, realmName)
        for realmWarn in realmWarns:
            envWarns.append(realmWarn)
    return envWarns


def getRealmWarns(env, realmName):
    realmWarns = []
    for client in getClients(env, realmName):
        normalized_client = getClient(env, realmName, client["clientId"])
        clientWarns = getClientWarns(normalized_client)
        for clientWarn in clientWarns:
            realmWarns.append(clientWarn)
    logger.trace("getRealmWarns({}, {}). response: {}", env, realmName, realmWarns)
    return realmWarns


def getClientWarns(client):
    logger.trace("getWarns(). client: {}", client)
    clientWarns = []
    client_id = client["client_id"]
    tag = client["tag"]
    name = client["name"]
    description = client["description"]
    realmName = client["realm_name"]
    match client["tag"]:
        case "[KEYCLOAK_NATIVE]":
            logger.debug("Native client, do nothing.")
        case "[TAG_MISSING]":
            clientWarns.append(dict(realmName=realmName, client_id=client_id, tag=tag, name=name, description=description, issue_level="WARN", issue_description="Client has no tag."))
        case "[TAG_INVALID]":
            clientWarns.append(dict(realmName=realmName, client_id=client_id, tag=tag, name=name, description=description, issue_level="WARN", issue_description="Client tag is invalid:" + tag))
        case _:
            if client.get("email_owner") == "":
                clientWarns.append(dict(realmName=realmName, client_id=client_id, tag=tag, name=name, description=description, issue_level="WARN", issue_description="Client does not have an owner email."))
    logger.trace("getClientWarns({}). response: {}", client, clientWarns)
    return clientWarns
