import json
import os
import time

import requests
import boto3
from dotenv import load_dotenv
from mcp.client.streamable_http import streamablehttp_client
from strands import Agent, tool
from strands.models import BedrockModel
from bedrock_agentcore import BedrockAgentCoreApp
import asyncio
from openfga_sdk.client import OpenFgaClient, ClientConfiguration
from openfga_sdk.client.models import ClientCheckRequest
from openfga_sdk.credentials import Credentials, CredentialConfiguration
from strands.tools.executors import SequentialToolExecutor
import logging

from strands.tools.mcp import MCPClient

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)



BASE_DIR = os.path.dirname(os.path.abspath(__file__))
load_dotenv(os.path.join(BASE_DIR, ".env"))

# --- Globals for session context ---
dynamodbSessionID = ""
email = ""
access_token=""
# -----------------------------------

app = BedrockAgentCoreApp()

# Secrets Manager bundle that keeps Auth0, FGA, and Okta settings out of source.
SECRETS_ARN = "arn:aws:secretsmanager:us-east-1:aaaaaaaaaaaa:secret:bbbbbbbbbbbb"

def load_managed_secrets():
    try:
        session = boto3.session.Session()
        sm = session.client("secretsmanager")
        secret_value = sm.get_secret_value(SecretId=SECRETS_ARN)
        payload = secret_value.get("SecretString")
        if not payload:
            return {}
        secrets = json.loads(payload)
        logger.info("Loaded secrets from %s", SECRETS_ARN)
        return secrets
    except Exception as e:
        logger.warning("Unable to load secrets from %s: %s", SECRETS_ARN, e)
        return {}

MANAGED_SECRETS = load_managed_secrets()

CIBA_AUTH0_DOMAIN = (
    MANAGED_SECRETS.get("AUTH0_DOMAIN_CIBA", "")
    .replace("https://", "")
    .replace("http://", "")
    .strip("/")
)
if not CIBA_AUTH0_DOMAIN:
    raise ValueError("AUTH0_DOMAIN_CIBA must be configured via Secrets Manager.")

CIBA_CLIENT_ID = MANAGED_SECRETS.get("CIBA_CLIENT_ID", "")
CIBA_CLIENT_SECRET = MANAGED_SECRETS.get("CIBA_CLIENT_SECRET", "")
CIBA_SCOPE = MANAGED_SECRETS.get("CIBA_SCOPE", "openid profile")
DEFAULT_BINDING_MESSAGE = MANAGED_SECRETS.get("CIBA_BINDING_MESSAGE", "RESET PASSWORD FLOW")
ciba_url = f"https://{CIBA_AUTH0_DOMAIN}/bc-authorize"
token_url = f"https://{CIBA_AUTH0_DOMAIN}/oauth/token"

FGA_API_ISSUER = MANAGED_SECRETS.get("FGA_API_ISSUER", "")
FGA_API_AUDIENCE = MANAGED_SECRETS.get("FGA_API_AUDIENCE", "")
FGA_CLIENT_ID = MANAGED_SECRETS.get("FGA_CLIENT_ID", "")
FGA_CLIENT_SECRET = MANAGED_SECRETS.get("FGA_CLIENT_SECRET", "")
FGA_API_SCHEME = MANAGED_SECRETS.get("FGA_API_SCHEME", "https")
FGA_API_HOST = MANAGED_SECRETS.get("FGA_API_HOST", "")
FGA_STORE_ID = MANAGED_SECRETS.get("FGA_STORE_ID", "")
FGA_AUTHORIZATION_MODEL_ID = MANAGED_SECRETS.get("FGA_AUTHORIZATION_MODEL_ID", "")
MCP_GATEWAY_URL= MANAGED_SECRETS.get("MCP_GATEWAY_URL")
OKTA_DOMAIN = MANAGED_SECRETS.get("OKTA_DOMAIN", "kapil.oktapreview.com")


logger.info("CIBA_CLIENT_ID: %s", CIBA_CLIENT_ID) 
# --- DynamoDB Helper ---
def get_dynamodb_table(region="us-east-1"):
    """Helper function to get the DynamoDB table resource."""
    table_name = "auth0_agentcore_agent" # Using table name directly
    if not table_name:
        raise ValueError("SESSION_TABLE_NAME not configured")
    dynamodb = boto3.resource("dynamodb", region_name=region)
    return dynamodb.Table(table_name)
# ----------------------

async def main(user_obj):
    """
    Perform FGA authorization check for the given user object.
    (This function appears unchanged from your original)
    """
    # Step 1: Set up client credentials for Auth0 authentication
    credentials = Credentials(
        method="client_credentials",
        configuration=CredentialConfiguration(
            api_issuer=FGA_API_ISSUER,
            api_audience=FGA_API_AUDIENCE,
            client_id=FGA_CLIENT_ID,
            client_secret=FGA_CLIENT_SECRET,
        )
    )

    configuration = ClientConfiguration(
        api_scheme=FGA_API_SCHEME,
        api_host=FGA_API_HOST,
        store_id=FGA_STORE_ID,
        authorization_model_id=FGA_AUTHORIZATION_MODEL_ID,
        credentials=credentials,
    )

    async with OpenFgaClient(configuration) as fga_client:
        # Step 03. Check for access
        options = {}
        body = ClientCheckRequest(
            user='user:' + user_obj['user'],  # e.g., "user:alice@example.com"
            relation=user_obj['relation'],    # e.g., "read"
            object=user_obj['object'],        # e.g., "document:123"
        )
        response = await fga_client.check(body, options)
        return response
        await fga_client.close()


os.environ["LANGSMITH_OTEL_ENABLED"] = "true"

@tool
def weather():
    """Get weather"""
    return "sunny"

# --- REFACTORED TOOL 1 ---

# --- CIBA Password Reset Tool ---

@tool
def invokeCiba(user_identifier: str = "", scope: str = "", binding_message: str = ""):
    """
    Initiate and complete a CIBA password-reset approval flow in one step.
    Provide an explicit user_identifier (Auth0 subject) if available; otherwise we will
    fall back to the email captured in the session payload.
    """
    logger.info("[Tool:invokeCiba] invoked")

    identifier = ""
    
    if not identifier:
        session_id = (dynamodbSessionID or "").strip()
        if not session_id:
            logger.error("Missing session id (dynamoID) and no user identifier provided")
            return json.dumps({"error": "Missing session id and user identifier"})
        table = get_dynamodb_table()
        resp = table.get_item(Key={"session_id": session_id})
        item = resp.get("Item")
        if not item:
            logger.error("No session found for id %s", session_id)
            return json.dumps({"error": f"No session found for id {session_id}"})
        identifier = item.get("user_id", "").strip()

    if not identifier:
        return json.dumps({"error": "No user identifier available for CIBA login_hint"})


    login_hint = {
        "format": "iss_sub",
        "iss": f"https://{CIBA_AUTH0_DOMAIN}/",
        "sub": identifier
    }

    payload = {
        "client_id": CIBA_CLIENT_ID,
        "client_secret": CIBA_CLIENT_SECRET,
        "login_hint": json.dumps(login_hint),
        "scope": "openid profile",
        "binding_message": "Please approve the password-reset request"
    }

    headers = {"Content-Type": "application/x-www-form-urlencoded"}

    try:
        response = requests.post(ciba_url, headers=headers, data=payload)
        try:
            auth_data = response.json()
        except json.JSONDecodeError:
            logger.error("Non-JSON response from CIBA initiation: %s", response.text)

        if response.status_code != 200:
            logger.error("Failed to initiate CIBA request: %s", auth_data)

        auth_req_id = auth_data.get('auth_req_id')
        expires_in = auth_data.get('expires_in', 300)
        interval = auth_data.get('interval', 5)
        logger.info("CIBA initiated. auth_req_id=%s expires_in=%s interval=%s", auth_req_id, expires_in, interval)

        def poll_for_token(token_url: str, auth_req_id: str, expires_in: int, interval: int):
            start_time = time.time()
            current_interval = interval
            while True:
                if time.time() - start_time > expires_in:
                    logger.warning("CIBA request timed out after %s seconds", expires_in)
                    return None

                token_payload = {
                    'grant_type': 'urn:openid:params:grant-type:ciba',
                    'auth_req_id': auth_req_id,
                    'client_id': CIBA_CLIENT_ID,
                    'client_secret': CIBA_CLIENT_SECRET

                }
                token_headers = {"Content-Type": "application/x-www-form-urlencoded"}

                try:
                    token_response = requests.post(token_url, data=token_payload, headers=token_headers)
                    if token_response.status_code == 200:
                        logger.info("CIBA token obtained successfully")
                        return token_response.json()

                    try:
                        error_response = token_response.json()
                    except json.JSONDecodeError:
                        error_response = {"error": token_response.text}

                    error_code = error_response.get('error')
                    if error_code == 'authorization_pending':
                        logger.info('Authorization pending; retrying in %s seconds', current_interval)
                        time.sleep(current_interval)
                        continue
                    if error_code == 'slow_down':
                        current_interval += 5
                        logger.info('Received slow_down; new interval=%s', current_interval)
                        time.sleep(current_interval)
                        continue

                    logger.error('CIBA token polling failed: %s', error_response)
                    return None

                except Exception as poll_exc:
                    logger.error('Error during CIBA token polling: %s', poll_exc)
                    return None

        tokens = poll_for_token(token_url, auth_req_id, expires_in, interval)
        if tokens:
            logger.info("CIBA flow completed for identifier=%s", identifier)
            return json.dumps({
                "status": "success",
                "message": "Identity verified and password has been sucessfully set"
            })
        logger.warning("CIBA flow failed or timed out for identifier=%s", identifier)
        return json.dumps({
            "status": "failed",
            "message": "Unable to verify identity. Please try again."
        })

    except Exception as e:
        logger.error("Exception in invokeCiba: %s", e)
        return json.dumps({"error": f"An internal error occurred: {str(e)}"})


@tool
def getOktaGroups():
    """
    Fetch Okta groups using federated token stored in DynamoDB for the current session.
    Steps:
    1) Read the session item from DynamoDB using the global session id.
    2) Extract the federated access token from the item (key: 'federated_token').
    3) Call the Okta Groups API with that bearer token.
    4) Return the group list as JSON (or a helpful error).
    """
    logger.info("Starting getOktaGroups flow. email=%s", email)
    try:
        user_for_check = {
            "user": email,
            "relation": "read_groups",
            "object": "okta:groups",
        }
        logger.info("Authorization check payload: %s", user_for_check)
        fga_response = asyncio.run(main(user_for_check))
        logger.info("FGA response: %s", fga_response)

        is_authorized = False
        if isinstance(fga_response, dict) and 'Payload' in fga_response:
            response_payload = fga_response['Payload'].read()
            decoded_response = json.loads(response_payload)
            is_authorized = decoded_response.get('isAuthorized') is True
        elif isinstance(fga_response, dict) and 'isAuthorized' in fga_response:
            is_authorized = fga_response.get('isAuthorized') is True
        elif hasattr(fga_response, 'allowed'):
            is_authorized = bool(getattr(fga_response, 'allowed'))

        if not is_authorized:

            return "User not authorized to perform this operation"
    except Exception as e:
        logger.error("error11111: %s", e)
        return json.dumps({"error": "authorization_check_failed", "detail": str(e)})

    session_id = (dynamodbSessionID or "").strip()
    if not session_id:
        return json.dumps({"error": "Missing session id (dynamoID)"})

    try:
        table = get_dynamodb_table()
        resp = table.get_item(Key={"session_id": session_id})
        item = resp.get("Item")
        if not item:
            return json.dumps({"error": f"No session found for id {session_id}"})

        federated_token = item.get("federated_token")
        if not federated_token:
            return json.dumps({"error": "No federated_token found in session item"})

        headers = {"Authorization": f"Bearer {federated_token}", "Accept": "application/json"}

        user_url = f'https://{OKTA_DOMAIN}/api/v1/users/{email}'

        user_response = requests.get(user_url, headers=headers)
        logger.info("User lookup status: %s", user_response.status_code)
        logger.info("User response: %s", user_response.text)
        if user_response.status_code != 200:
            logger.error("Error retrieving user: %s - %s", user_response.status_code, user_response.text)
            actiongroup_output = f"Error retrieving user: {user_response.status_code}"
        else:
            user = user_response.json()
            user_id = user['id']
            logger.info("User ID: %s", user_id)

            groups_response = requests.get(f'https://{OKTA_DOMAIN}/api/v1/users/{user_id}/groups', headers=headers)

            if groups_response.status_code != 200:
                logger.error("Error retrieving groups: %s - %s", groups_response.status_code, groups_response.text)
                actiongroup_output = f"Error retrieving groups: {groups_response.status_code}"
            else:
                groups = groups_response.json()
                return json.dumps({"okta_groups": groups})

        return json.dumps({"error": actiongroup_output})

    except Exception as e:
        logger.error("Unhandled error fetching Okta groups: %s", e)
        return json.dumps({"error": str(e)})


# --- Agent Definition ---
model_id = "us.anthropic.claude-3-7-sonnet-20250219-v1:0"
model = BedrockModel(
    model_id=model_id,
    streaming=False
)

# Provide a fresh MCP transport per request so auth headers stay current.
def create_transport():
    return streamablehttp_client(
        MCP_GATEWAY_URL,
        headers={"Authorization": f"Bearer {access_token}"}
)


@app.entrypoint
def strands_agent_bedrock(payload):
    """
    Invoke the agent with a payload
    """
    # INSERT_YOUR_CODE
  
    # Log payload fields and stash session identifiers for later tool usage.
    for k, v in payload.items():
        logger.info(f"  {k!r}: {v!r}")
    user_input = payload.get("prompt")
    # Propagate session id and email for tool access
    global dynamodbSessionID, email, access_token
    dynamodbSessionID = str(payload.get("dynamoID") or "")
    email = str(payload.get("email") or "")
    # INSERT_YOUR_CODE
    # Retrieve access_token from DynamoDB session record, if present
    access_token = str(payload.get("access_token") or "")
    try:
        table = get_dynamodb_table()
        resp = table.get_item(Key={"session_id": dynamodbSessionID})
        item = resp.get("Item")
        access_token = item.get("access_token")
    except Exception as e:
        logger.error("Error fetching access_token from DynamoDB: %s", e)

    try:
        with MCPClient(create_transport) as mcp_client:
            remote_tools = mcp_client.list_tools_sync()
            # Combine local tools with the freshly fetched remote tools
            # We update the agent's tool list for this specific request
            # NOTE: remote tool availability is dynamic per MCP session.
            agent = Agent(
                model=model,
                # *** UPDATED TOOL LIST ***
                tools=[weather, getOktaGroups, invokeCiba]+remote_tools,
                system_prompt=(
                    "You are a helpful assistant with specific tools. Follow these rules carefully:\n"
                    "1.  **For Okta groups:** When the user asks to get Okta groups (e.g., 'get me okta groups', 'what are my okta groups'), "
                    "you MUST call the `getOktaGroups` tool and return ONLY its result.\n"

                    "2.  **For Password Resets:** When a user asks to perform an elevated operation like resetting a password "
                    "(e.g., 'reset my password', 'I need to reset a password', 'reset okta password for <email>'), "
                    "you MUST call the `invokeCiba` tool, wait for it to complete, and return ONLY the tool's result.\n"

                    "3.  **You also have access to **dynamic remote tools**. If a user asks about 'employee tasks', 'assigned work', "
                    "or 'employee records', look through your available tools for a match and invoke it immediately.\n"

                    "4. **For other tasks:** You can also do simple math calculations and tell the weather."

                ),
                tool_executor=SequentialToolExecutor()
            )

            resp = agent(user_input)
            return resp.message['content'][0]['text']
    except Exception as e:
        logger.error("MCP Initialization failed: %s", e)
        # Fallback: try to answer with local tools if MCP fails
        resp = agent(user_input)
        return resp.message['content'][0]['text']


    resp = agent(user_input)
    return resp.message['content'][0]['text']

if __name__ == "__main__":
    app.run()