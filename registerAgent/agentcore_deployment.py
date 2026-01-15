from dotenv import load_dotenv

# Load environment variables from .env file FIRST
# This ensures os.environ is populated before any AWS/Auth0 setup.
load_dotenv()

import os
import time

from auth0.authentication import GetToken
from dotenv import load_dotenv

# Load environment variables from .env file FIRST
load_dotenv()

# Ensure AWS credentials are set in environment
# Abort early if required credentials are missing to avoid partial configuration.
if not os.getenv('AWS_ACCESS_KEY_ID') or not os.getenv('AWS_SECRET_ACCESS_KEY'):
    raise ValueError("AWS credentials not found. Please set AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY in your .env file")

# Now import after credentials are set
# These imports depend on AWS credentials being present.
from bedrock_agentcore_starter_toolkit import Runtime
import traceback
from boto3.session import Session

# Create boto3 session
# Let boto3 discover the region via environment or default to us-east-1.
boto_session = Session()
region = boto_session.region_name or os.getenv('AWS_DEFAULT_REGION', 'us-east-1')

# Instantiate the AgentCore runtime helper used to configure and launch deployments.
agentcore_runtime = Runtime()
agent_name = "agentcore_agent_a4aa"

# Configure the AgentCore deployment for the agentcore_agent entrypoint.
response = agentcore_runtime.configure(
    entrypoint="agentcore_agent.py",
    auto_create_execution_role=True,
    auto_create_ecr=True,
    requirements_file="requirements.txt",
    region=region,
    agent_name=agent_name,
    authorizer_configuration={
        "customJWTAuthorizer": {
            "discoveryUrl": f"https://{os.getenv("AUTH0_DOMAIN")}/.well-known/openid-configuration",
            "allowedClients": [os.getenv("AUTH0_CLIENT_ID")],
            "allowedAudience": [os.getenv("AUTH0_AUDIENCE")]
        }
    }
)

try:
    # Trigger the deployment for the agentcore_agent configuration.
    launch_result = agentcore_runtime.launch()
except Exception as e:
    print('Error launching AgentCore runtime:', repr(e))
    print('Traceback:')
    traceback.print_exc()
    raise


# Ensure AWS credentials are set in environment
if not os.getenv('AWS_ACCESS_KEY_ID') or not os.getenv('AWS_SECRET_ACCESS_KEY'):
    raise ValueError("AWS credentials not found. Please set AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY in your .env file")

# Now import after credentials are set
# Repeat the imports to keep this section self-contained.
from bedrock_agentcore_starter_toolkit import Runtime
import traceback
from boto3.session import Session

# Create boto3 session
# This session instance drives the second runtime configuration.
boto_session = Session()
region = boto_session.region_name or os.getenv('AWS_DEFAULT_REGION', 'us-east-1')

# Instantiate another runtime helper for the second agent configuration.
agentcore_runtime = Runtime()
 
agent_name = "agentcore_agent_a4aa"

# Configure the AgentCore deployment for the identity-enabled strands agent.
response = agentcore_runtime.configure(
    entrypoint="agentcore_agent.py",
    auto_create_execution_role=True,
    auto_create_ecr=True,
    requirements_file="requirements.txt",
    region=region,
    agent_name=agent_name,
    authorizer_configuration={
        "customJWTAuthorizer": {
            "discoveryUrl": f"https://{os.getenv("AUTH0_DOMAIN")}/.well-known/openid-configuration",
            "allowedClients": [os.getenv("AUTH0_CLIENT_ID")],
            "allowedAudience": [os.getenv("AUTH0_AUDIENCE")]
        },

    }
)
 
try:
    # Launch the identity-enabled agent deployment.
    launch_result = agentcore_runtime.launch()
except Exception as e:
    print('Error launching AgentCore runtime:', repr(e))
    print('Traceback:')
    traceback.print_exc()
    raise
