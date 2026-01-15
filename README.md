# AgentCore Auth0 Web App

FastAPI application that authenticates users with Auth0, links downstream accounts, and invokes AWS Bedrock AgentCore for chat-style interactions. The main application lives in `app.py` and expects configuration via a `.env` copied from `env.template`.

## Features

- Auth0 login and logout flow handled by `app.py`
- Connect-account experience for retrieving federated provider tokens
- DynamoDB-backed session store for AgentCore invocations
- AgentCore runtime invocation via AWS Bedrock REST API
## Architecture Flow 


## Requirements

- Python 3.10+
- Auth0 tenant with Regular Web Application + Machine-to-Machine client
- AWS account with Bedrock AgentCore runtime deployed and DynamoDB table provisioned
- `.env` file based on `env.template`

## Setup

1. Install dependencies.
   ```bash
   python -m venv .venv
   source .venv/bin/activate
   pip install -r requirements.txt
   ```

2. Copy `env.template` and populate real values.
   ```bash
   cp env.template .env
   ```
   Update the placeholders:
   - `APP_SECRET_KEY` for FastAPI session middleware
   - `AUTH0_*` values from the Auth0 dashboard (client, secret, domain, scopes, callback URL)
   - `AGENT_RUNTIME_ARN` pointing to your Bedrock AgentCore runtime
   - `GATEWAY_URL` / `BEARER_TOKEN` if you use the fallback gateway utilities

3. Ensure AWS credentials (via environment or profile) grant access to DynamoDB and the AgentCore runtime.

## Running Locally

```bash
uvicorn app:app --host 0.0.0.0 --port 5000 --reload
```

Navigate to `http://127.0.0.1:5000` to start the Auth0 login. After authentication you will be redirected into the connect-account flow and then to the chat interface.

## Key Flows in `app.py`

- `/login` and `/auth/callback` bootstrap the Auth0 session and store the tokens in the FastAPI session.
- `/connect-account/start` and `/connect-account/callback` invoke Auth0’s account linking APIs, then persist federated tokens in DynamoDB via `store_session_data`.
- `/chat` renders the chat UI and, on POST, calls the Bedrock AgentCore runtime using the stored session data (`session_id`, `federated_token`, `access_token`) to build the payload.
- `/api/token-vault` exposes the stored tokens for debugging and refreshes the DynamoDB copy when needed.

## Environment Template Reference

`env.template` documents the minimum variables required to run the app. Copy it to `.env` and replace every placeholder:

```env
# Flask Configuration (used here by FastAPI session middleware)
APP_SECRET_KEY=your-super-secret-key-here

# Auth0 configuration
AUTH0_CLIENT_ID=your-auth0-client-id
AUTH0_CLIENT_SECRET=your-auth0-client-secret
AUTH0_DOMAIN=your-domain.auth0.com
AUTH0_CALLBACK_URL=http://127.0.0.1:5000/callback
AUTH0_AUDIENCE=your-api-identifier
AUTH0_SCOPE=invoke:gateway read:gateway

# AgentCore configuration
AWS_REGION=us-east-1
AGENT_RUNTIME_ARN=arn:aws:bedrock:us-east-1:123456789012:agent-runtime/ABCDEFGHIJ

# Optional gateway overrides
GATEWAY_URL=https://your-bedrock-gateway-url.us-east-1.amazonaws.com/mcp
BEARER_TOKEN=your-fallback-bearer-token
```

## Helpful Tips

- The app relies on DynamoDB table name supplied through `SESSION_TABLE_NAME` in the `.env`. Create the table before running locally.
- If `app.py` throws Auth0 or Bedrock errors, enable verbose logging by setting `LOGLEVEL=DEBUG` in `.env`.
- You can test individual endpoints using `uvicorn` with `--reload` to auto-restart on code changes.