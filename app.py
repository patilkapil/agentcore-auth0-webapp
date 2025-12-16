import os
import json
import time
import urllib.parse
import uuid
import logging
import sys
import boto3
import requests
from functools import wraps
from flask import Flask, render_template, request, jsonify, redirect, url_for, session
from authlib.integrations.flask_client import OAuth
from dotenv import load_dotenv
from auth0.authentication import GetToken


# Load environment variables
load_dotenv()

# Initialize Flask app
app = Flask(__name__)
app.secret_key = os.getenv("APP_SECRET_KEY", "your-secret-key-here")
app.config['SESSION_COOKIE_SAMESITE'] = "Lax"

# Auth0 Configuration
AUTH0_CLIENT_ID = os.getenv("AUTH0_CLIENT_ID")
AUTH0_CLIENT_SECRET = os.getenv("AUTH0_CLIENT_SECRET")
AUTH0_DOMAIN = os.getenv("AUTH0_DOMAIN")
AUTH0_BASE_URL = f"https://{AUTH0_DOMAIN}"
AUTH0_CALLBACK_URL = os.getenv("AUTH0_CALLBACK_URL", "http://127.0.0.1:5000/callback")
AUTH0_AUDIENCE = os.getenv("AUTH0_AUDIENCE")
SESSION_TABLE_NAME=os.getenv("SESSION_TABLE_NAME")

dynamodb = boto3.resource(
    'dynamodb',
    region_name='us-east-1',
    aws_access_key_id=os.getenv("AWS_ACCESS_KEY_ID"),
    aws_secret_access_key=os.getenv("AWS_SECRET_ACCESS_KEY")
)

# Agent Core Configuration
AGENT_RUNTIME_ARN = os.getenv("AGENT_RUNTIME_ARN")

# Auth0 OAuth Configuration
oauth = OAuth(app)
auth0 = oauth.register(
    'auth0',
    client_id=AUTH0_CLIENT_ID,
    client_secret=AUTH0_CLIENT_SECRET,
    api_base_url=AUTH0_BASE_URL,
    access_token_url=f'{AUTH0_BASE_URL}/oauth/token',
    authorize_url=f'{AUTH0_BASE_URL}/authorize',
    client_kwargs={
        'scope': 'openid profile email offline_access okta.users.read',
    },
    server_metadata_url=f'https://{AUTH0_DOMAIN}/.well-known/openid-configuration'
)

def requires_auth(f):
    """
    Decorator to require authentication for protected routes.
    """
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'profile' not in session:
            return redirect('/login')
        return f(*args, **kwargs)
    return decorated

def get_bearer_token():
    """
    Get bearer token from Auth0 for machine-to-machine authentication
    """
    try:
        auth0_domain = AUTH0_DOMAIN
        client_id = AUTH0_CLIENT_ID
        client_secret = AUTH0_CLIENT_SECRET
        audience = AUTH0_AUDIENCE
        scope = os.getenv("AUTH0_SCOPE", "invoke:gateway read:gateway")

        if not all([auth0_domain, client_id, client_secret, audience]):
            raise ValueError("Missing required Auth0 environment variables")

        get_token = GetToken(auth0_domain, client_id, client_secret=client_secret)
        token_response = get_token.client_credentials(audience=audience)
        access_token = token_response.get("access_token")

        if not access_token:
            raise ValueError("No access token received from Auth0")

        return access_token

    except Exception as e:
        print(f"Error getting Auth0 token: {e}")
        # Fallback to environment variable if available
        fallback_token = os.getenv("BEARER_TOKEN")
        if fallback_token:
            return fallback_token
        raise

def get_tokenset():
    """
    Exchange refresh token for federated access token from token vault.
    Returns JSON object with token vault information.
    """
    if not session.get("refresh_token"):
        print("No refresh token available in session")
        return None

    url = f"https://{AUTH0_DOMAIN}/oauth/token"
    headers = {"content-type": "application/json"}
    payload = {
        "client_id": AUTH0_CLIENT_ID,
        "client_secret": AUTH0_CLIENT_SECRET,
        "grant_type": "urn:auth0:params:oauth:grant-type:token-exchange:federated-connection-access-token",
        "subject_token_type": "urn:ietf:params:oauth:token-type:refresh_token",
        "subject_token": session["refresh_token"],
        "connection": os.getenv("AUTH0_CONNECTION_NAME"),
        "audience": f"https://{AUTH0_DOMAIN}/api/v2/",
        "requested_token_type": "http://auth0.com/oauth/token-type/federated-connection-access-token",
        "scope": "okta.users.read okta.users.read.self"
    }
    for key, value in payload.items():
        print(f"{key}: {value}")



    try:
        response = requests.post(url, json=payload, headers=headers)
        response.raise_for_status()
        tokenset = response.json()
        return tokenset
    except requests.exceptions.RequestException as e:
        error_text = e.response.text if hasattr(e, 'response') else "No response"
        print("Error getting token vault:", e)
        return {"error": f"Token vault error: {error_text}"}

# DynamoDB helper functions
def store_session_data(session_id, refresh_token, federated_token, user_data):
    """
    Store session data in DynamoDB

    Args:
        session_id: Unique session identifier
        refresh_token: Auth0 refresh token
        federated_token: Federated access token
        user_data: User profile information
    """
    try:
        table = dynamodb.Table(SESSION_TABLE_NAME)

        # TTL: Session expires in 24 hours
        ttl = int(time.time()) + (24 * 60 * 60)

        table.put_item(
            Item={
                'session_id': session_id,
                'refresh_token': refresh_token,
                'federated_token': federated_token,
                'user_id': user_data.get('user_id'),
                'user_email': user_data.get('email'),
                'user_name': user_data.get('name'),
                'user_picture': user_data.get('picture'),
                'ttl': ttl,
                'created_at': int(time.time())
            }
        )
        print(f"Stored session data for session_id: {session_id}")

    except Exception as e:
        print(f"Error storing session data: {str(e)}")
        raise

def get_session_data(session_id):
    """
    Retrieve session data from DynamoDB

    Args:
        session_id: Session identifier

    Returns:
        Dict containing session data or None if not found
    """
    try:
        table = dynamodb.Table(SESSION_TABLE_NAME)
        response = table.get_item(Key={'session_id': session_id})
        item = response.get('Item')

        if item:
            # Remove TTL field from response
            item.pop('ttl', None)
            return item
        return None

    except Exception as e:
        print(f"Error retrieving session data for {session_id}: {str(e)}")
        return None

@app.route("/")
def index():
    """
    Home page - redirect to chat if authenticated, otherwise show login
    """
    if 'profile' in session:
        return redirect('/chat')
    else:
        return render_template("login.html")

@app.route("/login")
def login():
    """
    Initiate Auth0 login flow
    """
    session.clear()
    return auth0.authorize_redirect(
        redirect_uri=AUTH0_CALLBACK_URL,
        response_type='code'
    )

@app.route("/callback")
def callback():
    """
    Handle Auth0 callback after successful authentication
    """
    try:
        token = auth0.authorize_access_token()
        print('tokennnn')
        print(token)
        userinfo = auth0.get('userinfo').json()

        user_profile = {
            'user_id': userinfo['sub'],
            'name': userinfo['name'],
            'email': userinfo['email'],
            'picture': userinfo.get('picture', '')
        }
        session['profile'] = user_profile
        # Generate a unique session ID for DynamoDB storage
        session_id = str(uuid.uuid4())
        session['session_id'] = session_id

        # Store the tokens
        session['user'] = token
        if "refresh_token" in token:
            session["refresh_token"] = token["refresh_token"]
            print("Stored refresh token in session")
        else:
            print("No refresh token received")

        # Get federated token from token vault
        federated_token = None
        try:
            federated_token = get_tokenset()
            print('federated_tokenfederated_tokenfederated_tokenfederated_tokenfederated_token')
            print(federated_token.get("access_token"))
        except Exception as e:
            print(f"Warning: Could not get federated token: {str(e)}")

        # Store session data in DynamoDB
        store_session_data(
            session_id=session_id,
            refresh_token=token.get("refresh_token"),
            federated_token=federated_token.get("access_token"),
            user_data=user_profile
        )


        return redirect('/chat')

    except Exception as e:
        print(f"Error in callback: {str(e)}")
        session.clear()
        return redirect('/login')

@app.route("/logout")
def logout():
    """
    Handle user logout
    """
    session.clear()
    return redirect(
        f"{AUTH0_BASE_URL}/v2/logout?returnTo={url_for('index', _external=True)}&client_id={AUTH0_CLIENT_ID}"
    )

@app.route("/chat", methods=["GET", "POST"])
@requires_auth
def chat_page():
    """
    Main chat interface page - handles both displaying chat and processing messages
    """
    messages = session.get('chat_messages', [])
    # Allow JSON/AJAX clients to use the same endpoint without page reload
    wants_json = (
        'application/json' in (request.headers.get('Accept') or '')
        or (request.headers.get('X-Requested-With') == 'XMLHttpRequest')
        or (request.args.get('format') == 'json')
    )

    if request.method == "POST":
        user_message = request.form.get("message", "").strip()

        if user_message:
            # Add user message to chat history
            messages.append({
                "sender": "user",
                "message": user_message,
                "timestamp": "Just now"
            })

            try:
                # Get the session ID from Flask session
                session_id = session.get('session_id')
                if not session_id:
                    if wants_json:
                        return jsonify({"response": "No session ID found. Please log in again.", "success": False}), 401
                    return jsonify({"response": "No session ID found. Please log in again."}), 401  # fallback

                # Verify the session exists in DynamoDB
                session_data = get_session_data(session_id)
                if not session_data:
                    if wants_json:
                        return jsonify({"response": "Session expired or invalid. Please log in again.", "success": False}), 401
                    return jsonify({"response": "Session expired or invalid. Please log in again."}), 401

                print(f'Using session_id from dynamoDB: {session_id}')

                # Prepare the session state with ONLY session_id and basic user info
                # No tokens are sent to Bedrock
                session_state = {
                    "sessionAttributes": {
                        "session_id": session_id,
                        "logged_in_user": session['profile']['email'],
                        "user_id": session['profile']['user_id']
                    }
                }


                # Get bearer token for Agent Core API
                bearer_token = get_bearer_token()

                # Prepare the API request
                agent_runtime_arn_encoded = urllib.parse.quote(AGENT_RUNTIME_ARN, safe='')
                print('agent_runtime_arn_encodedagent_runtime_arn_encodedagent_runtime_arn_encoded',agent_runtime_arn_encoded)
                api_endpoint = f"https://bedrock-agentcore.us-east-1.amazonaws.com/runtimes/{agent_runtime_arn_encoded}/invocations?qualifier=DEFAULT"

                headers = {
                    "Authorization": f"Bearer {bearer_token}",
                    "Content-Type": "application/json",
                    "X-Amzn-Bedrock-AgentCore-Runtime-Session-Id": session.get('profile', {}).get('user_id', 'default-session')
                }
                print(type(session['profile']['email']))
                print(session['profile']['email'])
                # Send request to Agent Core
                response = requests.post(
                    api_endpoint,
                    headers=headers,
                    data=json.dumps({"prompt": user_message,"dynamoID":session_id,"email":session['profile']['email']}),
                    timeout=30
                )

                response.raise_for_status()
                agent_response = response.json()

                # Extract response text
                response_text = extract_response_text(agent_response)

                # Add agent response to chat history
                messages.append({
                    "sender": "agent",
                    "message": response_text,
                    "timestamp": "Just now"
                })
                if wants_json:
                    # Save messages in session for consistency and return JSON
                    session['chat_messages'] = messages
                    return jsonify({"response": response_text, "success": True})

            except requests.exceptions.HTTPError as e:
                print(f"HTTP Error: {e}")
                error_msg = f"Agent Core API error: {str(e)}"
                if wants_json:
                    return jsonify({"response": error_msg, "success": False}), 500
                else:
                    messages.append({
                        "sender": "system",
                        "message": error_msg,
                        "timestamp": "Just now"
                    })

            except Exception as e:
                print(f"Error in chat: {str(e)}")
                error_msg = f"Internal error: {str(e)}"
                if wants_json:
                    return jsonify({"response": error_msg, "success": False}), 500
                else:
                    messages.append({
                        "sender": "system",
                        "message": error_msg,
                        "timestamp": "Just now"
                    })

            # Save messages to session
            session['chat_messages'] = messages

    return render_template("chat.html", user=session['profile'], messages=messages)

@app.route("/clear-chat", methods=["POST"])
@requires_auth
def clear_chat():
    """
    Clear chat history
    """
    session['chat_messages'] = []
    return redirect('/chat')

@app.route("/api/token-vault", methods=["GET"])
@requires_auth
def get_token_vault_data():
    """
    Get token vault information for display in side panel
    """
    try:
        # Get token vault data
        tokenset = get_tokenset()

        if tokenset is None:
            return jsonify({
                "error": "No refresh token available",
                "message": "Token vault requires a refresh token from Auth0"
            }), 400

        # Add metadata for display
        vault_data = {
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "user": session.get('profile', {}).get('email', 'Unknown'),
            "token_vault_response": tokenset,
            "connection": os.getenv("AUTH0_CONNECTION_NAME", "Not configured"),
            "audience": f"https://{AUTH0_DOMAIN}/api/v2/"
        }

        return jsonify(vault_data)

    except Exception as e:
        print(f"Error fetching token vault data: {e}")
        return jsonify({
            "error": str(e),
            "message": "Failed to fetch token vault data"
        }), 500

def extract_response_text(response):
    """
    Extract response text from Agent Core response
    """
    if isinstance(response, str):
        return response
    elif isinstance(response, dict):
        # Look for common response fields
        return response.get('text') or response.get('message') or response.get('content') or str(response)
    else:
        return "Received response from agent."

if __name__ == "__main__":
    app.run(debug=True, host='0.0.0.0', port=5000) 