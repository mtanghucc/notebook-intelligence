import datetime as dt
import enum
import json
import logging
import secrets
import subprocess
import threading
import time
import uuid
import requests

from notebook_intelligence.api import CancelToken, ChatResponse, CompletionContext, MarkdownData

from ._version import __version__ as NBI_VERSION

# Logger setup
log = logging.getLogger(__name__)

# Define login status enum
LoginStatus = enum.Enum('LoginStatus', ['NOT_LOGGED_IN', 'ACTIVATING_DEVICE', 'LOGGING_IN', 'LOGGED_IN'])

# Global constants and variables
EDITOR_VERSION = f"NotebookIntelligence/{NBI_VERSION}"
EDITOR_PLUGIN_VERSION = f"NotebookIntelligence/{NBI_VERSION}"
USER_AGENT = f"NotebookIntelligence/{NBI_VERSION}"
CLIENT_ID = "Iv1.b507a08c87ecfe98"
MACHINE_ID = secrets.token_hex(33)[:65]

API_ENDPOINT = "https://api.githubcopilot.com"
PROXY_ENDPOINT = "https://copilot-proxy.githubusercontent.com"
TOKEN_REFRESH_INTERVAL = 1500
ACCESS_TOKEN_THREAD_SLEEP_INTERVAL = 5
TOKEN_THREAD_SLEEP_INTERVAL = 3
TOKEN_FETCH_INTERVAL = 15
NL = '\n'
KEYRING_SERVICE_NAME = "NotebookIntelligence"
GITHUB_ACCESS_TOKEN_KEYRING_NAME = "github-copilot-access-token"

github_auth = {
    "verification_uri": None,
    "user_code": None,
    "device_code": None,
    "access_token": None,
    "status": LoginStatus.NOT_LOGGED_IN,
    "token": None,
    "token_expires_at": dt.datetime.now()
}

# Globals for legacy keyring support
github_access_token_provided = None
remember_github_access_token = False

stop_requested = False
get_access_code_thread = None
get_token_thread = None
last_token_fetch_time = dt.datetime.now() - dt.timedelta(seconds=TOKEN_FETCH_INTERVAL)


def get_login_status():
    """
    Returns the current login status.
    If the device flow is active, includes verification_uri and user_code.
    """
    global github_auth
    response = {"status": github_auth["status"].name}
    if github_auth["status"] == LoginStatus.ACTIVATING_DEVICE:
        response.update({
            "verification_uri": github_auth["verification_uri"],
            "user_code": github_auth["user_code"]
        })
    return response


def get_gh_auth_token():
    """
    Attempt to retrieve a GitHub token using the GitHub CLI (gh auth).
    Returns the token if found; otherwise, returns None.
    """
    try:
        result = subprocess.run(
            ["gh", "auth", "token"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=True
        )
        token = result.stdout.strip()
        if token:
            log.info("Found gh auth token via GitHub CLI.")
            return token
    except Exception as e:
        log.error(f"Failed to retrieve gh auth token: {e}")
    return None


def login_with_existing_credentials(access_token_config=None):
    """
    Legacy support for existing credentials.
    If access_token_config is 'remember' or None, attempts to retrieve the token from keyring.
    If 'forget' is passed, deletes the stored token.
    Otherwise, if a token is provided directly, it is used.
    Finally, login() is called which now also tries gh auth.
    """
    global github_access_token_provided, remember_github_access_token, github_auth

    if github_auth["status"] is not LoginStatus.NOT_LOGGED_IN:
        return

    if access_token_config == "remember" or access_token_config is None:
        try:
            import keyring
            github_access_token_provided = keyring.get_password(KEYRING_SERVICE_NAME, GITHUB_ACCESS_TOKEN_KEYRING_NAME)
        except Exception as e:
            if access_token_config == "remember":
                log.error(f"Failed to get GitHub access token from keyring: {e}")
        remember_github_access_token = (access_token_config == "remember")
    elif access_token_config == "forget":
        try:
            import keyring
            keyring.delete_password(KEYRING_SERVICE_NAME, GITHUB_ACCESS_TOKEN_KEYRING_NAME)
        except Exception as e:
            log.error(f"Failed to forget GitHub access token from keyring: {e}")
    elif access_token_config is not None:
        github_access_token_provided = access_token_config

    if github_access_token_provided is not None:
        login()


def store_github_access_token(access_token):
    """
    Stores the GitHub access token in keyring if the 'remember' option was used.
    """
    if remember_github_access_token:
        try:
            import keyring
            keyring.set_password(KEYRING_SERVICE_NAME, GITHUB_ACCESS_TOKEN_KEYRING_NAME, access_token)
        except Exception as e:
            log.error(f"Failed to store GitHub access token in keyring: {e}")


def login():
    """
    Main login function.
    First tries to retrieve a token using gh auth.
    If that fails, and if a token from keyring is available, it uses that.
    Otherwise, falls back to the device verification flow.
    Once a token is obtained, get_token() is called to retrieve the Copilot token.
    """
    global github_access_token_provided, github_auth

    # Try gh auth token first.
    gh_token = get_gh_auth_token()
    if not gh_token and github_access_token_provided:
        gh_token = github_access_token_provided
        log.info("Using token from legacy credentials.")
    if gh_token:
        log.info("User authenticated via GitHub CLI or keyring.")
        github_auth["access_token"] = gh_token
        github_auth["status"] = LoginStatus.LOGGING_IN
        get_token()
        return {"status": github_auth["status"].name}
    else:
        # Fall back to device code flow.
        login_info = get_device_verification_info()
        if login_info is not None:
            wait_for_tokens()
        return login_info


def logout():
    """
    Logs the user out by resetting all authentication state.
    """
    global github_auth
    github_auth.update({
        "verification_uri": None,
        "user_code": None,
        "device_code": None,
        "access_token": None,
        "status": LoginStatus.NOT_LOGGED_IN,
        "token": None
    })
    return {"status": github_auth["status"].name}


def handle_stop_request():
    """
    Sets a flag to request termination of background token fetching threads.
    """
    global stop_requested
    stop_requested = True


def get_device_verification_info():
    """
    Initiates the device verification flow.
    Returns a dictionary containing the verification URI and user code.
    """
    global github_auth
    data = {
        "client_id": CLIENT_ID,
        "scope": "read:user"
    }
    try:
        resp = requests.post(
            'https://github.com/login/device/code',
            headers={
                'accept': 'application/json',
                'editor-version': EDITOR_VERSION,
                'editor-plugin-version': EDITOR_PLUGIN_VERSION,
                'content-type': 'application/json',
                'user-agent': USER_AGENT,
                'accept-encoding': 'gzip,deflate,br'
            },
            data=json.dumps(data)
        )
        resp_json = resp.json()
        github_auth["verification_uri"] = resp_json.get('verification_uri')
        github_auth["user_code"] = resp_json.get('user_code')
        github_auth["device_code"] = resp_json.get('device_code')
        github_auth["status"] = LoginStatus.ACTIVATING_DEVICE
    except Exception as e:
        log.error(f"Failed to get device verification info: {e}")
        return None

    return {
        "verification_uri": github_auth["verification_uri"],
        "user_code": github_auth["user_code"]
    }


def wait_for_user_access_token_thread_func():
    """
    Thread function that polls for the access token using the device flow.
    If a token is already available (e.g. from gh auth or keyring), it exits immediately.
    """
    global github_auth, get_access_code_thread
    if github_auth["access_token"]:
        log.info("Using existing GitHub access token; skipping device polling.")
        get_access_code_thread = None
        return

    while True:
        if stop_requested or github_auth["access_token"] is not None or github_auth["device_code"] is None or github_auth["status"] == LoginStatus.NOT_LOGGED_IN:
            get_access_code_thread = None
            break
        data = {
            "client_id": CLIENT_ID,
            "device_code": github_auth["device_code"],
            "grant_type": "urn:ietf:params:oauth:grant-type:device_code"
        }
        try:
            resp = requests.post(
                'https://github.com/login/oauth/access_token',
                headers={
                    'accept': 'application/json',
                    'editor-version': EDITOR_VERSION,
                    'editor-plugin-version': EDITOR_PLUGIN_VERSION,
                    'content-type': 'application/json',
                    'user-agent': USER_AGENT,
                    'accept-encoding': 'gzip,deflate,br'
                },
                data=json.dumps(data)
            )
            resp_json = resp.json()
            access_token = resp_json.get('access_token')
            if access_token:
                github_auth["access_token"] = access_token
                get_token()
                get_access_code_thread = None
                store_github_access_token(access_token)
                break
        except Exception as e:
            log.error(f"Failed to get access token from device flow: {e}")
        time.sleep(ACCESS_TOKEN_THREAD_SLEEP_INTERVAL)


def get_token():
    """
    Uses the acquired GitHub access token to request a Copilot-specific token.
    """
    global github_auth, API_ENDPOINT, PROXY_ENDPOINT, TOKEN_REFRESH_INTERVAL
    access_token = github_auth["access_token"]
    if access_token is None:
        return

    github_auth["status"] = LoginStatus.LOGGING_IN
    try:
        resp = requests.get(
            'https://api.github.com/copilot_internal/v2/token',
            headers={
                'authorization': f'token {access_token}',
                'editor-version': EDITOR_VERSION,
                'editor-plugin-version': EDITOR_PLUGIN_VERSION,
                'user-agent': USER_AGENT
            }
        )
        resp_json = resp.json()
        if resp.status_code == 401:
            # Token no longer valid; restart authentication.
            github_auth["access_token"] = None
            logout()
            wait_for_tokens()
            return
        if resp.status_code != 200:
            log.error(f"Failed to get token from GitHub Copilot: {resp_json}")
            return

        token = resp_json.get('token')
        github_auth["token"] = token
        expires_at = resp_json.get('expires_at')
        if expires_at is not None:
            github_auth["token_expires_at"] = dt.datetime.fromtimestamp(expires_at)
        else:
            github_auth["token_expires_at"] = dt.datetime.now() + dt.timedelta(seconds=TOKEN_REFRESH_INTERVAL)
        github_auth["verification_uri"] = None
        github_auth["user_code"] = None
        github_auth["status"] = LoginStatus.LOGGED_IN

        endpoints = resp_json.get('endpoints', {})
        API_ENDPOINT = endpoints.get('api', API_ENDPOINT)
        PROXY_ENDPOINT = endpoints.get('proxy', PROXY_ENDPOINT)
        TOKEN_REFRESH_INTERVAL = resp_json.get('refresh_in', TOKEN_REFRESH_INTERVAL)
    except Exception as e:
        log.error(f"Failed to get token from GitHub Copilot: {e}")


def get_token_thread_func():
    """
    Thread function that periodically refreshes the Copilot token.
    """
    global github_auth, get_token_thread, last_token_fetch_time
    while True:
        if stop_requested or github_auth["status"] == LoginStatus.NOT_LOGGED_IN:
            get_token_thread = None
            return
        token = github_auth["token"]
        # Refresh token if it is expired or about to expire.
        if github_auth["access_token"] is not None and (token is None or (dt.datetime.now() - github_auth["token_expires_at"]).total_seconds() > -10):
            if (dt.datetime.now() - last_token_fetch_time).total_seconds() > TOKEN_FETCH_INTERVAL:
                log.info("Refreshing GitHub token")
                get_token()
                last_token_fetch_time = dt.datetime.now()
        time.sleep(TOKEN_THREAD_SLEEP_INTERVAL)


def wait_for_tokens():
    """
    Starts the threads for waiting for the access token and for token refreshing.
    """
    global get_access_code_thread, get_token_thread
    if get_access_code_thread is None:
        get_access_code_thread = threading.Thread(target=wait_for_user_access_token_thread_func)
        get_access_code_thread.start()
    if get_token_thread is None:
        get_token_thread = threading.Thread(target=get_token_thread_func)
        get_token_thread.start()


def generate_copilot_headers():
    """
    Generates headers for GitHub Copilot API requests.
    """
    token = github_auth.get('token')
    return {
        'authorization': f'Bearer {token}',
        'editor-version': EDITOR_VERSION,
        'editor-plugin-version': EDITOR_PLUGIN_VERSION,
        'user-agent': USER_AGENT,
        'content-type': 'application/json',
        'openai-intent': 'conversation-panel',
        'openai-organization': 'github-copilot',
        'copilot-integration-id': 'vscode-chat',
        'x-request-id': str(uuid.uuid4()),
        'vscode-sessionid': str(uuid.uuid4()),
        'vscode-machineid': MACHINE_ID,
    }


def inline_completions(model_id, prefix, suffix, language, filename, context, cancel_token) -> str:
    """
    Retrieves inline completions using the Copilot API.
    """
    token = github_auth.get('token')
    prompt = f"# Path: {filename}"
    if cancel_token.is_cancel_requested:
        return ''
    if context is not None:
        for item in context.items:
            context_file = f"Compare this snippet from {item.filePath if item.filePath is not None else 'undefined'}:{NL}{item.content}{NL}"
            prompt += "\n# " + "\n# ".join(context_file.split('\n'))
    prompt += f"{NL}{prefix}"
    try:
        if cancel_token.is_cancel_requested:
            return ''
        resp = requests.post(
            f"{PROXY_ENDPOINT}/v1/engines/{model_id}/completions",
            headers={'authorization': f'Bearer {token}'},
            json={
                'prompt': prompt,
                'suffix': suffix,
                'min_tokens': 500,
                'max_tokens': 2000,
                'temperature': 0,
                'top_p': 1,
                'n': 1,
                'stop': ['<END>', '```'],
                'nwo': 'NotebookIntelligence',
                'stream': True,
                'extra': {
                    'language': language,
                    'next_indent': 0,
                    'trim_by_indentation': True
                }
            }
        )
    except Exception as e:
        log.error(f"Failed to get inline completions: {e}")
        return ''
    if cancel_token.is_cancel_requested:
        return ''
    result = ''
    decoded_response = resp.content.decode()
    resp_text = decoded_response.split('\n')
    for line in resp_text:
        if line.startswith('data: {'):
            json_completion = json.loads(line[6:])
            completion = json_completion.get('choices')[0].get('text')
            if completion:
                result += completion
    return result


def completions(model_id, messages, tools=None, response=None, cancel_token=None, options: dict = {}) -> any:
    """
    Retrieves chat completions from the Copilot API.
    Supports streaming responses if a response handler is provided.
    """
    stream = response is not None
    try:
        data = {
            'model': model_id,
            'messages': messages,
            'tools': tools,
            'max_tokens': 1000,
            'temperature': 0,
            'top_p': 1,
            'n': 1,
            'stop': ['<END>'],
            'nwo': 'NotebookIntelligence',
            'stream': stream
        }
        if 'tool_choice' in options:
            data['tool_choice'] = options['tool_choice']
        if cancel_token is not None and cancel_token.is_cancel_requested:
            response.finish()
        request = requests.post(
            f"{API_ENDPOINT}/chat/completions",
            headers=generate_copilot_headers(),
            json=data,
            stream=stream
        )
        if request.status_code != 200:
            msg = f"Failed to get completions from GitHub Copilot: [{request.status_code}]: {request.text}"
            log.error(msg)
            if response:
                response.stream(msg)
                response.finish()
            raise Exception(msg)
        if stream:
            import sseclient
            client = sseclient.SSEClient(request)
            for event in client.events():
                if cancel_token is not None and cancel_token.is_cancel_requested:
                    response.finish()
                if event.data == '[DONE]':
                    response.finish()
                else:
                    response.stream(json.loads(event.data))
            return
        else:
            return request.json()
    except requests.exceptions.ConnectionError:
        raise Exception("Connection error")
    except Exception as e:
        log.error(f"Failed to get completions from GitHub Copilot: {e}")
        raise e
