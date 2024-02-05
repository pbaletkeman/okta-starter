from __future__ import annotations

import os
from typing import Tuple, Any
from urllib.parse import quote

from litestar.connection import request
from litestar.contrib.mako import MakoTemplateEngine
from litestar.response import Template, Redirect
from litestar.template.config import TemplateConfig
from pathlib import Path
from litestar.middleware.session.client_side import CookieBackendConfig

import base64
import hashlib
import requests
import secrets

from litestar import Controller, Litestar, get, post, route, HttpMethod, Request
from pydantic import BaseModel

session_config = CookieBackendConfig(secret=os.urandom(16))

yourOktaDomain = 'dev-38646384.okta.com'
clientId = '0oaexmmww3ORg28pC5d7'
clientSecret = 'rLQkpoHzwhJ1-AvGm7qwUacQKDjpwcNsSi9vYCl8QzSH0BuvQknTIG47H7PRgs8b'

config = {
    "auth_uri": "https://" + yourOktaDomain + "/oauth2/default/v1/authorize",
    "client_id": clientId,
    "client_secret": clientSecret,
    "redirect_uri": "http://localhost:8000/authorization-code/callback",
    "issuer": "https://" + yourOktaDomain + "/oauth2/default",
    "token_uri": "https://" + yourOktaDomain + "/oauth2/default/v1/token",
    "userinfo_uri": "https://" + yourOktaDomain + "/oauth2/default/v1/userinfo",
    "SECRET_KEY": secrets.token_hex(64)
}

# Simulate user database
USERS_DB = {}


class User(BaseModel):
    """Custom User class."""

    def __init__(self, id_, name, email, **data: Any):
        super().__init__(**data)
        self.id = id_
        self.name = name
        self.email = email

    def __str__(self):
        return "{id=" + self.id + ", name=" + self.name + ', email=' + self.email + '}'

    def claims(self):
        """Use this method to render all assigned claims on profile page."""
        return {'name': self.name,
                'email': self.email}.items()

    @staticmethod
    def get(user_id):
        return USERS_DB.get(user_id)

    @staticmethod
    def create(user_id, name, email):
        USERS_DB[user_id] = User(user_id, name, email)


class SampleController(Controller):

    @get(path="/")
    async def home_page(self) -> Template:
        """Check database available and returns app config info."""
        return Template(template_name="signin.html.mako")

    @route(path="/signin", http_method=[HttpMethod.GET, HttpMethod.POST])
    async def signin(self, request: Request) -> Redirect:
        request.set_session({"app_state": secrets.token_urlsafe(64), "code_verifier": secrets.token_urlsafe(64)})

        # calculate code challenge
        hashed = hashlib.sha256(request.session['code_verifier'].encode('ascii')).digest()
        encoded = base64.urlsafe_b64encode(hashed)
        code_challenge = encoded.decode('ascii').strip('=')

        # get request params
        query_params = {'client_id': config["client_id"],
                        'redirect_uri': config["redirect_uri"],
                        'scope': "openid email profile",
                        'state': request.session['app_state'],
                        'code_challenge': code_challenge,
                        'code_challenge_method': 'S256',
                        'response_type': 'code',
                        'response_mode': 'query'}

        # build request_uri
        request_uri = "{base_url}?{query_params}".format(
            base_url=config["auth_uri"],
            query_params=quote(str(query_params)))
        return Redirect(request_uri)

    @get('/signout')
    def sign_out(self) -> str:
        return 'hello from signout'

    @get(path='/authorization-code/callback')
    async def callback(self, request: Request) -> str | tuple[str, int]:
        """Check database available and returns app config info."""
        headers = {'Content-Type': 'application/x-www-form-urlencoded'}
        code = request.query_params.get("code")
        app_state = request.query_params.get("state")
        if app_state != request.sessions['app_state']:
            return "The app state doesn't match"
        if not code:
            return "The code wasn't returned or isn't accessible", 403
        query_params = {'grant_type': 'authorization_code',
                        'code': code,
                        'redirect_uri': request.base_url,
                        'code_verifier': request.sessions['code_verifier'],
                        }

        query_params = quote(str(query_params))
        exchange = requests.post(
            config["token_uri"],
            headers=headers,
            data=query_params,
            auth=(config["client_id"], config["client_secret"]),
        ).json()

        # Get tokens and validate
        if not exchange.get("token_type"):
            return "Unsupported token type. Should be 'Bearer'.", 403
        access_token = exchange["access_token"]
        id_token = exchange["id_token"]

        # Authorization flow successful, get userinfo and sign in user
        userinfo_response = requests.get(config["userinfo_uri"],
                                         headers={'Authorization': f'Bearer {access_token}'}).json()

        unique_id = userinfo_response["sub"]
        user_email = userinfo_response["email"]
        user_name = userinfo_response["given_name"]

        user = User(
            id_=unique_id, name=user_name, email=user_email
        )
        return str(user)


app = Litestar(
    route_handlers=[SampleController],
    template_config=TemplateConfig(
        directory=Path("templates"),
        engine=MakoTemplateEngine,
    ),
    middleware=[session_config.middleware],
)
