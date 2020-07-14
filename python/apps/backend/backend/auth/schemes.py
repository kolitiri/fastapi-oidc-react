from typing import Optional

from fastapi.security.utils import get_authorization_scheme_param
from fastapi import Request

from backend.exceptions import (
	UnauthorizedUser,
	exception_handling,
)
from backend.models.db_models import InternalUser
from backend.auth import util as auth_util


class CSRFTokenRedirectCookieBearer():
	""" Scheme that checks the validity of the state parameter
		returned by the Authentication provider when it redirects
		the user to the application after a successful sing in.
	"""
	async def __call__(self, request: Request) -> InternalUser:
		async with exception_handling():
			# State token from redirect
			state_csrf_token: str = request.query_params.get("state")
			# State token from cookie
			state_csrf_token_cookie: str = request.cookies.get('state')

			if not state_csrf_token_cookie:
				raise UnauthorizedUser("Invalid state token")

			# Remove Bearer
			state_csrf_token_cookie = state_csrf_token_cookie.split()[1]

			await auth_util.validate_state_csrf_token(state_csrf_token, state_csrf_token_cookie)


class AccessTokenCookieBearer():
	""" Scheme that checks the validity of the access token
		that is stored to an HTTPOnly secure cookie in order
		to authorize the user.
	"""
	async def __call__(self, request: Request) -> InternalUser:
		async with exception_handling():
			internal_access_token: str = request.cookies.get('access_token')
			if not internal_access_token:
				raise UnauthorizedUser("Invalid access token cookie")

			# Remove Bearer
			internal_access_token = internal_access_token.split()[1]

			internal_user = await auth_util.validate_internal_access_token(internal_access_token)

			return internal_user


class AuthTokenBearer():
	""" Scheme that checks the validity of the authorization token
		that is exchanged prior to authenticating the user in the
		service and issuing the final access token.
	"""
	async def __call__(self, request: Request) -> Optional[str]:
		async with exception_handling():
			authorization: str = request.headers.get("Authorization")
			scheme, internal_auth_token = get_authorization_scheme_param(authorization)

			if not authorization or scheme.lower() != "bearer":
				raise UnauthorizedUser("Invalid authentication token")

			internal_user = await auth_util.validate_internal_auth_token(internal_auth_token)

			return internal_user
