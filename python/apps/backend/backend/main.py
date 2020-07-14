import logging
import time
from uuid import uuid4

from fastapi import (
	Depends,
	FastAPI,
	Request,
	status,
)
from fastapi.encoders import jsonable_encoder
from fastapi.middleware.cors import CORSMiddleware
from starlette.responses import (
	JSONResponse,
	RedirectResponse,
)

from backend.auth import (
	providers as auth_providers,
	schemes as auth_schemes,
	util as auth_util,
)
from backend import config
from backend import db_client
from backend.exceptions import (
	AuthorizationException,
	exception_handling,
)
from backend.models.db_models import (
	InternalUser,
)
from backend.models.auth_models import (
	ExternalAuthToken,
	ExternalUser,
	InternalAccessTokenData,
)


logger = logging.getLogger(__name__)

app = FastAPI()

# Allow CORS. DON'T do that on production!
origins = [
	"http://localhost:3000",
]
app.add_middleware(
	CORSMiddleware,
	allow_origins=origins,
	allow_credentials=True,
	allow_methods=["*"],
	allow_headers=["*"],
)

csrf_token_redirect_cookie_scheme = auth_schemes.CSRFTokenRedirectCookieBearer()
auth_token_scheme = auth_schemes.AuthTokenBearer()
access_token_cookie_scheme = auth_schemes.AccessTokenCookieBearer()


@app.on_event("startup")
async def startup_event():
	""" Startup functionality """
	async with exception_handling():
		await db_client.start_session()


@app.on_event("shutdown")
async def shutdown_event():
	""" Shutdown functionality """
	async with exception_handling():
		await db_client.end_session()
		await db_client.close_connection()


@app.middleware("http")
async def setup_request(request: Request, call_next) -> JSONResponse:
	""" A middleware for setting up a request. It creates a new request_id
		and adds some basic metrics.

		Args:
			request: The incoming request
			call_next (obj): The wrapper as per FastAPI docs

		Returns:
			response: The JSON response
	"""
	response = await call_next(request)

	return response


@app.get("/login-redirect")
async def login_redirect(auth_provider: str):
	""" Redirects the user to the external authentication pop-up

		Args:
			auth_provider: The authentication provider (i.e google-iodc)

		Returns:
			Redirect response to the external provider's auth endpoint
	"""
	async with exception_handling():
		provider = await auth_providers.get_auth_provider(auth_provider)

		request_uri, state_csrf_token = await provider.get_request_uri()

		response = RedirectResponse(url=request_uri)

		# Make this a secure cookie for production use
		response.set_cookie(key="state", value=f"Bearer {state_csrf_token}", httponly=True)

		return response


@app.get("/google-login-callback/")
async def google_login_callback(
	request: Request,
	_ = Depends(csrf_token_redirect_cookie_scheme)
):
	""" Callback triggered when the user logs in to Google's pop-up.

		Receives an authentication_token from Google which then
		exchanges for an access_token. The latter is used to
		gain user information from Google's userinfo_endpoint.

		Args:
			request: The incoming request as redirected by Google
	"""
	async with exception_handling():
		code = request.query_params.get("code")

		if not code:
			raise AuthorizationException("Missing external authentication token")

		provider = await auth_providers.get_auth_provider(config.GOOGLE)

		# Authenticate token and get user's info from external provider
		external_user = await provider.get_user(
			auth_token=ExternalAuthToken(code=code)
		)

		# Get or create the internal user
		internal_user = await db_client.get_user_by_external_sub_id(external_user)

		if internal_user is None:
			internal_user = await db_client.create_internal_user(external_user)

		internal_auth_token = await auth_util.create_internal_auth_token(internal_user)

		# Redirect the user to the home page
		redirect_url = f"{config.FRONTEND_URL}?authToken={internal_auth_token}"
		response = RedirectResponse(url=redirect_url)

		# Delete state cookie. No longer required
		response.delete_cookie(key="state")

		return response


@app.get("/azure-login-callback/")
async def azure_login_callback(
	request: Request,
	_ = Depends(csrf_token_redirect_cookie_scheme)
):
	""" Callback triggered when the user logs in to Azure's pop-up.

		Receives an authentication_token from Azure which then
		exchanges for an access_token. The latter is used to
		gain user information from Azure's userinfo_endpoint.

		Args:
			request: The incoming request as redirected by Azure
	"""
	async with exception_handling():
		code = request.query_params.get("code")

		if not code:
			raise AuthorizationException("Missing external authentication token")

		provider = await auth_providers.get_auth_provider(config.AZURE)

		# Authenticate token and get user's info from external provider
		external_user = await provider.get_user(
			auth_token=ExternalAuthToken(code=code)
		)

		# Get or create the internal user
		internal_user = await db_client.get_user_by_external_sub_id(external_user)

		if internal_user is None:
			internal_user = await db_client.create_internal_user(external_user)

		internal_auth_token = await auth_util.create_internal_auth_token(internal_user)

		# Redirect the user to the home page
		redirect_url = f"{config.FRONTEND_URL}?authToken={internal_auth_token}"
		response = RedirectResponse(url=redirect_url)

		# Delete state cookie. No longer required
		response.delete_cookie(key="state")

		return response


@app.get("/login/")
async def login(
	response: JSONResponse,
	internal_user: str = Depends(auth_token_scheme)
) -> JSONResponse:
	""" Login endpoint for authenticating a user after he has received
		an authentication token. If the token is valid it generates
		an access token and inserts it in a HTTPOnly cookie.

		Args:
			internal_auth_token: Internal authentication token

		Returns:
			response: A JSON response with the status of the user's session
	"""
	async with exception_handling():
		access_token = await auth_util.create_internal_access_token(
			InternalAccessTokenData(
				sub=internal_user.internal_sub_id,
			)
		)

		response = JSONResponse(
			content=jsonable_encoder({
				"userLoggedIn": True,
				"userName": internal_user.username,
			}),
		)

		# Make this a secure cookie for production use
		response.set_cookie(key="access_token", value=f"Bearer {access_token}", httponly=True)

		return response


@app.get("/logout/")
async def logout(
	response: JSONResponse,
	internal_user: str = Depends(access_token_cookie_scheme)
) -> JSONResponse:
	""" Logout endpoint for deleting the HTTPOnly cookie on the user's browser.

		Args:
			internal_auth_token: Internal authentication token

		Returns:
			response: A JSON response with the status of the user's session
	"""
	async with exception_handling():
		response = JSONResponse(
			content=jsonable_encoder({
				"userLoggedIn": False,
			}),
		)

		response.delete_cookie(key="access_token")

		return response


@app.get("/user-session-status/")
async def user_session_status(
	internal_user: InternalUser = Depends(access_token_cookie_scheme)
) -> JSONResponse:
	""" User status endpoint for checking whether the user currently holds
		an HTTPOnly cookie with a valid access token.

		Args:
			internal_user: A user object that has meaning in this application

		Returns:
			response: A JSON response with the status of the user's session
	"""
	async with exception_handling():
		logged_id = True if internal_user else False

		response = JSONResponse(
			content=jsonable_encoder({
				"userLoggedIn": logged_id,
				"userName": internal_user.username,
			}),
		)

		return response
