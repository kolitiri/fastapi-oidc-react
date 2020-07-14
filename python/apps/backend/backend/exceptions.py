from contextlib import asynccontextmanager
import logging

from fastapi import HTTPException, status


logger = logging.getLogger(__name__)

class DatabaseException(Exception):
	pass


class UnknownDatabaseType(DatabaseException):
	pass


class DatabaseConnectionError(DatabaseException):
	pass


class AuthenticationException(Exception):
	pass


class UnknownAuthenticationProvider(AuthenticationException):
	pass


class AuthorizationException(Exception):
	pass


class UnauthorizedUser(AuthorizationException):
	pass


class DiscoveryDocumentError(AuthorizationException):
	pass


class ProviderConnectionError(AuthorizationException):
	pass


@asynccontextmanager
async def exception_handling():
	try:
		yield
	except DatabaseConnectionError as exc:
		logger.exception(f"Failed to connect to the database: {repr(exc)}")
		raise HTTPException(status_code=500, detail="Cannot serve results at the moment. Please try again.")
	except UnauthorizedUser as exc:
		logger.warning(f"Failed to authorize user: {repr(exc)}")
		raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not authorized")
	except Exception as exc:
		logger.exception(repr(exc))
		raise HTTPException(status_code=500, detail="An error has occurred. Please try again.")
