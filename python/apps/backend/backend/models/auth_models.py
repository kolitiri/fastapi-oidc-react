from pydantic import BaseModel


class InternalAuthToken(BaseModel):
	code: str


class ExternalAuthToken(BaseModel):
	code: str


class InternalAccessTokenData(BaseModel):
	sub: str


class ExternalUser(BaseModel):
	email: str
	username: str
	external_sub_id: str
