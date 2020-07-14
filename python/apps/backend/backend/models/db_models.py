import datetime

from pydantic import BaseModel


class InternalUser(BaseModel):
	external_sub_id: str
	internal_sub_id: str
	username: str
	created_at: datetime.datetime
