import datetime
from enum import Enum
from typing import List, Optional

from pydantic import BaseModel, Field, conint, conlist, constr


class InternalUser(BaseModel):
	external_sub_id: str
	internal_sub_id: str
	username: str
	created_at: datetime.datetime
