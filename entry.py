import datetime

from pydantic import BaseModel, IPvAnyAddress
from typing import List


class ModelEntry(BaseModel):
    set_name: str
    fqdn: str
    family: str
    typeof: int
    table: str
    ip_list: List[IPvAnyAddress] | None
    ttl: int | None
    next_update: datetime.datetime | None
