import datetime

from pydantic import BaseModel, IPvAnyAddress


class ModelEntry(BaseModel):
    set_name: str
    fqdn: str
    family: str
    typeof: int
    table: str
    ip_list: list[IPvAnyAddress] | None
    ttl: int | None
    next_update: datetime.datetime | None
