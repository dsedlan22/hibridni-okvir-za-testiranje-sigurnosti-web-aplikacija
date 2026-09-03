"""Finding model - unified vulnerability record (chapter 4.4)."""

import uuid
from dataclasses import dataclass, field
from typing import List, Optional


@dataclass
class Finding:
    """Single normalized vulnerability finding."""

    # osnovna polja (4.4)
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    alat: str = ""
    ranjivost: str = ""
    url: str = ""
    parametar: Optional[str] = None
    owasp_kategorija: str = "nekategorizirano"
    ozbiljnost: str = "informativno"
    opis: str = ""
    dokaz: str = ""

    # dodatna polja nakon deduplikacije i korelacije (4.5)
    alati: List[str] = field(default_factory=list)
    dokazi: List[str] = field(default_factory=list)
    korelirano: bool = False
