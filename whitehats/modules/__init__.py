from whitehats.modules.base_module import BaseModule
from whitehats.modules.sql_injection import SQLInjectionModule
from whitehats.modules.xss import XSSModule
from whitehats.modules.csrf import CSRFModule
from whitehats.modules.header_security import HeaderSecurityModule
from whitehats.modules.cors_misconfig import CORSMisconfigModule
from whitehats.modules.info_disclosure import InfoDisclosureModule

ALL_MODULES = [
    SQLInjectionModule,
    XSSModule,
    CSRFModule,
    HeaderSecurityModule,
    CORSMisconfigModule,
    InfoDisclosureModule,
]

__all__ = [
    "BaseModule",
    "SQLInjectionModule",
    "XSSModule",
    "CSRFModule",
    "HeaderSecurityModule",
    "CORSMisconfigModule",
    "InfoDisclosureModule",
    "ALL_MODULES",
]
