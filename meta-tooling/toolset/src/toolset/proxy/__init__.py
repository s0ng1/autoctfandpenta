"""
The proxy is used to view HTTP traffic from the browser.
You can check the usage by running help(toolset.proxy).
"""
from core import namespace

namespace()

import os
from .proxy import Proxy

proxy = Proxy(f'http://localhost:{os.getenv("CAIDO_PORT")}/graphql', os.getenv("CAIDO_TOKEN"))

__all__ = ['proxy']
