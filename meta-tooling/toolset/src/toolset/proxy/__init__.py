"""
The proxy is used to view HTTP traffic from the browser.
Official methods are list_traffic, view_traffic, and replay_request. The deprecated get_traffic alias is kept only for compatibility.
You can check the usage by running help(toolset.proxy).
"""
from core import namespace

namespace()

import os
from .proxy import Proxy

proxy = Proxy(f'http://localhost:{os.getenv("CAIDO_PORT")}/graphql', os.getenv("CAIDO_TOKEN"))

__all__ = ['proxy']
