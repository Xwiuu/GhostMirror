"""WhatWeb integration package."""

from ghostmirror.integrations.whatweb.parser import WhatWebParser
from ghostmirror.integrations.whatweb.scanner import WhatWebRunner

__all__ = ["WhatWebRunner", "WhatWebParser"]
