// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 André Valentin <avalentin@marcant.net>
// What sipd require()s when ims_modem option access is 'vowifi': a plain
// script (require() reads source), whose imports load the VoWiFi modules —
// bytecode in the package — only then. Without wwand-ims-vowifi installed the
// require fails and sipd says which package is missing.

'use strict';

import * as VICI from 'vowifi_vici';
import * as CTL from 'vowifi_ctl';

return { VICI: VICI, CTL: CTL };
