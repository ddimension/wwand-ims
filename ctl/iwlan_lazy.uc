// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 André Valentin <avalentin@marcant.net>
// What `wwandctl ims` (ctl/ims.uc, a require()d script) loads the carrier
// config reader through: a plain script (require() reads source) whose
// imports load the ES modules — bytecode in the package. Installed as
// /usr/share/wwand-ims/ims_iwlan_lazy.uc.

'use strict';

import * as IW from 'ims_iwlan';
import * as DIAG from 'ims_diag';

return { IW: IW, DIAG: DIAG };
