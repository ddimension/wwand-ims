#!/bin/sh
# strongSwan ext-aka plugin's card program (charon.plugins.ext-aka.program):
# the AUTHENTICATE on the modem's USIM, wwand-ims-vowifi (vowifi/card.uc)
exec /usr/bin/ucode -L /usr/share/wwand-ims -L '/usr/lib/ucode/*.so' /usr/share/wwand-ims/vowifi_ext_aka.uc "$@"
