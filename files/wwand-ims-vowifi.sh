#!/bin/sh
# the VoWiFi tunnel by hand (vowifi/cli.uc)
exec /usr/bin/ucode -L /usr/share/wwand-ims -L '/usr/lib/ucode/*.so' /usr/share/wwand-ims/vowifi_cli.uc "$@"
