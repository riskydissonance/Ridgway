#!/bin/bash
msfvenom -a x86 --platform windows -p - -e x86/shikata_ga_nai -b '\x00\x0a\x0d' -f raw -o /tmp/ridgwayencoded.bin < /tmp/ridgwayunencoded.bin >/dev/null 2>/dev/null
