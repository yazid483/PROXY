@echo off
title FEKA Proxy - Port 8883 (Drag Headshot)
set M3SB_FEATURE=DRAG_HEADSHOT
set M3SB_DB_PATH=C:\m3sb\m3sb.db
set M3SB_DATA_DIR=C:\m3sb\data
set M3SB_LOG_DIR=C:\m3sb\logs
"C:\Program Files\Python311\Scripts\mitmdump.exe" -p 8883 --set proxyauth=M3SB:M3SB --set block_global=false --ssl-insecure -s C:\m3sb\scripts\m3sb_proxy.py
