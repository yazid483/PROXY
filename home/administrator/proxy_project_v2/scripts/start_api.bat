@echo off
title FEKA API Server
set M3SB_API_PORT=8080
set M3SB_DB_PATH=C:\m3sb\m3sb.db
set M3SB_DATA_DIR=C:\m3sb\data
set M3SB_AUTH_KEY=M3SB_PROXY
set M3SB_ACTIVE_FEATURE=NECK_ANTENNA
"C:\Program Files\Python311\python.exe" C:\m3sb\scripts\m3sb_api_server.py
