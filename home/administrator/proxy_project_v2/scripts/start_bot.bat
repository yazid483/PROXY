@echo off
title FEKA Telegram Bot
rem #Put your token here
set M3SB_BOT_TOKEN=YOUR_BOT_TOKEN_HERE
set M3SB_DB_PATH=C:\m3sb\m3sb.db
rem #And your id here
set M3SB_ADMIN_IDS=YOUR_TELEGRAM_ID_HERE
set M3SB_LOG_DIR=C:\m3sb\logs
"C:\Program Files\Python311\python.exe" C:\m3sb\scripts\m3sb_bot.py
