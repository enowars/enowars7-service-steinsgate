#!/bin/sh
sqlite3 /service/persist/usersdb.sqlite "DELETE FROM users WHERE created_at <= datetime('now','-10 minutes')"
sqlite3 /service/persist/usersdb.sqlite "DELETE FROM phones WHERE created_at <= datetime('now','-10 minutes')"
sqlite3 /service/persist/usersdb.sqlite "DELETE FROM notes WHERE created_at <= datetime('now','-10 minutes')"