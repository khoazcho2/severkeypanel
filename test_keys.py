import sqlite3
print('Recent 5 keys:')
for row in sqlite3.connect('serverkey.db').execute('SELECT key FROM keys ORDER BY id DESC LIMIT 5'):
    print(row[0])
