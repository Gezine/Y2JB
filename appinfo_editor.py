import sqlite3
import shutil
import os

if not os.path.exists('appinfo.db'):
    print("Error: appinfo.db file not found!")
    exit(1)

print("Creating backup...")
shutil.copy('appinfo.db', 'appinfo.org.db')
print("Backup created: appinfo.org.db")

conn = sqlite3.connect('appinfo.db')
cursor = conn.cursor()

TITLE_IDS = ['PPSA01650', 'PPSA01651', 'PPSA01652']

for title_id in TITLE_IDS:
    print(f"\n--- Processing {title_id} ---")

    cursor.execute("""
        SELECT key, val 
        FROM tbl_appinfo 
        WHERE titleId = ? 
        AND key IN ('CONTENT_VERSION', 'VERSION_FILE_URI')
    """, (title_id,))
    results = cursor.fetchall()

    if len(results) != 2:
        print(f"Error: Expected 2 keys but found {len(results)} for {title_id}")
        print("Required keys: CONTENT_VERSION, VERSION_FILE_URI")
        print(f"Found keys: {[row[0] for row in results]}")
        conn.close()
        exit(1)

    print("All required keys found. Proceeding with updates...")

    cursor.execute("""
        UPDATE tbl_appinfo 
        SET val = '99.999.999'
        WHERE titleId = ? 
        AND key = 'CONTENT_VERSION'
    """, (title_id,))
    print(f"Updated CONTENT_VERSION (rows affected: {cursor.rowcount})")

    cursor.execute("""
        UPDATE tbl_appinfo 
        SET val = 'http://127.0.0.2'
        WHERE titleId = ?
        AND key = 'VERSION_FILE_URI'
    """, (title_id,))
    print(f"Updated VERSION_FILE_URI (rows affected: {cursor.rowcount})")

conn.commit()

print("\nVerifying changes...")
for title_id in TITLE_IDS:
    print(f"\n  [{title_id}]")
    cursor.execute("""
        SELECT key, val 
        FROM tbl_appinfo 
        WHERE titleId = ? 
        AND key IN ('CONTENT_VERSION', 'VERSION_FILE_URI')
    """, (title_id,))
    for row in cursor.fetchall():
        print(f"    {row[0]}: {row[1]}")

conn.close()
print("\nChanges saved to appinfo.db")
print("Original backed up to appinfo.org.db")