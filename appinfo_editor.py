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
        print(f"Skipping {title_id}: Expected 2 keys but found {len(results)}")
        print(f"Found keys: {[row[0] for row in results]}")
        continue

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
    print(f"Changes committed for {title_id}")

print("\nVerifying changes...")
for title_id in TITLE_IDS:
    print(f"\n  [{title_id}]")
    cursor.execute("""
        SELECT key, val
        FROM tbl_appinfo
        WHERE titleId = ?
        AND key IN ('CONTENT_VERSION', 'VERSION_FILE_URI')
    """, (title_id,))
    rows = cursor.fetchall()

    if not rows:
        print("    No matching keys found.")
        continue

    for row in rows:
        print(f"    {row[0]}: {row[1]}")

conn.close()
print("\nDone.")
print("Original backed up to appinfo.org.db")
