import json
from pathlib import Path
import hashlib

def load_feeds(conn, path_to_vuln, path_to_versions):
    cur = conn.cursor()
    vuln_bytes = Path(path_to_vuln).read_bytes()
    advisories = json.loads(vuln_bytes.decode('utf-8'))
    version_bytes = Path(path_to_versions).read_bytes()
    versions_rows = json.loads(version_bytes.decode('utf-8'))
    with conn.transaction():
        cur.execute(
        '''
        DELETE FROM article;
        '''
        )
        cur.execute(
        '''
        DELETE FROM versions;
        '''
        )
        cur.execute(
        '''
        DELETE FROM products;
        '''
        )

        pairs = {(r['vendor'], r['product']) for r in advisories} | {(r['vendor'], r['product']) for r in versions_rows}
        mapping = {}
        for vendor, product in pairs:
            cur.execute("INSERT INTO products (vendor, name_product) VALUES (%s, %s) RETURNING id", (vendor, product))
            mapping[(vendor, product)] = cur.fetchone()[0]

        rows = []
        for r in versions_rows:
            pid = mapping[(r['vendor'], r['product'])]
            rows.append((pid, r['version']))
        cur.executemany('INSERT INTO versions (product_id, version) VALUES (%s, %s)', rows)

        rows = []
        for r in advisories:
            pid = mapping[(r['vendor'], r['product'])]
            rows.append((pid, r['KLA_id'], r['description'], r['publish_date'],
                    r['start_vuln_version'], r['fixed_version']))

        cur.executemany('''INSERT INTO article
        (product_id, kla_id, description, publish_date, start_vuln_version, fixed_version)
        VALUES (%s, %s, %s, %s, %s, %s)''', rows)
    return (hashlib.sha256(vuln_bytes).digest(), hashlib.sha256(version_bytes).digest())

