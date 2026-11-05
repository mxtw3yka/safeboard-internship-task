import argparse
from pathlib import Path
import shlex
import hashlib
import json
import os
import psycopg
from db import create_schema
from load import load_feeds

def parse_version(s: str) -> tuple:
    clean_str = s.split('.')
    clean_str = tuple(map(int, clean_str))
    return clean_str



def find_product(cur, name):
    cur.execute("SELECT id FROM products WHERE LOWER(name_product) = LOWER(%s)", (name,))
    result = cur.fetchone()
    if result is not None:
        return result[0]
    return None


def version_in_range(v, start, fixed):
    cur_clear_version = parse_version(v)
    start_clear_version = parse_version(start)
    fixed_clear_version = parse_version(fixed)
    len_list = [len(cur_clear_version), len(start_clear_version), len(fixed_clear_version)]
    cur_clear_version += (0, ) * (max(len_list) - len(cur_clear_version))
    start_clear_version += (0, ) * (max(len_list) - len(start_clear_version))
    fixed_clear_version += (0, ) * (max(len_list) - len(fixed_clear_version))
    if start_clear_version <= cur_clear_version < fixed_clear_version:
        return True
    return False



def safe_versions(cur, product_id):
    cur.execute("SELECT version FROM versions WHERE product_id = %s", (product_id,))
    versions = cur.fetchall()
    cur.execute("SELECT start_vuln_version, fixed_version FROM article WHERE product_id = %s", (product_id,))
    not_safety_range = cur.fetchall()

    safe_version = []

    for row in versions:
        is_safe = True
        for range_row in not_safety_range:
            if version_in_range(row[0], range_row[0], range_row[1]) == True:
                is_safe = False
                break   
        if is_safe:
            safe_version.append(row[0])
    safe_version.sort(key=parse_version)
    return safe_version


def vulns_for_version(cur, product_id, version):
    cur.execute('SELECT kla_id, publish_date, description, start_vuln_version, fixed_version FROM article WHERE product_id = %s', (product_id,))
    row = cur.fetchall()
    result = []
    for r in row:
        if version_in_range(version, r[3], r[4]) == True:
            result.append(r[:3])
    return result


def run_query(cur, product, version):
    pid = find_product(cur, product)
    if pid is None:
        print(f'Продукт не найден: {product}')
        return 1

    if version is None:
        versions = safe_versions(cur, pid)
        if not versions:
            print('Среди версий фида безопасных нет')
        for v in versions:
            print(v)
    else:
        cur.execute('SELECT version FROM versions WHERE product_id = %s and version = %s', (pid, version))
        row = cur.fetchone()
        if row is not None:
            rows = vulns_for_version(cur, pid, version)
            for r in rows:
                print(r)
            if rows == []:
                print('Для этой версии уязвимости не найдены')
        if row is None:
            print("Версия не найдена в фиде")
            return 1
    return 0


def feed_hashes(path_to_vulns, path_to_versions):
    vuln_hash = hashlib.sha256(Path(path_to_vulns).read_bytes()).digest()
    version_hash = hashlib.sha256(Path(path_to_versions).read_bytes()).digest()
    return (vuln_hash, version_hash)

def run_repl(conn, path_to_vulns, path_to_versions, loaded_hashes):
    cur = conn.cursor()
    while True:
        try:
            line = input('safeboard> ')
            parts = shlex.split(line)
        except (KeyboardInterrupt, EOFError):
            break
        except ValueError as exc:
            print(f'Ошибка команды: {exc}')
            continue
        if len(parts) == 0:
            continue
        else:
            if len(parts) >= 2 and parts[0] == 'safe':
                product = ' '.join(parts[1:])
                version = None
            elif len(parts) >= 3 and parts[0] == 'vulns':
                product = ' '.join(parts[1:-1])
                version = parts[-1]
            else:
                print('Команды: safe Название продукта | vulns Название продукта версия')
                continue
        try:
            current_hashes = feed_hashes(path_to_vulns, path_to_versions)
            if current_hashes != loaded_hashes:
                loaded_hashes = load_feeds(conn, path_to_vulns, path_to_versions)
        except (OSError, json.JSONDecodeError, KeyError, psycopg.Error) as exc:
            print(f'Не удалось обновить фиды: {exc}')
            continue
        run_query(cur, product, version)

def main():
    parser = argparse.ArgumentParser(description='Поиск уязвимостей по фидам KLA')
    parser.add_argument('product', nargs='*')
    parser.add_argument('--version')
    parser.add_argument('--versions', required=True)
    parser.add_argument('--vulnerabilities', required=True)
    parser.add_argument('--repl', action='store_true')
    args = parser.parse_args()

    if not args.repl and not args.product:
        parser.error('Укажи продукт или используй --repl')

    conn = psycopg.connect(
        host=os.environ["DB_HOST"],
        dbname=os.environ["POSTGRES_DB"],
        user=os.environ["POSTGRES_USER"],
        password=os.environ["POSTGRES_PASSWORD"],
        autocommit=True,
    )
    try:    
        cur = conn.cursor() 
        create_schema(conn)
        curr_feeds = load_feeds(conn, args.vulnerabilities, args.versions)
        if args.repl:
            run_repl(conn, args.vulnerabilities, args.versions, curr_feeds)
            status = 0
        else:
            status = run_query(cur, ' '.join(args.product), args.version)
    finally:
        conn.close()
    return status


if __name__ == '__main__':
    raise SystemExit(main())
