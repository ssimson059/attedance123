"""Database layer.

Production target is MySQL (PyMySQL). Set DB_ENGINE=sqlite only for quick local
testing on a machine without MySQL; all SQL in the app is written to run on both.
"""
import os
import re
import sqlite3
from contextlib import contextmanager
from datetime import date, datetime
from decimal import Decimal

from flask import g

ENGINE = os.getenv("DB_ENGINE", "mysql").lower()
BASE = os.path.dirname(os.path.abspath(__file__))

MYSQL = dict(
    host=os.getenv("DB_HOST", "127.0.0.1"),
    port=int(os.getenv("DB_PORT", "3306")),
    user=os.getenv("DB_USER", "root"),
    password=os.getenv("DB_PASSWORD", ""),
    database=os.getenv("DB_NAME", "sincet_attendance"),
)
SQLITE_PATH = os.getenv("SQLITE_PATH", os.path.join(BASE, "sincet.db"))

if ENGINE == "mysql":
    import pymysql
    import pymysql.cursors


class DatabaseError(Exception):
    """Any database failure (connection, query)."""


class IntegrityViolation(DatabaseError):
    """Unique / foreign key violation."""


def _connect():
    try:
        if ENGINE == "mysql":
            return pymysql.connect(
                **MYSQL, charset="utf8mb4", autocommit=False,
                cursorclass=pymysql.cursors.DictCursor, connect_timeout=8,
            )
        conn = sqlite3.connect(SQLITE_PATH, timeout=10)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys=ON")
        return conn
    except Exception as exc:  # noqa: BLE001
        raise DatabaseError(f"Cannot connect to the database: {exc}") from exc


def get_db():
    if "db" not in g:
        g.db = _connect()
    return g.db


def close_db(_exc=None):
    conn = g.pop("db", None)
    if conn is not None:
        try:
            conn.close()
        except Exception:  # noqa: BLE001
            pass


def _adapt(sql):
    if ENGINE == "sqlite":
        sql = sql.replace("%s", "?")
        sql = re.sub(r"INSERT IGNORE", "INSERT OR IGNORE", sql, flags=re.I)
        sql = re.sub(r"\s+FOR UPDATE", "", sql, flags=re.I)
    return sql


def _clean(row):
    if row is None:
        return None
    out = {}
    for k, v in dict(row).items():
        if isinstance(v, (datetime, date)):
            v = v.strftime("%Y-%m-%d %H:%M:%S") if isinstance(v, datetime) else v.isoformat()
        elif isinstance(v, Decimal):
            v = float(v)
        out[k] = v
    return out


def _is_integrity(exc):
    if ENGINE == "mysql":
        return isinstance(exc, pymysql.err.IntegrityError)
    return isinstance(exc, sqlite3.IntegrityError)


def _run(sql, args, fetch):
    conn = get_db()
    try:
        cur = conn.cursor()
        cur.execute(_adapt(sql), args)
        if fetch == "all":
            result = [_clean(r) for r in cur.fetchall()]
        elif fetch == "one":
            result = _clean(cur.fetchone())
        else:
            result = cur.lastrowid if fetch == "insert" else cur.rowcount
        return result
    except Exception as exc:  # noqa: BLE001
        conn.rollback()
        if _is_integrity(exc):
            raise IntegrityViolation(str(exc)) from exc
        raise DatabaseError(str(exc)) from exc


def query(sql, args=()):
    return _run(sql, args, "all")


def query_one(sql, args=()):
    return _run(sql, args, "one")


def execute(sql, args=(), commit=True):
    rc = _run(sql, args, "rowcount")
    if commit:
        get_db().commit()
    return rc


def insert(sql, args=(), commit=True):
    rid = _run(sql, args, "insert")
    if commit:
        get_db().commit()
    return rid


def commit():
    try:
        get_db().commit()
    except Exception as exc:  # noqa: BLE001
        raise DatabaseError(str(exc)) from exc


def rollback():
    try:
        get_db().rollback()
    except Exception:  # noqa: BLE001
        pass


@contextmanager
def transaction():
    """Commit on success, roll back on any error."""
    try:
        yield
        commit()
    except Exception:
        rollback()
        raise


def init_db(app_logger=None):
    """Create database/tables and seed departments. Idempotent."""
    if ENGINE == "mysql":
        try:
            boot = pymysql.connect(
                host=MYSQL["host"], port=MYSQL["port"], user=MYSQL["user"],
                password=MYSQL["password"], charset="utf8mb4",
            )
            with boot.cursor() as cur:
                cur.execute(
                    f"CREATE DATABASE IF NOT EXISTS `{MYSQL['database']}` "
                    "CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci"
                )
            boot.commit()
            boot.close()
        except Exception as exc:  # noqa: BLE001
            raise DatabaseError(f"Cannot create database: {exc}") from exc

    with open(os.path.join(BASE, "schema.sql"), encoding="utf-8") as fh:
        schema = fh.read()
    if ENGINE == "sqlite":
        schema = schema.replace("INT AUTO_INCREMENT PRIMARY KEY", "INTEGER PRIMARY KEY AUTOINCREMENT")
    suffix = " ENGINE=InnoDB DEFAULT CHARSET=utf8mb4" if ENGINE == "mysql" else ""

    conn = _connect()
    try:
        cur = conn.cursor()
        for stmt in [s.strip() for s in schema.split(";") if s.strip()]:
            cur.execute(stmt + suffix)
        conn.commit()
        try:  # upgrade path for databases created by an earlier version
            cur.execute("ALTER TABLE class_sessions ADD COLUMN faculty_ip VARCHAR(45) NULL")
            conn.commit()
        except Exception:  # noqa: BLE001  (column already exists)
            conn.rollback()
    except Exception as exc:  # noqa: BLE001
        conn.rollback()
        raise DatabaseError(f"Schema creation failed: {exc}") from exc
    finally:
        conn.close()
