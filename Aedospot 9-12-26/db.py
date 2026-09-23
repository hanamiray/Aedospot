"""
db.py — Drop-in replacement for sqlite3's connection/cursor, backed by
Supabase Postgres. app.py keeps using "?" placeholders, row[0] / row['col'],
cursor.lastrowid, and PRAGMA table_info(...) exactly like before — this file
translates all of that to Postgres under the hood.

Setup:
    pip install psycopg2-binary python-dotenv
    .env must have: SUPABASE_DB_URL=postgresql://postgres:yourpass@db.xxxx.supabase.co:5432/postgres
"""
import os
import re
import psycopg2
from dotenv import load_dotenv

load_dotenv()
PG_URL = os.environ.get("SUPABASE_DB_URL")
if not PG_URL:
    raise SystemExit(
        "Missing SUPABASE_DB_URL. Add it to your .env file.\n"
        "Example: SUPABASE_DB_URL=postgresql://postgres:yourpass@db.xxxx.supabase.co:5432/postgres"
    )

# NOTE: PG_URL already points at Supabase's connection pooler
# (aws-*.pooler.supabase.com), running in *session mode* — that pooler
# itself already caps concurrent clients at 15 (EMAXCONNSESSION). Running
# our own psycopg2 connection pool on top of that (as an earlier version of
# this file did) is actively harmful: it holds several persistent sessions
# checked out against that same 15-slot limit for the app's entire runtime,
# so it fills up even faster than connecting fresh per request. Because the
# pooler already does the real pooling, the correct pattern here is simply
# "open one connection per request/task, close it as soon as you're done" —
# exactly what get_db_connection() + `with ... as conn:` already give you.
# If you still see EMAXCONNSESSION after this, it almost always means a
# leftover/zombie python process (e.g. from a previous crashed run) is still
# holding sessions open — check Task Manager for old python.exe processes
# tied to this project and end them, or wait ~1 min for the pooler to reap
# idle sessions.

_PRAGMA_RE = re.compile(r"PRAGMA\s+table_info\(([\"']?)(\w+)\1\)", re.IGNORECASE)
_INSERT_RE = re.compile(r"^\s*INSERT\s+INTO\s+[\"']?(\w+)", re.IGNORECASE)

# Used to figure out which "?" placeholder maps to which column, so we can
# fix up Python int(1/0) vs bool(True/False) mismatches automatically (see
# _CursorWrapper._coerce_param_types below).
_INSERT_COLS_RE = re.compile(
    r"INSERT\s+INTO\s+[\"']?(\w+)[\"']?\s*\(([^)]+)\)\s*VALUES\s*\(([^)]+)\)",
    re.IGNORECASE | re.DOTALL,
)
_UPDATE_TABLE_RE = re.compile(r"UPDATE\s+[\"']?(\w+)[\"']?\s+SET", re.IGNORECASE)
_COL_EQ_PLACEHOLDER_RE = re.compile(r"[\"']?(\w+)[\"']?\s*=\s*\?")

# Cache of (table, column) -> Postgres data_type string, so we only ever hit
# information_schema once per column instead of on every request.
_COLUMN_TYPE_CACHE = {}


class Row:
    """Mimics sqlite3.Row: supports row[0], row['col'], and row.get('col')."""
    __slots__ = ("_values", "_cols")

    def __init__(self, values, cols):
        self._values = values
        self._cols = cols

    def __getitem__(self, key):
        if isinstance(key, str):
            return self._values[self._cols.index(key)]
        return self._values[key]

    def get(self, key, default=None):
        try:
            return self[key]
        except (ValueError, IndexError):
            return default

    def keys(self):
        return list(self._cols)

    def __iter__(self):
        return iter(self._values)

    def __len__(self):
        return len(self._values)

    def __repr__(self):
        return f"Row({dict(zip(self._cols, self._values))})"


class _CursorWrapper:
    def __init__(self, cur):
        self._cur = cur
        self.lastrowid = None

    def execute(self, query, params=None):
        pragma_match = _PRAGMA_RE.search(query)
        if pragma_match:
            table = pragma_match.group(2)
            self._cur.execute(
                "SELECT column_name FROM information_schema.columns "
                "WHERE table_name = %s ORDER BY ordinal_position",
                (table,),
            )
            names = [r[0] for r in self._cur.fetchall()]
            # Shape like sqlite PRAGMA table_info: (cid, name, type, notnull, dflt, pk)
            self._pragma_rows = [(i, n, None, 0, None, 0) for i, n in enumerate(names)]
            return self

        self._pragma_rows = None
        params = self._coerce_param_types(query, params)
        q = query.replace("?", "%s")
        q = q.replace("INTEGER PRIMARY KEY AUTOINCREMENT", "SERIAL PRIMARY KEY")

        insert_match = _INSERT_RE.match(q)
        wants_lastrowid = bool(insert_match) and "returning" not in q.lower()
        if wants_lastrowid:
            q = q.rstrip().rstrip(";") + " RETURNING id"

        self._cur.execute(q, params or ())

        if wants_lastrowid:
            row = self._cur.fetchone()
            self.lastrowid = row[0] if row else None
        return self

    def _coerce_param_types(self, query, params):
        """
        sqlite doesn't care whether you store a "boolean" as 0/1 or True/False —
        app.py was written against that and freely passes 1/0 ints for flags like
        email_enabled, sms_enabled, in_app_enabled. Postgres is strict: sending a
        Python int for a column that's actually `boolean` in the real Supabase
        table (very likely, since several of those columns were created/edited by
        hand in the Supabase table editor rather than through this file's
        ALTER TABLE calls) raises "column ... is of type boolean but expression
        is of type integer" and the whole request 500s — this is what was
        happening on notification-settings saves. This looks up each column's
        *actual* live Postgres type (cached after the first lookup) and
        transparently converts int<->bool so app.py doesn't need to know or
        care which one Supabase actually used.
        """
        if not params:
            return params

        params = list(params)
        table = None
        col_order = []

        insert_m = _INSERT_COLS_RE.search(query)
        update_m = _UPDATE_TABLE_RE.search(query)

        if insert_m:
            table = insert_m.group(1)
            cols = [c.strip().strip('"').strip("'") for c in insert_m.group(2).split(",")]
            placeholder_count = insert_m.group(3).count("?")
            col_order = cols[:placeholder_count]
        elif update_m:
            table = update_m.group(1)
            col_order = [m.group(1) for m in _COL_EQ_PLACEHOLDER_RE.finditer(query)]

        if not table or not col_order:
            return tuple(params)

        for i, col in enumerate(col_order):
            if i >= len(params):
                break
            val = params[i]
            # bool is a subclass of int in Python, so check bool first.
            if isinstance(val, bool):
                dtype = self._get_col_type(table, col)
                if dtype in ("integer", "smallint", "bigint"):
                    params[i] = int(val)
            elif isinstance(val, int):
                dtype = self._get_col_type(table, col)
                if dtype == "boolean":
                    params[i] = bool(val)

        return tuple(params)

    def _get_col_type(self, table, col):
        key = (table, col)
        if key in _COLUMN_TYPE_CACHE:
            return _COLUMN_TYPE_CACHE[key]
        dtype = None
        try:
            self._cur.execute(
                "SELECT data_type FROM information_schema.columns "
                "WHERE table_name = %s AND column_name = %s",
                (table, col),
            )
            row = self._cur.fetchone()
            dtype = row[0] if row else None
        except Exception:
            dtype = None
        _COLUMN_TYPE_CACHE[key] = dtype
        return dtype

    def executemany(self, query, seq_of_params):
        q = query.replace("?", "%s")
        self._cur.executemany(q, seq_of_params)
        return self

    def _wrap(self, raw):
        if raw is None:
            return None
        cols = [d[0] for d in self._cur.description] if self._cur.description else []
        return Row(raw, cols)

    def fetchone(self):
        if getattr(self, "_pragma_rows", None) is not None:
            return self._pragma_rows[0] if self._pragma_rows else None
        return self._wrap(self._cur.fetchone())

    def fetchall(self):
        if getattr(self, "_pragma_rows", None) is not None:
            return self._pragma_rows
        return [self._wrap(r) for r in self._cur.fetchall()]

    def __getattr__(self, name):
        return getattr(self._cur, name)


class _ConnWrapper:
    def __init__(self, conn):
        self._conn = conn
        self._closed = False

    def cursor(self):
        return _CursorWrapper(self._conn.cursor())

    def execute(self, query, params=None):
        c = self.cursor()
        c.execute(query, params)
        return c

    def commit(self):
        self._conn.commit()

    def close(self):
        # Actually releases this session back to Supabase's pooler so the
        # next get_db_connection() (or another process entirely) can use
        # that slot. Guarded so an accidental double-close (e.g. both an
        # explicit close() call and a `with` block's __exit__ running) never
        # raises on an already-closed connection.
        if not self._closed:
            self._closed = True
            self._conn.close()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if exc_type is None:
            self._conn.commit()
        else:
            # Leaving a failed transaction uncommitted before closing is
            # fine (the whole connection is going away), but rollback keeps
            # behavior predictable if this ever gets reused.
            try:
                self._conn.rollback()
            except Exception:
                pass
        self.close()


def get_db_connection():
    """Returns a Postgres (Supabase pooler) connection wrapped to behave like sqlite3.

    One real connection per call, closed by the caller (or by `with ... as conn:`)
    as soon as it's done — see the note above PG_URL for why we don't layer our
    own pool on top of Supabase's own session-mode pooler.
    """
    conn = psycopg2.connect(PG_URL)
    # Supabase/Postgres sessions default to UTC. Every CURRENT_TIMESTAMP default
    # in the schema (users.created_at, risk_alerts.created_at, notifications.created_at,
    # dismissed_notifications.created_at, etc.) gets its wall-clock value from the
    # session timezone. Left at UTC, "Joined" and every other timestamp shown to
    # admins/residents comes out 8 hours behind real Philippine time (e.g. a signup
    # at 12:20 PM PHT got stored/displayed as 04:20 AM). Setting the session timezone
    # here means CURRENT_TIMESTAMP always writes Manila wall-clock time, matching what
    # the frontend's "REAL TIME" clock and every `new Date(created_at)` call expect.
    with conn.cursor() as _cur:
        _cur.execute("SET TIME ZONE 'Asia/Manila'")
    conn.commit()
    return _ConnWrapper(conn)