import sqlite3
from datetime import datetime

from flask import current_app, g
from werkzeug.security import generate_password_hash

from app.checklist import TOOL_MATCH_RULES


def is_postgres():
    return bool(current_app.config.get("DATABASE_URL"))


def _postgres_sql(sql):
    return sql.replace("?", "%s")


def _normalize_bool(value):
    if value is None:
        return False
    if isinstance(value, bool):
        return value
    normalized = str(value).strip().lower()
    return normalized in {"1", "true", "yes", "y", "on"}


AUDIT_SCOPE_OFFICIAL = "oficial"
AUDIT_SCOPE_TESTING = "pruebas"


def normalize_audit_record_scope(value):
    normalized = (value or AUDIT_SCOPE_OFFICIAL).strip().lower()
    if normalized == AUDIT_SCOPE_TESTING:
        return AUDIT_SCOPE_TESTING
    return AUDIT_SCOPE_OFFICIAL


def get_audit_official_from_date():
    raw = (current_app.config.get("AUDIT_OFFICIAL_FROM_DATE") or "").strip()
    if not raw:
        return None
    try:
        return datetime.strptime(raw, "%Y-%m-%d").date().isoformat()
    except ValueError:
        return None


class PostgresConnection:
    def __init__(self, connection):
        self._connection = connection

    def execute(self, sql, params=None):
        cursor = self._connection.cursor()
        cursor.execute(_postgres_sql(sql), params or None)
        return cursor

    def executemany(self, sql, seq_of_params):
        cursor = self._connection.cursor()
        cursor.executemany(_postgres_sql(sql), seq_of_params)
        return cursor

    def commit(self):
        self._connection.commit()

    def close(self):
        self._connection.close()


def get_db():
    if "db_conn" not in g:
        if is_postgres():
            import psycopg
            from psycopg.rows import dict_row

            connection = psycopg.connect(current_app.config["DATABASE_URL"], row_factory=dict_row)
            g.db_conn = PostgresConnection(connection)
        else:
            connection = sqlite3.connect(current_app.config["DATABASE_PATH"])
            connection.row_factory = sqlite3.Row
            g.db_conn = connection
    return g.db_conn


def close_db(_error=None):
    connection = g.pop("db_conn", None)
    if connection is not None:
        connection.close()


def append_audit_visibility_filters(where_clauses, params, include_pruebas=False):
    if not _normalize_bool(include_pruebas):
        where_clauses.append("COALESCE(audits.record_scope, ?) = ?")
        params.extend([AUDIT_SCOPE_OFFICIAL, AUDIT_SCOPE_OFFICIAL])

        official_from_date = get_audit_official_from_date()
        if official_from_date:
            where_clauses.append("audits.audit_date >= ?")
            params.append(official_from_date)


def init_db():
    if is_postgres():
        init_db_postgres()
        return

    connection = sqlite3.connect(current_app.config["DATABASE_PATH"])
    connection.executescript(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            username TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'auditor',
            is_active INTEGER NOT NULL DEFAULT 1
        );

        CREATE TABLE IF NOT EXISTS technicians (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            employee_code TEXT NOT NULL UNIQUE,
            region TEXT NOT NULL,
            phone TEXT,
            commune TEXT,
            team TEXT,
            company_name TEXT,
            union_name TEXT,
            supervisor_name TEXT,
            center_name TEXT,
            is_active INTEGER NOT NULL DEFAULT 1
        );

        CREATE TABLE IF NOT EXISTS vehicles (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            plate TEXT NOT NULL UNIQUE,
            brand TEXT NOT NULL,
            model TEXT NOT NULL,
            year INTEGER,
            status TEXT NOT NULL DEFAULT 'activo',
            unit_number TEXT,
            odometer_km INTEGER,
            assigned_employee_code TEXT,
            review_date TEXT,
            insurance_expiry TEXT,
            extinguisher_expiry TEXT,
            gnc_expiry TEXT,
            rto_expiry TEXT,
            botiquin_expiry TEXT
        );

        CREATE TABLE IF NOT EXISTS mobile_units (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            mobile_code TEXT NOT NULL UNIQUE,
            technician_id INTEGER,
            user_name TEXT,
            warehouse_description TEXT,
            warehouse_type TEXT,
            is_enabled INTEGER NOT NULL DEFAULT 1,
            notes TEXT,
            FOREIGN KEY (technician_id) REFERENCES technicians (id)
        );

        CREATE TABLE IF NOT EXISTS storage_locations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            mobile_unit_id INTEGER NOT NULL,
            center_name TEXT NOT NULL,
            warehouse_code TEXT NOT NULL,
            warehouse_name TEXT NOT NULL,
            warehouse_type TEXT,
            user_name TEXT,
            is_enabled INTEGER NOT NULL DEFAULT 1,
            UNIQUE(center_name, warehouse_code),
            FOREIGN KEY (mobile_unit_id) REFERENCES mobile_units (id)
        );

        CREATE TABLE IF NOT EXISTS materials (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            material_code TEXT,
            material_name TEXT NOT NULL UNIQUE
        );

        CREATE TABLE IF NOT EXISTS material_stock (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            material_id INTEGER NOT NULL,
            mobile_unit_id INTEGER NOT NULL,
            quantity REAL NOT NULL DEFAULT 0,
            UNIQUE(material_id, mobile_unit_id),
            FOREIGN KEY (material_id) REFERENCES materials (id),
            FOREIGN KEY (mobile_unit_id) REFERENCES mobile_units (id)
        );

        CREATE TABLE IF NOT EXISTS equipment_inventory (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            storage_location_id INTEGER,
            mobile_unit_id INTEGER,
            center_name TEXT NOT NULL,
            warehouse_code TEXT NOT NULL,
            warehouse_name TEXT NOT NULL,
            material_code TEXT NOT NULL,
            material_name TEXT NOT NULL,
            serial_number TEXT NOT NULL UNIQUE,
            FOREIGN KEY (storage_location_id) REFERENCES storage_locations (id),
            FOREIGN KEY (mobile_unit_id) REFERENCES mobile_units (id)
        );

        CREATE TABLE IF NOT EXISTS audits (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            audit_date TEXT NOT NULL,
            auditor_name TEXT NOT NULL,
            sa_number TEXT,
            auditor_user_id INTEGER,
            auditor_signature_path TEXT,
            technician_signature_path TEXT,
            technician_display_name TEXT,
            technician_employee_code TEXT,
            location TEXT NOT NULL,
            installation_type TEXT NOT NULL,
            total_score REAL NOT NULL DEFAULT 0,
            result_status TEXT NOT NULL,
            record_scope TEXT NOT NULL DEFAULT 'oficial',
            general_notes TEXT,
            serialized_stock_status TEXT,
            serialized_stock_notes TEXT,
            material_stock_status TEXT,
            material_stock_notes TEXT,
            mobile_unit_id INTEGER,
            technician_id INTEGER,
            vehicle_id INTEGER NOT NULL,
            FOREIGN KEY (mobile_unit_id) REFERENCES mobile_units (id),
            FOREIGN KEY (technician_id) REFERENCES technicians (id),
            FOREIGN KEY (vehicle_id) REFERENCES vehicles (id),
            FOREIGN KEY (auditor_user_id) REFERENCES users (id)
        );

        CREATE TABLE IF NOT EXISTS audit_items (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            audit_id INTEGER NOT NULL,
            section_key TEXT NOT NULL,
            section_title TEXT NOT NULL,
            item_key TEXT NOT NULL,
            item_label TEXT NOT NULL,
            status TEXT NOT NULL,
            is_critical INTEGER NOT NULL DEFAULT 0,
            non_compliance_reason TEXT,
            notes TEXT,
            photo_path TEXT,
            FOREIGN KEY (audit_id) REFERENCES audits (id)
        );

        CREATE TABLE IF NOT EXISTS audit_supply_requests (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            audit_id INTEGER NOT NULL,
            section_key TEXT NOT NULL,
            section_title TEXT NOT NULL,
            item_key TEXT NOT NULL,
            item_label TEXT NOT NULL,
            request_type TEXT NOT NULL,
            material_code TEXT NOT NULL,
            quantity INTEGER,
            notes TEXT,
            FOREIGN KEY (audit_id) REFERENCES audits (id)
        );

        CREATE TABLE IF NOT EXISTS tnps_responses (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            response_date TEXT NOT NULL,
            score INTEGER NOT NULL CHECK(score >= 0 AND score <= 10),
            booking_ease_score INTEGER,
            punctuality_score INTEGER,
            communication_clarity_score INTEGER,
            issue_resolved_first_visit INTEGER,
            comment TEXT,
            customer_name TEXT,
            technician_id INTEGER,
            audit_id INTEGER,
            FOREIGN KEY (technician_id) REFERENCES technicians (id),
            FOREIGN KEY (audit_id) REFERENCES audits (id)
        );
        """
    )
    ensure_legacy_columns(connection)
    seed_demo_data(connection)
    ensure_mobile_unit_codes_normalized_sqlite(connection)
    connection.commit()
    connection.close()


def init_db_postgres():
    import psycopg
    from psycopg.rows import dict_row

    connection = psycopg.connect(current_app.config["DATABASE_URL"], row_factory=dict_row)
    cursor = connection.cursor()

    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            id SERIAL PRIMARY KEY,
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            username TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'auditor',
            is_active INTEGER NOT NULL DEFAULT 1
        )
        """
    )

    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS technicians (
            id SERIAL PRIMARY KEY,
            name TEXT NOT NULL,
            employee_code TEXT NOT NULL UNIQUE,
            region TEXT NOT NULL,
            phone TEXT,
            commune TEXT,
            team TEXT,
            company_name TEXT,
            union_name TEXT,
            supervisor_name TEXT,
            center_name TEXT,
            is_active INTEGER NOT NULL DEFAULT 1
        )
        """
    )

    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS vehicles (
            id SERIAL PRIMARY KEY,
            plate TEXT NOT NULL UNIQUE,
            brand TEXT NOT NULL,
            model TEXT NOT NULL,
            year INTEGER,
            status TEXT NOT NULL DEFAULT 'activo',
            unit_number TEXT,
            odometer_km INTEGER,
            assigned_employee_code TEXT,
            review_date TEXT,
            insurance_expiry TEXT,
            extinguisher_expiry TEXT,
            gnc_expiry TEXT,
            rto_expiry TEXT,
            botiquin_expiry TEXT
        )
        """
    )

    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS mobile_units (
            id SERIAL PRIMARY KEY,
            mobile_code TEXT NOT NULL UNIQUE,
            technician_id INTEGER REFERENCES technicians (id),
            user_name TEXT,
            warehouse_description TEXT,
            warehouse_type TEXT,
            is_enabled INTEGER NOT NULL DEFAULT 1,
            notes TEXT
        )
        """
    )

    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS storage_locations (
            id SERIAL PRIMARY KEY,
            mobile_unit_id INTEGER NOT NULL REFERENCES mobile_units (id),
            center_name TEXT NOT NULL,
            warehouse_code TEXT NOT NULL,
            warehouse_name TEXT NOT NULL,
            warehouse_type TEXT,
            user_name TEXT,
            is_enabled INTEGER NOT NULL DEFAULT 1,
            UNIQUE(center_name, warehouse_code)
        )
        """
    )

    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS materials (
            id SERIAL PRIMARY KEY,
            material_code TEXT,
            material_name TEXT NOT NULL UNIQUE
        )
        """
    )

    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS material_stock (
            id SERIAL PRIMARY KEY,
            material_id INTEGER NOT NULL REFERENCES materials (id),
            mobile_unit_id INTEGER NOT NULL REFERENCES mobile_units (id),
            quantity DOUBLE PRECISION NOT NULL DEFAULT 0,
            UNIQUE(material_id, mobile_unit_id)
        )
        """
    )

    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS equipment_inventory (
            id SERIAL PRIMARY KEY,
            storage_location_id INTEGER REFERENCES storage_locations (id),
            mobile_unit_id INTEGER REFERENCES mobile_units (id),
            center_name TEXT NOT NULL,
            warehouse_code TEXT NOT NULL,
            warehouse_name TEXT NOT NULL,
            material_code TEXT NOT NULL,
            material_name TEXT NOT NULL,
            serial_number TEXT NOT NULL UNIQUE
        )
        """
    )

    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS audits (
            id SERIAL PRIMARY KEY,
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            audit_date TEXT NOT NULL,
            auditor_name TEXT NOT NULL,
            sa_number TEXT,
            auditor_user_id INTEGER REFERENCES users (id),
            auditor_signature_path TEXT,
            technician_signature_path TEXT,
            technician_display_name TEXT,
            technician_employee_code TEXT,
            location TEXT NOT NULL,
            installation_type TEXT NOT NULL,
            total_score DOUBLE PRECISION NOT NULL DEFAULT 0,
            result_status TEXT NOT NULL,
            record_scope TEXT NOT NULL DEFAULT 'oficial',
            general_notes TEXT,
            serialized_stock_status TEXT,
            serialized_stock_notes TEXT,
            material_stock_status TEXT,
            material_stock_notes TEXT,
            mobile_unit_id INTEGER REFERENCES mobile_units (id),
            technician_id INTEGER REFERENCES technicians (id),
            vehicle_id INTEGER NOT NULL REFERENCES vehicles (id)
        )
        """
    )

    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS audit_items (
            id SERIAL PRIMARY KEY,
            audit_id INTEGER NOT NULL REFERENCES audits (id),
            section_key TEXT NOT NULL,
            section_title TEXT NOT NULL,
            item_key TEXT NOT NULL,
            item_label TEXT NOT NULL,
            status TEXT NOT NULL,
            is_critical INTEGER NOT NULL DEFAULT 0,
            non_compliance_reason TEXT,
            notes TEXT,
            photo_path TEXT
        )
        """
    )

    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS audit_supply_requests (
            id SERIAL PRIMARY KEY,
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            audit_id INTEGER NOT NULL REFERENCES audits (id),
            section_key TEXT NOT NULL,
            section_title TEXT NOT NULL,
            item_key TEXT NOT NULL,
            item_label TEXT NOT NULL,
            request_type TEXT NOT NULL,
            material_code TEXT NOT NULL,
            quantity INTEGER,
            notes TEXT
        )
        """
    )

    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS tnps_responses (
            id SERIAL PRIMARY KEY,
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            response_date TEXT NOT NULL,
            score INTEGER NOT NULL CHECK(score >= 0 AND score <= 10),
            booking_ease_score INTEGER,
            punctuality_score INTEGER,
            communication_clarity_score INTEGER,
            issue_resolved_first_visit INTEGER,
            comment TEXT,
            customer_name TEXT,
            technician_id INTEGER REFERENCES technicians (id),
            audit_id INTEGER REFERENCES audits (id)
        )
        """
    )

    ensure_technicians_columns_postgres(cursor)
    ensure_audits_columns_postgres(cursor)
    ensure_mobile_unit_codes_normalized_postgres(cursor)
    connection.commit()
    connection.close()


def count_users():
    row = get_db().execute("SELECT COUNT(*) AS user_count FROM users").fetchone()
    if not row:
        return 0
    return row["user_count"] if isinstance(row, dict) else row[0]


def fetch_user_by_id(user_id):
    row = get_db().execute(
        """
        SELECT id, username, password_hash, role, is_active
        FROM users
        WHERE id = ?
        """,
        (user_id,),
    ).fetchone()
    return dict(row) if row else None


def fetch_user_by_username(username):
    normalized = (username or "").strip()
    if not normalized:
        return None
    row = get_db().execute(
        """
        SELECT id, username, password_hash, role, is_active
        FROM users
        WHERE username = ?
        """,
        (normalized,),
    ).fetchone()
    return dict(row) if row else None


def fetch_users():
    created_at_expr = "created_at" if is_postgres() else "datetime(created_at, 'localtime')"
    rows = get_db().execute(
        f"""
        SELECT
            id,
            username,
            role,
            is_active,
            {created_at_expr} AS created_at
        FROM users
        ORDER BY username ASC
        """
    ).fetchall()
    return [dict(row) for row in rows]


def count_active_admins():
    row = get_db().execute(
        """
        SELECT COUNT(*) AS admin_count
        FROM users
        WHERE role = 'admin' AND is_active = 1
        """
    ).fetchone()
    if not row:
        return 0
    return row["admin_count"] if isinstance(row, dict) else row[0]


def create_user(username, password, role="auditor", is_active=1):
    normalized = (username or "").strip()
    if not normalized:
        raise ValueError("El usuario es obligatorio.")
    raw_password = (password or "").strip()
    if not raw_password:
        raise ValueError("La contraseña es obligatoria.")

    safe_role = (role or "auditor").strip().lower()
    if safe_role == "supervisor":
        safe_role = "admin"
    if safe_role not in {"admin", "auditor", "gerente"}:
        safe_role = "auditor"

    password_hash = generate_password_hash(raw_password)
    connection = get_db()
    insert_sql = """
        INSERT INTO users (username, password_hash, role, is_active)
        VALUES (?, ?, ?, ?)
        """
    insert_params = (normalized, password_hash, safe_role, 1 if is_active else 0)

    try:
        if is_postgres():
            cursor = connection.execute(insert_sql + " RETURNING id", insert_params)
            row = cursor.fetchone()
            connection.commit()
            return (row["id"] if isinstance(row, dict) else row[0]) if row else None

        cursor = connection.execute(insert_sql, insert_params)
        connection.commit()
        return cursor.lastrowid
    except Exception as exc:
        message = str(exc).lower()
        if "unique" in message or "duplicate" in message:
            raise ValueError("El usuario ya existe.") from exc
        raise


def update_user(user_id, username=None, password=None, role=None, is_active=None):
    existing = fetch_user_by_id(user_id)
    if not existing:
        return False

    normalized_username = (username or "").strip() if username is not None else existing["username"]
    if not normalized_username:
        raise ValueError("El usuario es obligatorio.")

    safe_role = (role or existing["role"] or "auditor").strip().lower()
    if safe_role == "supervisor":
        safe_role = "admin"
    if safe_role not in {"admin", "auditor", "gerente"}:
        safe_role = "auditor"

    active_value = existing["is_active"] if is_active is None else (1 if is_active else 0)

    password_hash = existing["password_hash"]
    if password is not None:
        raw_password = (password or "").strip()
        if not raw_password:
            raise ValueError("La contraseña no puede estar vacía.")
        password_hash = generate_password_hash(raw_password)

    connection = get_db()
    try:
        connection.execute(
            """
            UPDATE users
            SET username = ?, password_hash = ?, role = ?, is_active = ?
            WHERE id = ?
            """,
            (normalized_username, password_hash, safe_role, active_value, user_id),
        )
        connection.commit()
        return True
    except Exception as exc:
        message = str(exc).lower()
        if "unique" in message or "duplicate" in message:
            raise ValueError("El usuario ya existe.") from exc
        raise

def ensure_legacy_columns(connection):
    add_column_if_missing(connection, "technicians", "phone", "TEXT")
    add_column_if_missing(connection, "technicians", "commune", "TEXT")
    add_column_if_missing(connection, "technicians", "team", "TEXT")
    add_column_if_missing(connection, "technicians", "company_name", "TEXT")
    add_column_if_missing(connection, "technicians", "union_name", "TEXT")
    add_column_if_missing(connection, "technicians", "supervisor_name", "TEXT")
    add_column_if_missing(connection, "technicians", "center_name", "TEXT")
    add_column_if_missing(connection, "technicians", "is_active", "INTEGER NOT NULL DEFAULT 1")
    add_column_if_missing(connection, "vehicles", "year", "INTEGER")
    add_column_if_missing(connection, "vehicles", "status", "TEXT NOT NULL DEFAULT 'activo'")
    add_column_if_missing(connection, "vehicles", "unit_number", "TEXT")
    add_column_if_missing(connection, "vehicles", "odometer_km", "INTEGER")
    add_column_if_missing(connection, "vehicles", "assigned_employee_code", "TEXT")
    add_column_if_missing(connection, "vehicles", "review_date", "TEXT")
    add_column_if_missing(connection, "vehicles", "insurance_expiry", "TEXT")
    add_column_if_missing(connection, "vehicles", "extinguisher_expiry", "TEXT")
    add_column_if_missing(connection, "vehicles", "gnc_expiry", "TEXT")
    add_column_if_missing(connection, "vehicles", "rto_expiry", "TEXT")
    add_column_if_missing(connection, "vehicles", "botiquin_expiry", "TEXT")
    add_column_if_missing(connection, "mobile_units", "technician_id", "INTEGER")
    add_column_if_missing(connection, "mobile_units", "user_name", "TEXT")
    add_column_if_missing(connection, "mobile_units", "warehouse_description", "TEXT")
    add_column_if_missing(connection, "mobile_units", "warehouse_type", "TEXT")
    add_column_if_missing(connection, "mobile_units", "is_enabled", "INTEGER NOT NULL DEFAULT 1")
    add_column_if_missing(connection, "mobile_units", "notes", "TEXT")
    add_column_if_missing(connection, "materials", "material_code", "TEXT")
    add_column_if_missing(connection, "audits", "mobile_unit_id", "INTEGER")
    add_column_if_missing(connection, "audits", "auditor_user_id", "INTEGER")
    add_column_if_missing(connection, "audits", "sa_number", "TEXT")
    add_column_if_missing(connection, "audits", "auditor_signature_path", "TEXT")
    add_column_if_missing(connection, "audits", "technician_signature_path", "TEXT")
    add_column_if_missing(connection, "audits", "technician_display_name", "TEXT")
    add_column_if_missing(connection, "audits", "technician_employee_code", "TEXT")
    add_column_if_missing(connection, "audits", "record_scope", "TEXT NOT NULL DEFAULT 'oficial'")
    add_column_if_missing(connection, "audits", "serialized_stock_status", "TEXT")
    add_column_if_missing(connection, "audits", "serialized_stock_notes", "TEXT")
    add_column_if_missing(connection, "audits", "material_stock_status", "TEXT")
    add_column_if_missing(connection, "audits", "material_stock_notes", "TEXT")
    add_column_if_missing(connection, "audit_items", "non_compliance_reason", "TEXT")
    add_column_if_missing(connection, "audit_items", "photo_path", "TEXT")
    add_column_if_missing(connection, "tnps_responses", "booking_ease_score", "INTEGER")
    add_column_if_missing(connection, "tnps_responses", "punctuality_score", "INTEGER")
    add_column_if_missing(connection, "tnps_responses", "communication_clarity_score", "INTEGER")
    add_column_if_missing(connection, "tnps_responses", "issue_resolved_first_visit", "INTEGER")
    migrate_tnps_experience_scores_to_ten_scale(connection)
    ensure_audits_nullable_technician(connection)


def migrate_tnps_experience_scores_to_ten_scale(connection):
    def migrate_column(column_name):
        usage = connection.execute(
            f"""
            SELECT
                SUM(CASE WHEN {column_name} BETWEEN 1 AND 5 THEN 1 ELSE 0 END) AS low_count,
                SUM(CASE WHEN {column_name} BETWEEN 6 AND 10 THEN 1 ELSE 0 END) AS high_count
            FROM tnps_responses
            """
        ).fetchone()
        if not usage:
            return
        low_count = usage[0] or 0
        high_count = usage[1] or 0
        if low_count and not high_count:
            connection.execute(
                f"""
                UPDATE tnps_responses
                SET {column_name} = ({column_name} * 2)
                WHERE {column_name} BETWEEN 1 AND 5
                """
            )

    migrate_column("booking_ease_score")
    migrate_column("punctuality_score")
    migrate_column("communication_clarity_score")


def ensure_audits_nullable_technician(connection):
    rows = connection.execute("PRAGMA table_info(audits)").fetchall()
    columns = {row[1]: row for row in rows}
    technician_info = columns.get("technician_id")
    if not technician_info:
        return

    technician_notnull = technician_info[3] == 1
    if not technician_notnull:
        return

    connection.execute("PRAGMA foreign_keys = OFF")
    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS audits_new (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            audit_date TEXT NOT NULL,
            auditor_name TEXT NOT NULL,
            sa_number TEXT,
            auditor_user_id INTEGER,
            auditor_signature_path TEXT,
            technician_signature_path TEXT,
            technician_display_name TEXT,
            technician_employee_code TEXT,
            location TEXT NOT NULL,
            installation_type TEXT NOT NULL,
            total_score REAL NOT NULL DEFAULT 0,
            result_status TEXT NOT NULL,
            record_scope TEXT NOT NULL DEFAULT 'oficial',
            general_notes TEXT,
            serialized_stock_status TEXT,
            serialized_stock_notes TEXT,
            material_stock_status TEXT,
            material_stock_notes TEXT,
            mobile_unit_id INTEGER,
            technician_id INTEGER,
            vehicle_id INTEGER NOT NULL,
            FOREIGN KEY (mobile_unit_id) REFERENCES mobile_units (id),
            FOREIGN KEY (technician_id) REFERENCES technicians (id),
            FOREIGN KEY (vehicle_id) REFERENCES vehicles (id),
            FOREIGN KEY (auditor_user_id) REFERENCES users (id)
        )
        """
    )

    connection.execute(
        """
        INSERT INTO audits_new (
            id,
            created_at,
            audit_date,
            auditor_name,
            sa_number,
            auditor_user_id,
            auditor_signature_path,
            technician_signature_path,
            technician_display_name,
            technician_employee_code,
            location,
            installation_type,
            total_score,
            result_status,
            record_scope,
            general_notes,
            serialized_stock_status,
            serialized_stock_notes,
            material_stock_status,
            material_stock_notes,
            mobile_unit_id,
            technician_id,
            vehicle_id
        )
        SELECT
            id,
            created_at,
            audit_date,
            auditor_name,
            sa_number,
            auditor_user_id,
            auditor_signature_path,
            technician_signature_path,
            technician_display_name,
            technician_employee_code,
            location,
            installation_type,
            total_score,
            result_status,
            COALESCE(record_scope, 'oficial'),
            general_notes,
            serialized_stock_status,
            serialized_stock_notes,
            material_stock_status,
            material_stock_notes,
            mobile_unit_id,
            technician_id,
            vehicle_id
        FROM audits
        """
    )

    connection.execute("DROP TABLE audits")
    connection.execute("ALTER TABLE audits_new RENAME TO audits")
    connection.execute("PRAGMA foreign_keys = ON")

    connection.execute(
        """
        UPDATE audits
        SET
            technician_display_name = COALESCE(
                NULLIF(technician_display_name, ''),
                (SELECT technicians.name FROM technicians WHERE technicians.id = audits.technician_id)
            ),
            technician_employee_code = COALESCE(
                NULLIF(technician_employee_code, ''),
                (SELECT technicians.employee_code FROM technicians WHERE technicians.id = audits.technician_id)
            )
        WHERE technician_id IS NOT NULL
        """
    )


def add_column_if_missing(connection, table_name, column_name, column_definition):
    existing_columns = {
        row[1]
        for row in connection.execute(f"PRAGMA table_info({table_name})").fetchall()
    }
    if column_name not in existing_columns:
        connection.execute(
            f"ALTER TABLE {table_name} ADD COLUMN {column_name} {column_definition}"
        )


def ensure_technicians_columns_postgres(cursor):
    cursor.execute("ALTER TABLE technicians ADD COLUMN IF NOT EXISTS company_name TEXT")
    cursor.execute("ALTER TABLE technicians ADD COLUMN IF NOT EXISTS union_name TEXT")
    cursor.execute("ALTER TABLE technicians ADD COLUMN IF NOT EXISTS supervisor_name TEXT")
    cursor.execute("ALTER TABLE technicians ADD COLUMN IF NOT EXISTS center_name TEXT")


def ensure_audits_columns_postgres(cursor):
    cursor.execute("ALTER TABLE audits ADD COLUMN IF NOT EXISTS sa_number TEXT")
    cursor.execute("ALTER TABLE audits ADD COLUMN IF NOT EXISTS record_scope TEXT NOT NULL DEFAULT 'oficial'")


def ensure_mobile_unit_codes_normalized_sqlite(connection):
    mobile_rows = connection.execute(
        "SELECT id, mobile_code FROM mobile_units ORDER BY id ASC"
    ).fetchall()
    if not mobile_rows:
        return

    normalized_groups = {}
    for row in mobile_rows:
        mobile_id = row["id"] if hasattr(row, "keys") else row[0]
        mobile_code = row["mobile_code"] if hasattr(row, "keys") else row[1]
        normalized_code = normalize_mobile_code(mobile_code)
        if not normalized_code or normalized_code == mobile_code:
            continue
        normalized_groups.setdefault(normalized_code, []).append((mobile_id, mobile_code))

    for normalized_code, entries in normalized_groups.items():
        existing = connection.execute(
            "SELECT id FROM mobile_units WHERE mobile_code = ?",
            (normalized_code,),
        ).fetchone()
        keep_id = (existing["id"] if hasattr(existing, "keys") else existing[0]) if existing else entries[0][0]

        for source_id, _source_code in entries:
            if source_id == keep_id:
                continue
            merge_mobile_unit_into_sqlite(connection, source_id, keep_id)
            connection.execute("DELETE FROM mobile_units WHERE id = ?", (source_id,))

        connection.execute(
            "UPDATE mobile_units SET mobile_code = ? WHERE id = ?",
            (normalized_code, keep_id),
        )
        normalize_storage_location_codes_for_mobile_sqlite(connection, keep_id, normalized_code)


def ensure_mobile_unit_codes_normalized_postgres(cursor):
    cursor.execute("SELECT id, mobile_code FROM mobile_units ORDER BY id ASC")
    rows = cursor.fetchall()
    if not rows:
        return

    normalized_groups = {}
    for row in rows:
        normalized_code = normalize_mobile_code(row["mobile_code"])
        if not normalized_code or normalized_code == row["mobile_code"]:
            continue
        normalized_groups.setdefault(normalized_code, []).append((row["id"], row["mobile_code"]))

    for normalized_code, entries in normalized_groups.items():
        cursor.execute(
            "SELECT id FROM mobile_units WHERE mobile_code = %s",
            (normalized_code,),
        )
        existing = cursor.fetchone()
        keep_id = existing["id"] if existing else entries[0][0]

        for source_id, _source_code in entries:
            if source_id == keep_id:
                continue
            cursor.execute(
                "UPDATE audits SET mobile_unit_id = %s WHERE mobile_unit_id = %s",
                (keep_id, source_id),
            )
            cursor.execute(
                "UPDATE equipment_inventory SET mobile_unit_id = %s WHERE mobile_unit_id = %s",
                (keep_id, source_id),
            )
            cursor.execute(
                "UPDATE storage_locations SET mobile_unit_id = %s WHERE mobile_unit_id = %s",
                (keep_id, source_id),
            )

            cursor.execute(
                "SELECT material_id, quantity FROM material_stock WHERE mobile_unit_id = %s",
                (source_id,),
            )
            stock_rows = cursor.fetchall()
            for stock_row in stock_rows:
                material_id = stock_row["material_id"]
                source_qty = stock_row["quantity"] or 0
                cursor.execute(
                    """
                    SELECT id, quantity
                    FROM material_stock
                    WHERE mobile_unit_id = %s AND material_id = %s
                    """,
                    (keep_id, material_id),
                )
                existing_stock = cursor.fetchone()
                if existing_stock:
                    target_qty = existing_stock["quantity"] or 0
                    cursor.execute(
                        "UPDATE material_stock SET quantity = %s WHERE id = %s",
                        (target_qty + source_qty, existing_stock["id"]),
                    )
                    cursor.execute(
                        "DELETE FROM material_stock WHERE mobile_unit_id = %s AND material_id = %s",
                        (source_id, material_id),
                    )

            cursor.execute(
                "UPDATE material_stock SET mobile_unit_id = %s WHERE mobile_unit_id = %s",
                (keep_id, source_id),
            )
            cursor.execute("DELETE FROM mobile_units WHERE id = %s", (source_id,))

        cursor.execute(
            "UPDATE mobile_units SET mobile_code = %s WHERE id = %s",
            (normalized_code, keep_id),
        )
        cursor.execute(
            "UPDATE storage_locations SET warehouse_code = %s WHERE mobile_unit_id = %s",
            (normalized_code, keep_id),
        )


def merge_mobile_unit_into_sqlite(connection, source_id, target_id):
    connection.execute(
        "UPDATE audits SET mobile_unit_id = ? WHERE mobile_unit_id = ?",
        (target_id, source_id),
    )
    connection.execute(
        "UPDATE equipment_inventory SET mobile_unit_id = ? WHERE mobile_unit_id = ?",
        (target_id, source_id),
    )
    connection.execute(
        "UPDATE storage_locations SET mobile_unit_id = ? WHERE mobile_unit_id = ?",
        (target_id, source_id),
    )

    stock_rows = connection.execute(
        "SELECT material_id, quantity FROM material_stock WHERE mobile_unit_id = ?",
        (source_id,),
    ).fetchall()
    for row in stock_rows:
        material_id = row["material_id"] if hasattr(row, "keys") else row[0]
        source_qty = (row["quantity"] if hasattr(row, "keys") else row[1]) or 0
        existing = connection.execute(
            "SELECT id, quantity FROM material_stock WHERE mobile_unit_id = ? AND material_id = ?",
            (target_id, material_id),
        ).fetchone()
        if existing:
            existing_id = existing["id"] if hasattr(existing, "keys") else existing[0]
            target_qty = (existing["quantity"] if hasattr(existing, "keys") else existing[1]) or 0
            connection.execute(
                "UPDATE material_stock SET quantity = ? WHERE id = ?",
                (target_qty + source_qty, existing_id),
            )
            connection.execute(
                "DELETE FROM material_stock WHERE mobile_unit_id = ? AND material_id = ?",
                (source_id, material_id),
            )

    connection.execute(
        "UPDATE material_stock SET mobile_unit_id = ? WHERE mobile_unit_id = ?",
        (target_id, source_id),
    )


def normalize_storage_location_codes_for_mobile_sqlite(connection, mobile_unit_id, normalized_code):
    rows = connection.execute(
        """
        SELECT id, center_name, warehouse_code
        FROM storage_locations
        WHERE mobile_unit_id = ?
        """,
        (mobile_unit_id,),
    ).fetchall()
    for row in rows:
        storage_id = row["id"] if hasattr(row, "keys") else row[0]
        center_name = row["center_name"] if hasattr(row, "keys") else row[1]
        warehouse_code = row["warehouse_code"] if hasattr(row, "keys") else row[2]
        if warehouse_code == normalized_code:
            continue
        if normalize_mobile_code(warehouse_code) != normalized_code:
            continue

        conflict = connection.execute(
            """
            SELECT id
            FROM storage_locations
            WHERE center_name = ? AND warehouse_code = ? AND id != ?
            """,
            (center_name, normalized_code, storage_id),
        ).fetchone()
        if conflict:
            connection.execute("DELETE FROM storage_locations WHERE id = ?", (storage_id,))
        else:
            connection.execute(
                "UPDATE storage_locations SET warehouse_code = ? WHERE id = ?",
                (normalized_code, storage_id),
            )


def seed_demo_data(connection):
    technician_count = connection.execute("SELECT COUNT(*) FROM technicians").fetchone()[0]
    if technician_count == 0:
        connection.executemany(
            """
            INSERT INTO technicians (name, employee_code, region, phone, commune, team, is_active)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            [
                ("Carlos Mena", "TEC-001", "Valparaiso", "", "Valparaiso", "Cuadrilla Norte", 1),
                ("Pedro Soto", "TEC-002", "Quilpue", "", "Quilpue", "Cuadrilla Centro", 1),
            ],
        )

    vehicle_count = connection.execute("SELECT COUNT(*) FROM vehicles").fetchone()[0]
    if vehicle_count == 0:
        connection.executemany(
            """
            INSERT INTO vehicles (plate, brand, model, year, status, assigned_employee_code, review_date, insurance_expiry)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            [
                ("ABCD-11", "Peugeot", "Partner", 2022, "activo", "TEC-001", "", ""),
                ("EFGH-22", "Citroen", "Berlingo", 2021, "activo", "TEC-002", "", ""),
            ],
        )

    mobile_count = connection.execute("SELECT COUNT(*) FROM mobile_units").fetchone()[0]
    if mobile_count == 0:
        tech_1 = connection.execute(
            "SELECT id FROM technicians WHERE employee_code = ?",
            ("TEC-001",),
        ).fetchone()
        tech_2 = connection.execute(
            "SELECT id FROM technicians WHERE employee_code = ?",
            ("TEC-002",),
        ).fetchone()
        connection.executemany(
            """
            INSERT INTO mobile_units (
                mobile_code,
                technician_id,
                user_name,
                warehouse_description,
                warehouse_type,
                is_enabled,
                notes
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            [
                (
                    "M-001",
                    tech_1[0] if tech_1 else None,
                    "Usuario demo 1",
                    "Movil tecnico demo 1",
                    "movil",
                    1,
                    "",
                ),
                (
                    "M-002",
                    tech_2[0] if tech_2 else None,
                    "Usuario demo 2",
                    "Movil tecnico demo 2",
                    "movil",
                    1,
                    "",
                ),
            ],
        )


def fetch_technicians():
    rows = get_db().execute(
        """
        SELECT id, name, employee_code, region, phone, commune, team, company_name, union_name, supervisor_name, center_name, is_active
        FROM technicians
        ORDER BY name ASC
        """
    ).fetchall()
    return [dict(row) for row in rows]


def fetch_vehicles():
    rows = get_db().execute(
        """
        SELECT id, plate, brand, model, year, status, unit_number, odometer_km, assigned_employee_code, review_date, insurance_expiry, extinguisher_expiry, gnc_expiry, rto_expiry, botiquin_expiry
        FROM vehicles
        ORDER BY plate ASC
        """
    ).fetchall()
    return [dict(row) for row in rows]


def update_vehicle_extinguisher_expiry(vehicle_id, expiry_date):
    connection = get_db()
    connection.execute(
        "UPDATE vehicles SET extinguisher_expiry = ? WHERE id = ?",
        (expiry_date, vehicle_id),
    )
    connection.commit()


def update_vehicle_insurance_expiry(vehicle_id, expiry_date):
    connection = get_db()
    connection.execute(
        "UPDATE vehicles SET insurance_expiry = ? WHERE id = ?",
        (expiry_date, vehicle_id),
    )
    connection.commit()


def update_vehicle_gnc_expiry(vehicle_id, expiry_date):
    connection = get_db()
    connection.execute(
        "UPDATE vehicles SET gnc_expiry = ? WHERE id = ?",
        (expiry_date, vehicle_id),
    )
    connection.commit()


def update_vehicle_rto_expiry(vehicle_id, expiry_date):
    connection = get_db()
    connection.execute(
        "UPDATE vehicles SET rto_expiry = ? WHERE id = ?",
        (expiry_date, vehicle_id),
    )
    connection.commit()


def update_vehicle_botiquin_expiry(vehicle_id, expiry_date):
    connection = get_db()
    connection.execute(
        "UPDATE vehicles SET botiquin_expiry = ? WHERE id = ?",
        (expiry_date, vehicle_id),
    )
    connection.commit()


def fetch_mobile_units():
    rows = get_db().execute(
        """
        SELECT
            mobile_units.id,
            mobile_units.mobile_code,
            mobile_units.technician_id,
            mobile_units.user_name,
            mobile_units.warehouse_description,
            mobile_units.warehouse_type,
            mobile_units.is_enabled,
            mobile_units.notes,
            technicians.name AS technician_name,
            technicians.center_name AS technician_center_name,
            technicians.supervisor_name AS technician_supervisor_name,
            technicians.company_name AS technician_company_name,
            technicians.union_name AS technician_union_name,
            technicians.region AS technician_region,
            (
                SELECT storage_locations.center_name
                FROM storage_locations
                WHERE (
                    storage_locations.mobile_unit_id = mobile_units.id
                    OR storage_locations.warehouse_code = mobile_units.mobile_code
                )
                    AND storage_locations.is_enabled = 1
                ORDER BY
                    CASE WHEN LOWER(COALESCE(storage_locations.warehouse_type, '')) = 'movil' THEN 0 ELSE 1 END,
                    storage_locations.id DESC
                LIMIT 1
            ) AS storage_center_name,
            technicians.employee_code
        FROM mobile_units
        LEFT JOIN technicians ON technicians.id = mobile_units.technician_id
        ORDER BY mobile_units.mobile_code ASC
        """
    ).fetchall()
    return [dict(row) for row in rows]


def fetch_mobile_unit_detail(mobile_code):
    row = get_db().execute(
        """
        SELECT
            mobile_units.id,
            mobile_units.mobile_code,
            mobile_units.user_name,
            mobile_units.warehouse_description,
            mobile_units.warehouse_type,
            mobile_units.is_enabled,
            mobile_units.notes,
            mobile_units.technician_id,
            technicians.name AS technician_name,
            technicians.employee_code,
            technicians.phone,
            technicians.region,
            technicians.commune,
            technicians.team,
            technicians.company_name,
            technicians.union_name,
            technicians.supervisor_name,
            technicians.center_name
        FROM mobile_units
        LEFT JOIN technicians ON technicians.id = mobile_units.technician_id
        WHERE mobile_units.mobile_code = ?
        """,
        (mobile_code,),
    ).fetchone()
    return dict(row) if row else None


def fetch_mobile_unit_by_id(mobile_unit_id):
    row = get_db().execute(
        """
        SELECT
            mobile_units.id,
            mobile_units.mobile_code,
            mobile_units.user_name,
            mobile_units.warehouse_description,
            mobile_units.warehouse_type,
            mobile_units.is_enabled,
            mobile_units.notes,
            mobile_units.technician_id,
            technicians.name AS technician_name,
            technicians.employee_code
        FROM mobile_units
        LEFT JOIN technicians ON technicians.id = mobile_units.technician_id
        WHERE mobile_units.id = ?
        """,
        (mobile_unit_id,),
    ).fetchone()
    return dict(row) if row else None


def update_mobile_unit_technician(mobile_code, technician_id):
    connection = get_db()
    connection.execute(
        """
        UPDATE mobile_units
        SET technician_id = ?
        WHERE mobile_code = ?
        """,
        (technician_id, mobile_code),
    )
    connection.commit()


def fetch_mobile_overview_stats(mobile_code):
    row = get_db().execute(
        """
        SELECT
            (SELECT COUNT(*) FROM storage_locations WHERE storage_locations.warehouse_code = ?) AS storage_count,
            (SELECT COUNT(*) FROM equipment_inventory WHERE equipment_inventory.warehouse_code = ?) AS equipment_count,
            (
                SELECT COUNT(DISTINCT material_stock.material_id)
                FROM material_stock
                INNER JOIN mobile_units ON mobile_units.id = material_stock.mobile_unit_id
                WHERE mobile_units.mobile_code = ?
            ) AS materials_count,
            (
                SELECT COALESCE(SUM(material_stock.quantity), 0)
                FROM material_stock
                INNER JOIN mobile_units ON mobile_units.id = material_stock.mobile_unit_id
                WHERE mobile_units.mobile_code = ?
            ) AS stock_units_count
        """,
        (mobile_code, mobile_code, mobile_code, mobile_code),
    ).fetchone()
    return dict(row)


def fetch_mobile_storage_locations(mobile_code):
    rows = get_db().execute(
        """
        SELECT
            center_name,
            warehouse_code,
            warehouse_name,
            warehouse_type,
            user_name,
            is_enabled
        FROM storage_locations
        WHERE warehouse_code = ?
        ORDER BY center_name ASC, warehouse_name ASC
        """,
        (mobile_code,),
    ).fetchall()
    return [dict(row) for row in rows]


def fetch_mobile_equipment(mobile_code, limit=100):
    rows = get_db().execute(
        """
        SELECT
            center_name,
            warehouse_name,
            material_code,
            material_name,
            serial_number
        FROM equipment_inventory
        WHERE warehouse_code = ?
        ORDER BY material_name ASC, serial_number ASC
        LIMIT ?
        """,
        (mobile_code, limit),
    ).fetchall()
    return [dict(row) for row in rows]


def fetch_mobile_material_stock(mobile_code, limit=200):
    rows = get_db().execute(
        """
        SELECT
            materials.material_code,
            materials.material_name,
            material_stock.quantity
        FROM material_stock
        INNER JOIN materials ON materials.id = material_stock.material_id
        INNER JOIN mobile_units ON mobile_units.id = material_stock.mobile_unit_id
        WHERE mobile_units.mobile_code = ?
        ORDER BY materials.material_name ASC
        LIMIT ?
        """,
        (mobile_code, limit),
    ).fetchall()
    return [dict(row) for row in rows]


def fetch_mobile_related_audits(mobile_code, limit=20, auditor_user_id=None):
    mobile = fetch_mobile_unit_detail(mobile_code)
    technician_id = mobile["technician_id"] if mobile else None
    mobile_unit_id = mobile["id"] if mobile else None
    auditor_filter_sql = ""
    auditor_filter_params = ()
    if auditor_user_id is not None:
        auditor_filter_sql = " AND audits.auditor_user_id = ?"
        auditor_filter_params = (auditor_user_id,)

    visibility_filter_sql = " AND COALESCE(audits.record_scope, ?) = ?"
    visibility_filter_params = (AUDIT_SCOPE_OFFICIAL, AUDIT_SCOPE_OFFICIAL)

    official_from_date = get_audit_official_from_date()
    cutoff_sql = ""
    cutoff_params = ()
    if official_from_date:
        cutoff_sql = " AND audits.audit_date >= ?"
        cutoff_params = (official_from_date,)

    if technician_id is None:
        rows = get_db().execute(
            f"""
            SELECT
                audits.id,
                audits.audit_date,
                audits.location,
                audits.installation_type,
                audits.total_score,
                audits.result_status,
                audit_mobile.mobile_code,
                COALESCE(technicians.name, audits.technician_display_name) AS technician_name,
                vehicles.plate AS vehicle_plate
            FROM audits
            LEFT JOIN mobile_units AS audit_mobile ON audit_mobile.id = audits.mobile_unit_id
            LEFT JOIN technicians ON technicians.id = audits.technician_id
            INNER JOIN vehicles ON vehicles.id = audits.vehicle_id
            WHERE audits.mobile_unit_id = ?{visibility_filter_sql}{cutoff_sql}{auditor_filter_sql}
            ORDER BY audits.created_at DESC
            LIMIT ?
            """,
            (
                mobile_unit_id,
                *visibility_filter_params,
                *cutoff_params,
                *auditor_filter_params,
                limit,
            ),
        ).fetchall()
    else:
        rows = get_db().execute(
            f"""
            SELECT
                audits.id,
                audits.audit_date,
                audits.location,
                audits.installation_type,
                audits.total_score,
                audits.result_status,
                audit_mobile.mobile_code,
                COALESCE(technicians.name, audits.technician_display_name) AS technician_name,
                vehicles.plate AS vehicle_plate
            FROM audits
            LEFT JOIN mobile_units AS audit_mobile ON audit_mobile.id = audits.mobile_unit_id
            LEFT JOIN technicians ON technicians.id = audits.technician_id
            INNER JOIN vehicles ON vehicles.id = audits.vehicle_id
            WHERE (audits.mobile_unit_id = ? OR audits.technician_id = ?){visibility_filter_sql}{cutoff_sql}{auditor_filter_sql}
            ORDER BY audits.created_at DESC
            LIMIT ?
            """,
            (
                mobile_unit_id,
                technician_id,
                *visibility_filter_params,
                *cutoff_params,
                *auditor_filter_params,
                limit,
            ),
        ).fetchall()
    return [dict(row) for row in rows]


def fetch_mobile_audit_context(mobile_unit_id, equipment_limit=None, stock_limit=None):
    mobile = fetch_mobile_unit_by_id(mobile_unit_id)
    if not mobile:
        return None

    summary_row = get_db().execute(
        """
        SELECT
            (
                SELECT COUNT(*)
                FROM equipment_inventory
                WHERE mobile_unit_id = ?
            ) AS equipment_count,
            (
                SELECT COUNT(*)
                FROM material_stock
                WHERE mobile_unit_id = ?
            ) AS stock_item_count,
            (
                SELECT COALESCE(SUM(quantity), 0)
                FROM material_stock
                WHERE mobile_unit_id = ?
            ) AS stock_units_count
        """,
        (mobile_unit_id, mobile_unit_id, mobile_unit_id),
    ).fetchone()

    if equipment_limit is None:
        equipment_rows = get_db().execute(
            """
            SELECT
                center_name,
                warehouse_name,
                material_code,
                material_name,
                serial_number
            FROM equipment_inventory
            WHERE mobile_unit_id = ?
            ORDER BY material_name ASC, serial_number ASC
            """,
            (mobile_unit_id,),
        ).fetchall()
    else:
        equipment_rows = get_db().execute(
            """
            SELECT
                center_name,
                warehouse_name,
                material_code,
                material_name,
                serial_number
            FROM equipment_inventory
            WHERE mobile_unit_id = ?
            ORDER BY material_name ASC, serial_number ASC
            LIMIT ?
            """,
            (mobile_unit_id, equipment_limit),
        ).fetchall()

    if stock_limit is None:
        stock_rows = get_db().execute(
            """
            SELECT
                materials.material_code,
                materials.material_name,
                material_stock.quantity
            FROM material_stock
            INNER JOIN materials ON materials.id = material_stock.material_id
            WHERE material_stock.mobile_unit_id = ?
            ORDER BY materials.material_name ASC
            """,
            (mobile_unit_id,),
        ).fetchall()
    else:
        stock_rows = get_db().execute(
            """
            SELECT
                materials.material_code,
                materials.material_name,
                material_stock.quantity
            FROM material_stock
            INNER JOIN materials ON materials.id = material_stock.material_id
            WHERE material_stock.mobile_unit_id = ?
            ORDER BY materials.material_name ASC
            LIMIT ?
            """,
            (mobile_unit_id, stock_limit),
        ).fetchall()

    search_rows = get_db().execute(
        """
        SELECT material_name AS name
        FROM equipment_inventory
        WHERE mobile_unit_id = ?
        UNION ALL
        SELECT material_code AS name
        FROM equipment_inventory
        WHERE mobile_unit_id = ?
        UNION ALL
        SELECT materials.material_name AS name
        FROM material_stock
        INNER JOIN materials ON materials.id = material_stock.material_id
        WHERE material_stock.mobile_unit_id = ?
        UNION ALL
        SELECT materials.material_code AS name
        FROM material_stock
        INNER JOIN materials ON materials.id = material_stock.material_id
        WHERE material_stock.mobile_unit_id = ?
        """,
        (mobile_unit_id, mobile_unit_id, mobile_unit_id, mobile_unit_id),
    ).fetchall()

    summary = dict(summary_row)
    tool_matches = detect_tool_matches([row["name"] for row in search_rows])

    return {
        "mobile": mobile,
        "summary": summary,
        "equipment_rows": [dict(row) for row in equipment_rows],
        "_debug_equipment_rows": [dict(row) for row in equipment_rows], # DEBUG: Para inspeccionar los datos de seriales
        "stock_rows": [dict(row) for row in stock_rows],
        "tool_matches": tool_matches,
        "alerts": build_mobile_audit_alerts(mobile, summary, tool_matches),
    }


def fetch_vehicles_by_employee_code(employee_code):
    if not employee_code:
        return []

    rows = get_db().execute(
        """
        SELECT
            plate,
            brand,
            model,
            year,
            status,
            review_date,
            insurance_expiry
        FROM vehicles
        WHERE assigned_employee_code = ?
        ORDER BY plate ASC
        """,
        (employee_code,),
    ).fetchall()
    return [dict(row) for row in rows]


def fetch_materials_summary(limit=15):
    rows = get_db().execute(
        """
        SELECT
            materials.id,
            materials.material_code,
            materials.material_name,
            COALESCE(SUM(material_stock.quantity), 0) AS total_quantity,
            COUNT(DISTINCT material_stock.mobile_unit_id) AS mobile_count
        FROM materials
        LEFT JOIN material_stock ON material_stock.material_id = materials.id
        GROUP BY materials.id, materials.material_code, materials.material_name
        ORDER BY materials.material_name ASC
        LIMIT ?
        """,
        (limit,),
    ).fetchall()
    return [dict(row) for row in rows]


def fetch_material_catalog(limit=3000):
    rows = get_db().execute(
        """
        SELECT
            material_code,
            material_name
        FROM materials
        WHERE material_code IS NOT NULL AND material_code != ''
        ORDER BY material_name ASC
        LIMIT ?
        """,
        (limit,),
    ).fetchall()
    return [dict(row) for row in rows]


def fetch_material_by_code(material_code):
    code = (material_code or "").strip()
    if not code:
        return None
    row = get_db().execute(
        """
        SELECT material_code, material_name
        FROM materials
        WHERE material_code = ?
        LIMIT 1
        """,
        (code,),
    ).fetchone()
    return dict(row) if row else None


def fetch_storage_locations_summary(limit=15):
    rows = get_db().execute(
        """
        SELECT
            storage_locations.id,
            storage_locations.center_name,
            storage_locations.warehouse_code,
            storage_locations.warehouse_name,
            storage_locations.user_name,
            storage_locations.warehouse_type,
            storage_locations.is_enabled,
            mobile_units.mobile_code
        FROM storage_locations
        INNER JOIN mobile_units ON mobile_units.id = storage_locations.mobile_unit_id
        ORDER BY storage_locations.center_name ASC, storage_locations.warehouse_code ASC
        LIMIT ?
        """,
        (limit,),
    ).fetchall()
    return [dict(row) for row in rows]


def fetch_equipment_summary(limit=15):
    rows = get_db().execute(
        """
        SELECT
            center_name,
            warehouse_code,
            material_code,
            material_name,
            COUNT(*) AS serial_count
        FROM equipment_inventory
        GROUP BY center_name, warehouse_code, material_code, material_name
        ORDER BY serial_count DESC, material_name ASC
        LIMIT ?
        """,
        (limit,),
    ).fetchall()
    return [dict(row) for row in rows]


def fetch_storage_locations(filters=None):
    filters = filters or {}
    query = """
        SELECT
            storage_locations.id,
            storage_locations.center_name,
            storage_locations.warehouse_code,
            storage_locations.warehouse_name,
            storage_locations.user_name,
            storage_locations.warehouse_type,
            storage_locations.is_enabled,
            mobile_units.mobile_code
        FROM storage_locations
        INNER JOIN mobile_units ON mobile_units.id = storage_locations.mobile_unit_id
        WHERE 1 = 1
    """
    params = []

    search_term = (filters.get("q") or "").strip()
    if search_term:
        query += """
            AND (
                storage_locations.center_name LIKE ?
                OR storage_locations.warehouse_code LIKE ?
                OR storage_locations.warehouse_name LIKE ?
                OR storage_locations.user_name LIKE ?
                OR mobile_units.mobile_code LIKE ?
            )
        """
        like_value = f"%{search_term}%"
        params.extend([like_value, like_value, like_value, like_value, like_value])

    if filters.get("center"):
        query += " AND storage_locations.center_name = ?"
        params.append(filters["center"])

    if filters.get("warehouse_type"):
        query += " AND storage_locations.warehouse_type = ?"
        params.append(filters["warehouse_type"])

    if filters.get("enabled") in {"0", "1"}:
        query += " AND storage_locations.is_enabled = ?"
        params.append(int(filters["enabled"]))

    query += " ORDER BY storage_locations.center_name ASC, storage_locations.warehouse_code ASC"
    rows = get_db().execute(query, params).fetchall()
    return [dict(row) for row in rows]


def fetch_equipment_inventory(filters=None):
    filters = filters or {}
    query = """
        SELECT
            equipment_inventory.id,
            equipment_inventory.center_name,
            equipment_inventory.warehouse_code,
            equipment_inventory.warehouse_name,
            equipment_inventory.material_code,
            equipment_inventory.material_name,
            equipment_inventory.serial_number,
            mobile_units.mobile_code
        FROM equipment_inventory
        LEFT JOIN mobile_units ON mobile_units.id = equipment_inventory.mobile_unit_id
        WHERE 1 = 1
    """
    params = []

    search_term = (filters.get("q") or "").strip()
    if search_term:
        query += """
            AND (
                equipment_inventory.serial_number LIKE ?
                OR equipment_inventory.material_code LIKE ?
                OR equipment_inventory.material_name LIKE ?
                OR equipment_inventory.warehouse_code LIKE ?
                OR equipment_inventory.warehouse_name LIKE ?
            )
        """
        like_value = f"%{search_term}%"
        params.extend([like_value, like_value, like_value, like_value, like_value])

    if filters.get("center"):
        query += " AND equipment_inventory.center_name = ?"
        params.append(filters["center"])

    if filters.get("warehouse_code"):
        query += " AND equipment_inventory.warehouse_code = ?"
        params.append(filters["warehouse_code"])

    query += " ORDER BY equipment_inventory.center_name ASC, equipment_inventory.warehouse_code ASC, equipment_inventory.material_name ASC"
    rows = get_db().execute(query, params).fetchall()
    return [dict(row) for row in rows]


def fetch_material_stock_rows(filters=None):
    filters = filters or {}
    query = """
        SELECT
            materials.material_code,
            materials.material_name,
            mobile_units.mobile_code,
            material_stock.quantity,
            mobile_units.user_name,
            mobile_units.warehouse_description
        FROM material_stock
        INNER JOIN materials ON materials.id = material_stock.material_id
        INNER JOIN mobile_units ON mobile_units.id = material_stock.mobile_unit_id
        WHERE 1 = 1
    """
    params = []

    search_term = (filters.get("q") or "").strip()
    if search_term:
        query += """
            AND (
                materials.material_code LIKE ?
                OR materials.material_name LIKE ?
                OR mobile_units.mobile_code LIKE ?
                OR mobile_units.user_name LIKE ?
            )
        """
        like_value = f"%{search_term}%"
        params.extend([like_value, like_value, like_value, like_value])

    if filters.get("mobile_code"):
        query += " AND mobile_units.mobile_code = ?"
        params.append(filters["mobile_code"])

    query += " ORDER BY materials.material_name ASC, mobile_units.mobile_code ASC"
    rows = get_db().execute(query, params).fetchall()
    return [dict(row) for row in rows]


def fetch_distinct_storage_centers():
    rows = get_db().execute(
        "SELECT DISTINCT center_name FROM storage_locations ORDER BY center_name ASC"
    ).fetchall()
    return [row["center_name"] for row in rows]


def fetch_distinct_warehouse_types():
    rows = get_db().execute(
        """
        SELECT DISTINCT warehouse_type
        FROM storage_locations
        WHERE warehouse_type IS NOT NULL AND warehouse_type != ''
        ORDER BY warehouse_type ASC
        """
    ).fetchall()
    return [row["warehouse_type"] for row in rows]


def fetch_distinct_warehouse_codes():
    rows = get_db().execute(
        "SELECT DISTINCT warehouse_code FROM equipment_inventory ORDER BY warehouse_code ASC"
    ).fetchall()
    return [row["warehouse_code"] for row in rows]


def fetch_distinct_mobile_codes():
    rows = get_db().execute(
        "SELECT DISTINCT mobile_code FROM mobile_units ORDER BY mobile_code ASC"
    ).fetchall()
    return [row["mobile_code"] for row in rows]


def fetch_stock_stats():
    row = get_db().execute(
        """
        SELECT
            (SELECT COUNT(*) FROM materials) AS materials_count,
            (SELECT COUNT(*) FROM mobile_units) AS mobile_units_count,
            (SELECT COUNT(*) FROM storage_locations) AS storage_locations_count,
            (SELECT COUNT(*) FROM equipment_inventory) AS serialized_equipment_count,
            COALESCE((SELECT SUM(quantity) FROM material_stock), 0) AS stock_units_count
        """
    ).fetchone()
    return dict(row)


def fetch_dashboard_stats(auditor_user_id=None):
    where_clauses = []
    params = []

    append_audit_visibility_filters(where_clauses, params)

    if auditor_user_id is not None:
        where_clauses.append("audits.auditor_user_id = ?")
        params.append(auditor_user_id)

    where_sql = ""
    if where_clauses:
        where_sql = "WHERE " + " AND ".join(where_clauses)

    row = get_db().execute(
        f"""
        SELECT
            COUNT(*) AS total_audits,
            SUM(CASE WHEN result_status IN ('Aprobada', 'Aprobada con observaciones') THEN 1 ELSE 0 END) AS approved_count,
            SUM(CASE WHEN result_status = 'Critica' THEN 1 ELSE 0 END) AS critical_count
        FROM audits
        {where_sql}
        """,
        tuple(params),
    ).fetchone()

    total_audits = row["total_audits"] or 0
    approved_count = row["approved_count"] or 0
    critical_count = row["critical_count"] or 0
    approval_rate = 0 if total_audits == 0 else round((approved_count / total_audits) * 100)

    return {
        "total_audits": total_audits,
        "approved_count": approved_count,
        "critical_count": critical_count,
        "approval_rate": approval_rate,
    }


def create_tnps_response(
    response_date,
    score,
    booking_ease_score=None,
    punctuality_score=None,
    communication_clarity_score=None,
    issue_resolved_first_visit=None,
    comment=None,
    customer_name=None,
    technician_id=None,
    audit_id=None,
):
    connection = get_db()
    if audit_id is not None:
        existing = connection.execute(
            "SELECT id FROM tnps_responses WHERE audit_id = ? ORDER BY id DESC LIMIT 1",
            (audit_id,),
        ).fetchone()
        if existing:
            connection.execute(
                """
                UPDATE tnps_responses
                SET
                    response_date = ?,
                    score = ?,
                    booking_ease_score = ?,
                    punctuality_score = ?,
                    communication_clarity_score = ?,
                    issue_resolved_first_visit = ?,
                    comment = ?,
                    customer_name = ?,
                    technician_id = ?
                WHERE id = ?
                """,
                (
                    response_date,
                    score,
                    booking_ease_score,
                    punctuality_score,
                    communication_clarity_score,
                    issue_resolved_first_visit,
                    (comment or "").strip() or None,
                    (customer_name or "").strip() or None,
                    technician_id,
                    existing["id"],
                ),
            )
            connection.commit()
            return existing["id"]

    insert_sql = """
        INSERT INTO tnps_responses (
            response_date,
            score,
            booking_ease_score,
            punctuality_score,
            communication_clarity_score,
            issue_resolved_first_visit,
            comment,
            customer_name,
            technician_id,
            audit_id
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """
    insert_params = (
        response_date,
        score,
        booking_ease_score,
        punctuality_score,
        communication_clarity_score,
        issue_resolved_first_visit,
        (comment or "").strip() or None,
        (customer_name or "").strip() or None,
        technician_id,
        audit_id,
    )

    if is_postgres():
        cursor = connection.execute(insert_sql + " RETURNING id", insert_params)
        new_id_row = cursor.fetchone()
        connection.commit()
        if not new_id_row:
            return None
        return new_id_row["id"] if isinstance(new_id_row, dict) else new_id_row[0]

    cursor = connection.execute(insert_sql, insert_params)
    connection.commit()
    return cursor.lastrowid


def fetch_tnps_stats(filters=None):
    filters = filters or {}
    where_clauses = []
    params = []

    from_date = (filters.get("from_date") or "").strip()
    to_date = (filters.get("to_date") or "").strip()
    technician_id = filters.get("technician_id")

    if from_date:
        where_clauses.append("tnps_responses.response_date >= ?")
        params.append(from_date)
    if to_date:
        where_clauses.append("tnps_responses.response_date <= ?")
        params.append(to_date)
    if technician_id:
        where_clauses.append("tnps_responses.technician_id = ?")
        params.append(technician_id)

    where_sql = ""
    if where_clauses:
        where_sql = "WHERE " + " AND ".join(where_clauses)

    row = get_db().execute(
        f"""
        SELECT
            COUNT(*) AS total_responses,
            SUM(CASE WHEN score BETWEEN 9 AND 10 THEN 1 ELSE 0 END) AS promoters_count,
            SUM(CASE WHEN score BETWEEN 7 AND 8 THEN 1 ELSE 0 END) AS passives_count,
            SUM(CASE WHEN score BETWEEN 0 AND 6 THEN 1 ELSE 0 END) AS detractors_count,
            AVG(score) AS average_score
        FROM tnps_responses
        {where_sql}
        """,
        tuple(params),
    ).fetchone()

    total = row["total_responses"] or 0
    promoters = row["promoters_count"] or 0
    passives = row["passives_count"] or 0
    detractors = row["detractors_count"] or 0
    average_score = 0 if total == 0 else round((row["average_score"] or 0), 2)

    tnps_score = 0
    if total:
        tnps_score = round(((promoters / total) - (detractors / total)) * 100)

    return {
        "total_responses": total,
        "promoters_count": promoters,
        "passives_count": passives,
        "detractors_count": detractors,
        "average_score": average_score,
        "tnps_score": tnps_score,
    }


def fetch_tnps_responses(filters=None, limit=200):
    filters = filters or {}
    where_clauses = []
    params = []

    from_date = (filters.get("from_date") or "").strip()
    to_date = (filters.get("to_date") or "").strip()
    technician_id = filters.get("technician_id")

    if from_date:
        where_clauses.append("tnps_responses.response_date >= ?")
        params.append(from_date)
    if to_date:
        where_clauses.append("tnps_responses.response_date <= ?")
        params.append(to_date)
    if technician_id:
        where_clauses.append("tnps_responses.technician_id = ?")
        params.append(technician_id)

    where_sql = ""
    if where_clauses:
        where_sql = "WHERE " + " AND ".join(where_clauses)

    created_at_expr = (
        "tnps_responses.created_at"
        if is_postgres()
        else "datetime(tnps_responses.created_at, 'localtime')"
    )
    rows = get_db().execute(
        f"""
        SELECT
            tnps_responses.id,
            tnps_responses.response_date,
            tnps_responses.score,
            tnps_responses.booking_ease_score,
            tnps_responses.punctuality_score,
            tnps_responses.communication_clarity_score,
            tnps_responses.issue_resolved_first_visit,
            tnps_responses.comment,
            tnps_responses.customer_name,
            tnps_responses.audit_id,
            {created_at_expr} AS created_at,
            technicians.name AS technician_name,
            technicians.employee_code AS technician_employee_code
        FROM tnps_responses
        LEFT JOIN technicians ON technicians.id = tnps_responses.technician_id
        {where_sql}
        ORDER BY tnps_responses.response_date DESC, tnps_responses.id DESC
        LIMIT ?
        """,
        tuple(params + [limit]),
    ).fetchall()
    return [dict(row) for row in rows]


def fetch_tnps_response_for_audit(audit_id):
    created_at_expr = (
        "tnps_responses.created_at"
        if is_postgres()
        else "datetime(tnps_responses.created_at, 'localtime')"
    )
    row = get_db().execute(
        f"""
        SELECT
            tnps_responses.id,
            tnps_responses.response_date,
            tnps_responses.score,
            tnps_responses.booking_ease_score,
            tnps_responses.punctuality_score,
            tnps_responses.communication_clarity_score,
            tnps_responses.issue_resolved_first_visit,
            tnps_responses.comment,
            tnps_responses.customer_name,
            tnps_responses.audit_id,
            tnps_responses.technician_id,
            {created_at_expr} AS created_at,
            technicians.name AS technician_name,
            technicians.employee_code AS technician_employee_code
        FROM tnps_responses
        LEFT JOIN technicians ON technicians.id = tnps_responses.technician_id
        WHERE tnps_responses.audit_id = ?
        ORDER BY tnps_responses.id DESC
        LIMIT 1
        """,
        (audit_id,),
    ).fetchone()
    return dict(row) if row else None


def fetch_recent_audits(limit=5, auditor_user_id=None):
    where_clauses = []
    params = []

    append_audit_visibility_filters(where_clauses, params)

    if auditor_user_id is not None:
        where_clauses.append("audits.auditor_user_id = ?")
        params.append(auditor_user_id)

    where_sql = ""
    if where_clauses:
        where_sql = "WHERE " + " AND ".join(where_clauses)

    params.append(limit)
    rows = get_db().execute(
        f"""
        SELECT
            audits.id,
            audits.audit_date,
            audits.sa_number,
            audits.location,
            audits.installation_type,
            audits.total_score,
            audits.result_status,
            mobile_units.mobile_code,
            COALESCE(technicians.name, audits.technician_display_name) AS technician_name,
            vehicles.plate AS vehicle_plate
        FROM audits
        LEFT JOIN mobile_units ON mobile_units.id = audits.mobile_unit_id
        LEFT JOIN technicians ON technicians.id = audits.technician_id
        INNER JOIN vehicles ON vehicles.id = audits.vehicle_id
        {where_sql}
        ORDER BY audits.created_at DESC
        LIMIT ?
        """,
        tuple(params),
    ).fetchall()
    return [dict(row) for row in rows]


def fetch_all_audits(filters=None, auditor_user_id=None):
    where_sql, params = build_audits_where_sql(filters, auditor_user_id=auditor_user_id)
    rows = get_db().execute(
        f"""
        SELECT
            audits.id,
            audits.audit_date,
            audits.auditor_name,
            audits.auditor_user_id,
            audits.sa_number,
            audits.location,
            audits.installation_type,
            audits.total_score,
            audits.result_status,
            audits.record_scope,
            mobile_units.mobile_code,
            COALESCE(technicians.name, audits.technician_display_name) AS technician_name,
            vehicles.plate AS vehicle_plate
        FROM audits
        LEFT JOIN mobile_units ON mobile_units.id = audits.mobile_unit_id
        LEFT JOIN technicians ON technicians.id = audits.technician_id
        INNER JOIN vehicles ON vehicles.id = audits.vehicle_id
        {where_sql}
        ORDER BY audits.created_at DESC
        """,
        params,
    ).fetchall()
    return [dict(row) for row in rows]


def build_audit_picker_where_sql(filters=None, auditor_user_id=None):
    filters = filters or {}
    extra_clauses = []
    extra_params = []

    audit_id_raw = (filters.get("audit_id") or "").strip()
    if audit_id_raw:
        extra_clauses.append("audits.id = ?")
        extra_params.append(audit_id_raw)

    query = (filters.get("q") or "").strip()
    if query:
        like_value = f"%{query}%"
        if is_postgres():
            extra_clauses.append(
                "("
                "COALESCE(audits.sa_number, '') ILIKE ? OR "
                "CAST(audits.id AS TEXT) ILIKE ? OR "
                "COALESCE(mobile_units.mobile_code, '') ILIKE ? OR "
                "COALESCE(technicians.name, audits.technician_display_name, '') ILIKE ? OR "
                "COALESCE(vehicles.plate, '') ILIKE ? OR "
                "COALESCE(audits.location, '') ILIKE ?"
                ")"
            )
            extra_params.extend([like_value] * 6)
        else:
            extra_clauses.append(
                "("
                "LOWER(COALESCE(audits.sa_number, '')) LIKE ? OR "
                "LOWER(CAST(audits.id AS TEXT)) LIKE ? OR "
                "LOWER(COALESCE(mobile_units.mobile_code, '')) LIKE ? OR "
                "LOWER(COALESCE(technicians.name, audits.technician_display_name, '')) LIKE ? OR "
                "LOWER(COALESCE(vehicles.plate, '')) LIKE ? OR "
                "LOWER(COALESCE(audits.location, '')) LIKE ?"
                ")"
            )
            extra_params.extend([like_value.lower()] * 6)

    return build_audits_where_sql(
        filters,
        auditor_user_id=auditor_user_id,
        extra_clauses=extra_clauses,
        extra_params=extra_params,
    )


def count_audit_picker_audits(filters=None, auditor_user_id=None):
    where_sql, params = build_audit_picker_where_sql(filters, auditor_user_id=auditor_user_id)
    row = get_db().execute(
        f"""
        SELECT COUNT(*) AS audits_count
        FROM audits
        LEFT JOIN mobile_units ON mobile_units.id = audits.mobile_unit_id
        LEFT JOIN technicians ON technicians.id = audits.technician_id
        INNER JOIN vehicles ON vehicles.id = audits.vehicle_id
        {where_sql}
        """,
        params,
    ).fetchone()
    if not row:
        return 0
    return row["audits_count"] if isinstance(row, dict) else row[0]


def fetch_audit_picker_audits(filters=None, auditor_user_id=None, limit=25, offset=0):
    where_sql, params = build_audit_picker_where_sql(filters, auditor_user_id=auditor_user_id)
    rows = get_db().execute(
        f"""
        SELECT
            audits.id,
            audits.audit_date,
            audits.sa_number,
            audits.location,
            audits.installation_type,
            audits.total_score,
            audits.result_status,
            mobile_units.mobile_code,
            COALESCE(technicians.name, audits.technician_display_name) AS technician_name,
            vehicles.plate AS vehicle_plate
        FROM audits
        LEFT JOIN mobile_units ON mobile_units.id = audits.mobile_unit_id
        LEFT JOIN technicians ON technicians.id = audits.technician_id
        INNER JOIN vehicles ON vehicles.id = audits.vehicle_id
        {where_sql}
        ORDER BY audits.created_at DESC
        LIMIT ? OFFSET ?
        """,
        tuple(list(params) + [limit, offset]),
    ).fetchall()
    return [dict(row) for row in rows]


def build_audits_where_sql(filters=None, auditor_user_id=None, extra_clauses=None, extra_params=None):
    filters = filters or {}
    extra_clauses = extra_clauses or []
    extra_params = extra_params or []

    where_clauses = []
    params = []

    from_date = (filters.get("from_date") or "").strip()
    to_date = (filters.get("to_date") or "").strip()
    status = (filters.get("status") or "").strip()
    auditor = (filters.get("auditor") or "").strip()

    include_pruebas = _normalize_bool(filters.get("include_pruebas"))
    append_audit_visibility_filters(where_clauses, params, include_pruebas=include_pruebas)

    if from_date:
        where_clauses.append("audits.audit_date >= ?")
        params.append(from_date)

    if to_date:
        where_clauses.append("audits.audit_date <= ?")
        params.append(to_date)

    if status:
        where_clauses.append("audits.result_status = ?")
        params.append(status)

    if auditor:
        like_value = f"%{auditor}%"
        if is_postgres():
            where_clauses.append("COALESCE(audits.auditor_name, '') ILIKE ?")
            params.append(like_value)
        else:
            where_clauses.append("LOWER(COALESCE(audits.auditor_name, '')) LIKE ?")
            params.append(like_value.lower())

    if auditor_user_id is not None:
        where_clauses.append("audits.auditor_user_id = ?")
        params.append(auditor_user_id)

    if extra_clauses:
        where_clauses.extend(extra_clauses)
        params.extend(list(extra_params))

    where_sql = ""
    if where_clauses:
        where_sql = "WHERE " + " AND ".join(where_clauses)

    return where_sql, tuple(params)


def build_audits_where_sql_with_technicians(filters=None, auditor_user_id=None, extra_clauses=None, extra_params=None):
    filters = filters or {}
    extra_clauses = list(extra_clauses or [])
    extra_params = list(extra_params or [])

    supervisor = (filters.get("supervisor") or "").strip()
    if supervisor:
        if is_postgres():
            extra_clauses.append("COALESCE(technicians.supervisor_name, 'Sin supervisor') ILIKE ?")
            extra_params.append(supervisor)
        else:
            extra_clauses.append("LOWER(COALESCE(technicians.supervisor_name, 'Sin supervisor')) = ?")
            extra_params.append(supervisor.lower())

    return build_audits_where_sql(
        filters,
        auditor_user_id=auditor_user_id,
        extra_clauses=extra_clauses,
        extra_params=extra_params,
    )


def fetch_distinct_auditors():
    where_clauses = [
        "COALESCE(users.username, audits.auditor_name) IS NOT NULL",
        "COALESCE(users.username, audits.auditor_name) != ''",
    ]
    params = []
    append_audit_visibility_filters(where_clauses, params)
    where_sql = "WHERE " + " AND ".join(where_clauses)
    rows = get_db().execute(
        f"""
        SELECT DISTINCT COALESCE(users.username, audits.auditor_name) AS auditor_name
        FROM audits
        LEFT JOIN users ON users.id = audits.auditor_user_id
        {where_sql}
        ORDER BY auditor_name ASC
        """,
        tuple(params),
    ).fetchall()
    return [dict(row)["auditor_name"] for row in rows]


def fetch_audit_reports_management_summary(filters=None, auditor_user_id=None):
    where_sql, params = build_audits_where_sql(filters, auditor_user_id=auditor_user_id)
    row = get_db().execute(
        f"""
        SELECT
            COUNT(*) AS total_audits,
            SUM(CASE WHEN result_status IN ('Aprobada', 'Aprobada con observaciones') THEN 1 ELSE 0 END) AS approved_count,
            SUM(CASE WHEN result_status = 'Critica' THEN 1 ELSE 0 END) AS critical_count,
            SUM(CASE WHEN result_status = 'Rechazada' THEN 1 ELSE 0 END) AS rejected_count,
            AVG(total_score) AS average_score
        FROM audits
        {where_sql}
        """,
        params,
    ).fetchone()

    total_audits = row["total_audits"] or 0
    approved_count = row["approved_count"] or 0
    critical_count = row["critical_count"] or 0
    rejected_count = row["rejected_count"] or 0
    average_score = 0 if total_audits == 0 else round((row["average_score"] or 0), 2)
    approval_rate = 0 if total_audits == 0 else round((approved_count / total_audits) * 100)

    return {
        "total_audits": total_audits,
        "approved_count": approved_count,
        "critical_count": critical_count,
        "rejected_count": rejected_count,
        "approval_rate": approval_rate,
        "average_score": average_score,
    }


def fetch_audit_reports_status_breakdown(filters=None, auditor_user_id=None):
    where_sql, params = build_audits_where_sql(filters, auditor_user_id=auditor_user_id)
    rows = get_db().execute(
        f"""
        SELECT
            audits.result_status,
            COUNT(*) AS audits_count,
            AVG(audits.total_score) AS average_score
        FROM audits
        {where_sql}
        GROUP BY audits.result_status
        ORDER BY audits_count DESC, audits.result_status ASC
        """,
        params,
    ).fetchall()

    breakdown = []
    for row in rows:
        breakdown.append(
            {
                "result_status": row["result_status"],
                "audits_count": row["audits_count"] or 0,
                "average_score": round((row["average_score"] or 0), 2),
            }
        )
    return breakdown


def fetch_audit_reports_supervisor_breakdown(filters=None, auditor_user_id=None, limit=500):
    where_sql, params = build_audits_where_sql_with_technicians(filters, auditor_user_id=auditor_user_id)
    label_expr = "COALESCE(technicians.supervisor_name, 'Sin supervisor')"
    rows = get_db().execute(
        f"""
        WITH audits_base AS (
            SELECT
                audits.id AS audit_id,
                audits.result_status,
                audits.total_score,
                audits.audit_date,
                {label_expr} AS supervisor_name
            FROM audits
            LEFT JOIN technicians ON technicians.id = audits.technician_id
            {where_sql}
        ),
        supervisor_reasons_per_audit AS (
            SELECT
                audit_items.audit_id,
                SUM(
                    CASE
                        WHEN audit_items.status = 'no_cumple'
                         AND LOWER(COALESCE(audit_items.non_compliance_reason, '')) = 'no_asignado'
                        THEN 1 ELSE 0
                    END
                ) AS no_asignado_items_count,
                MAX(
                    CASE
                        WHEN audit_items.status = 'no_cumple'
                         AND LOWER(COALESCE(audit_items.non_compliance_reason, '')) = 'no_asignado'
                        THEN 1 ELSE 0
                    END
                ) AS audits_with_no_asignado
                ,
                SUM(
                    CASE
                        WHEN audit_items.status = 'no_cumple'
                         AND LOWER(COALESCE(audit_items.non_compliance_reason, '')) = 'vencido'
                        THEN 1 ELSE 0
                    END
                ) AS vencido_items_count,
                MAX(
                    CASE
                        WHEN audit_items.status = 'no_cumple'
                         AND LOWER(COALESCE(audit_items.non_compliance_reason, '')) = 'vencido'
                        THEN 1 ELSE 0
                    END
                ) AS audits_with_vencido
                ,
                SUM(
                    CASE
                        WHEN audit_items.status = 'no_cumple'
                         AND LOWER(COALESCE(audit_items.non_compliance_reason, '')) = 'no_apta_para_el_uso'
                        THEN 1 ELSE 0
                    END
                ) AS no_apta_items_count,
                MAX(
                    CASE
                        WHEN audit_items.status = 'no_cumple'
                         AND LOWER(COALESCE(audit_items.non_compliance_reason, '')) = 'no_apta_para_el_uso'
                        THEN 1 ELSE 0
                    END
                ) AS audits_with_no_apta
            FROM audit_items
            GROUP BY audit_items.audit_id
        )
        SELECT
            audits_base.supervisor_name,
            COUNT(*) AS audits_count,
            SUM(CASE WHEN audits_base.result_status IN ('Aprobada', 'Aprobada con observaciones') THEN 1 ELSE 0 END) AS approved_count,
            SUM(CASE WHEN audits_base.result_status = 'Critica' THEN 1 ELSE 0 END) AS critical_count,
            SUM(CASE WHEN audits_base.result_status = 'Rechazada' THEN 1 ELSE 0 END) AS rejected_count,
            AVG(audits_base.total_score) AS average_score,
            MAX(audits_base.audit_date) AS last_audit_date,
            SUM(COALESCE(supervisor_reasons_per_audit.no_asignado_items_count, 0)) AS no_asignado_items_count,
            SUM(COALESCE(supervisor_reasons_per_audit.audits_with_no_asignado, 0)) AS audits_with_no_asignado,
            SUM(COALESCE(supervisor_reasons_per_audit.vencido_items_count, 0)) AS vencido_items_count,
            SUM(COALESCE(supervisor_reasons_per_audit.audits_with_vencido, 0)) AS audits_with_vencido,
            SUM(COALESCE(supervisor_reasons_per_audit.no_apta_items_count, 0)) AS no_apta_items_count,
            SUM(COALESCE(supervisor_reasons_per_audit.audits_with_no_apta, 0)) AS audits_with_no_apta
        FROM audits_base
        LEFT JOIN supervisor_reasons_per_audit ON supervisor_reasons_per_audit.audit_id = audits_base.audit_id
        GROUP BY audits_base.supervisor_name
        ORDER BY critical_count DESC, rejected_count DESC, audits_count DESC, audits_base.supervisor_name ASC
        LIMIT ?
        """,
        tuple(list(params) + [limit]),
    ).fetchall()
    breakdown = []
    for row in rows:
        total = row["audits_count"] or 0
        approved = row["approved_count"] or 0
        critical = row["critical_count"] or 0
        rejected = row["rejected_count"] or 0
        audits_with_no_asignado = row["audits_with_no_asignado"] or 0
        no_asignado_items_count = row["no_asignado_items_count"] or 0
        audits_with_vencido = row["audits_with_vencido"] or 0
        vencido_items_count = row["vencido_items_count"] or 0
        audits_with_no_apta = row["audits_with_no_apta"] or 0
        no_apta_items_count = row["no_apta_items_count"] or 0
        risk_index = (
            0
            if total == 0
            else round(
                (((critical * 2) + rejected + audits_with_no_asignado + audits_with_vencido + audits_with_no_apta) / total)
                * 100,
                1,
            )
        )
        breakdown.append(
            {
                "supervisor_name": row["supervisor_name"] or "Sin supervisor",
                "audits_count": total,
                "approved_count": approved,
                "critical_count": critical,
                "rejected_count": rejected,
                "approval_rate": 0 if total == 0 else round((approved / total) * 100),
                "critical_rate": 0 if total == 0 else round((critical / total) * 100),
                "rejected_rate": 0 if total == 0 else round((rejected / total) * 100),
                "no_asignado_audits": audits_with_no_asignado,
                "no_asignado_rate": 0 if total == 0 else round((audits_with_no_asignado / total) * 100),
                "no_asignado_items_count": no_asignado_items_count,
                "vencido_audits": audits_with_vencido,
                "vencido_rate": 0 if total == 0 else round((audits_with_vencido / total) * 100),
                "vencido_items_count": vencido_items_count,
                "no_apta_audits": audits_with_no_apta,
                "no_apta_rate": 0 if total == 0 else round((audits_with_no_apta / total) * 100),
                "no_apta_items_count": no_apta_items_count,
                "risk_index": risk_index,
                "average_score": 0 if total == 0 else round((row["average_score"] or 0), 2),
                "last_audit_date": row["last_audit_date"],
            }
        )
    return breakdown


def fetch_audit_reports_center_breakdown(filters=None, auditor_user_id=None, limit=500):
    where_sql, params = build_audits_where_sql(filters, auditor_user_id=auditor_user_id)
    label_expr = "COALESCE(technicians.center_name, 'Sin centro')"
    rows = get_db().execute(
        f"""
        SELECT
            {label_expr} AS center_name,
            COUNT(*) AS audits_count,
            SUM(CASE WHEN audits.result_status IN ('Aprobada', 'Aprobada con observaciones') THEN 1 ELSE 0 END) AS approved_count,
            SUM(CASE WHEN audits.result_status = 'Critica' THEN 1 ELSE 0 END) AS critical_count,
            SUM(CASE WHEN audits.result_status = 'Rechazada' THEN 1 ELSE 0 END) AS rejected_count,
            AVG(audits.total_score) AS average_score,
            MAX(audits.audit_date) AS last_audit_date
        FROM audits
        LEFT JOIN technicians ON technicians.id = audits.technician_id
        {where_sql}
        GROUP BY {label_expr}
        ORDER BY audits_count DESC, {label_expr} ASC
        LIMIT ?
        """,
        tuple(list(params) + [limit]),
    ).fetchall()
    breakdown = []
    for row in rows:
        total = row["audits_count"] or 0
        approved = row["approved_count"] or 0
        breakdown.append(
            {
                "center_name": row["center_name"] or "Sin centro",
                "audits_count": total,
                "approved_count": approved,
                "critical_count": row["critical_count"] or 0,
                "rejected_count": row["rejected_count"] or 0,
                "approval_rate": 0 if total == 0 else round((approved / total) * 100),
                "average_score": 0 if total == 0 else round((row["average_score"] or 0), 2),
                "last_audit_date": row["last_audit_date"],
            }
        )
    return breakdown


def fetch_audit_reports_company_breakdown(filters=None, auditor_user_id=None, limit=500):
    where_sql, params = build_audits_where_sql(filters, auditor_user_id=auditor_user_id)
    label_expr = "COALESCE(technicians.company_name, 'Sin empresa')"
    rows = get_db().execute(
        f"""
        SELECT
            {label_expr} AS company_name,
            COUNT(*) AS audits_count,
            SUM(CASE WHEN audits.result_status IN ('Aprobada', 'Aprobada con observaciones') THEN 1 ELSE 0 END) AS approved_count,
            SUM(CASE WHEN audits.result_status = 'Critica' THEN 1 ELSE 0 END) AS critical_count,
            SUM(CASE WHEN audits.result_status = 'Rechazada' THEN 1 ELSE 0 END) AS rejected_count,
            AVG(audits.total_score) AS average_score,
            MAX(audits.audit_date) AS last_audit_date
        FROM audits
        LEFT JOIN technicians ON technicians.id = audits.technician_id
        {where_sql}
        GROUP BY {label_expr}
        ORDER BY audits_count DESC, {label_expr} ASC
        LIMIT ?
        """,
        tuple(list(params) + [limit]),
    ).fetchall()
    breakdown = []
    for row in rows:
        total = row["audits_count"] or 0
        approved = row["approved_count"] or 0
        breakdown.append(
            {
                "company_name": row["company_name"] or "Sin empresa",
                "audits_count": total,
                "approved_count": approved,
                "critical_count": row["critical_count"] or 0,
                "rejected_count": row["rejected_count"] or 0,
                "approval_rate": 0 if total == 0 else round((approved / total) * 100),
                "average_score": 0 if total == 0 else round((row["average_score"] or 0), 2),
                "last_audit_date": row["last_audit_date"],
            }
        )
    return breakdown


def fetch_audit_reports_technician_ranking(filters=None, auditor_user_id=None, limit=200):
    where_sql, params = build_audits_where_sql(filters, auditor_user_id=auditor_user_id)
    name_expr = "COALESCE(technicians.name, audits.technician_display_name, 'Sin técnico')"
    employee_expr = "COALESCE(technicians.employee_code, audits.technician_employee_code, '')"
    supervisor_expr = "COALESCE(technicians.supervisor_name, '')"
    center_expr = "COALESCE(technicians.center_name, '')"
    company_expr = "COALESCE(technicians.company_name, '')"
    rows = get_db().execute(
        f"""
        SELECT
            {name_expr} AS technician_name,
            {employee_expr} AS technician_employee_code,
            {supervisor_expr} AS supervisor_name,
            {center_expr} AS center_name,
            {company_expr} AS company_name,
            COUNT(*) AS audits_count,
            SUM(CASE WHEN audits.result_status IN ('Aprobada', 'Aprobada con observaciones') THEN 1 ELSE 0 END) AS approved_count,
            SUM(CASE WHEN audits.result_status = 'Critica' THEN 1 ELSE 0 END) AS critical_count,
            SUM(CASE WHEN audits.result_status = 'Rechazada' THEN 1 ELSE 0 END) AS rejected_count,
            AVG(audits.total_score) AS average_score,
            MAX(audits.audit_date) AS last_audit_date
        FROM audits
        LEFT JOIN technicians ON technicians.id = audits.technician_id
        {where_sql}
        GROUP BY {name_expr}, {employee_expr}, {supervisor_expr}, {center_expr}, {company_expr}
        ORDER BY critical_count DESC, audits_count DESC, average_score ASC, {name_expr} ASC
        LIMIT ?
        """,
        tuple(list(params) + [limit]),
    ).fetchall()
    ranking = []
    for row in rows:
        total = row["audits_count"] or 0
        approved = row["approved_count"] or 0
        ranking.append(
            {
                "technician_name": row["technician_name"] or "Sin técnico",
                "technician_employee_code": row["technician_employee_code"] or "",
                "supervisor_name": row["supervisor_name"] or "",
                "center_name": row["center_name"] or "",
                "company_name": row["company_name"] or "",
                "audits_count": total,
                "approved_count": approved,
                "critical_count": row["critical_count"] or 0,
                "rejected_count": row["rejected_count"] or 0,
                "approval_rate": 0 if total == 0 else round((approved / total) * 100),
                "average_score": 0 if total == 0 else round((row["average_score"] or 0), 2),
                "last_audit_date": row["last_audit_date"],
            }
        )
    return ranking


def fetch_audit_reports_mobile_ranking(filters=None, auditor_user_id=None, limit=200):
    where_sql, params = build_audits_where_sql(filters, auditor_user_id=auditor_user_id)
    rows = get_db().execute(
        f"""
        SELECT
            COALESCE(mobile_units.mobile_code, 'Sin móvil') AS mobile_code,
            COUNT(*) AS audits_count,
            SUM(CASE WHEN audits.result_status IN ('Aprobada', 'Aprobada con observaciones') THEN 1 ELSE 0 END) AS approved_count,
            SUM(CASE WHEN audits.result_status = 'Critica' THEN 1 ELSE 0 END) AS critical_count,
            SUM(CASE WHEN audits.result_status = 'Rechazada' THEN 1 ELSE 0 END) AS rejected_count,
            AVG(audits.total_score) AS average_score,
            MAX(audits.audit_date) AS last_audit_date
        FROM audits
        LEFT JOIN mobile_units ON mobile_units.id = audits.mobile_unit_id
        {where_sql}
        GROUP BY COALESCE(mobile_units.mobile_code, 'Sin móvil')
        ORDER BY critical_count DESC, audits_count DESC, average_score ASC, COALESCE(mobile_units.mobile_code, 'Sin móvil') ASC
        LIMIT ?
        """,
        tuple(list(params) + [limit]),
    ).fetchall()
    ranking = []
    for row in rows:
        total = row["audits_count"] or 0
        approved = row["approved_count"] or 0
        ranking.append(
            {
                "mobile_code": row["mobile_code"] or "Sin móvil",
                "audits_count": total,
                "approved_count": approved,
                "critical_count": row["critical_count"] or 0,
                "rejected_count": row["rejected_count"] or 0,
                "approval_rate": 0 if total == 0 else round((approved / total) * 100),
                "average_score": 0 if total == 0 else round((row["average_score"] or 0), 2),
                "last_audit_date": row["last_audit_date"],
            }
        )
    return ranking


def fetch_audit_reports_time_series(filters=None, auditor_user_id=None, granularity="month", limit=60):
    normalized = (granularity or "").strip().lower()
    if normalized not in {"month", "week"}:
        raise ValueError("Granularidad no valida. Usa 'month' o 'week'.")

    where_sql, params = build_audits_where_sql(filters, auditor_user_id=auditor_user_id)

    if is_postgres():
        if normalized == "month":
            period_key_expr = "to_char(date_trunc('month', audits.audit_date::date), 'YYYY-MM')"
        else:
            period_key_expr = "to_char(date_trunc('week', audits.audit_date::date), 'IYYY-\"W\"IW')"
        period_start_expr = "MIN(audits.audit_date::date)"
    else:
        if normalized == "month":
            period_key_expr = "strftime('%Y-%m', audits.audit_date)"
        else:
            period_key_expr = "strftime('%Y-W%W', audits.audit_date)"
        period_start_expr = "MIN(audits.audit_date)"

    rows = get_db().execute(
        f"""
        SELECT
            {period_key_expr} AS period_key,
            {period_start_expr} AS period_start,
            COUNT(*) AS audits_count,
            SUM(CASE WHEN audits.result_status IN ('Aprobada', 'Aprobada con observaciones') THEN 1 ELSE 0 END) AS approved_count,
            SUM(CASE WHEN audits.result_status = 'Critica' THEN 1 ELSE 0 END) AS critical_count,
            SUM(CASE WHEN audits.result_status = 'Rechazada' THEN 1 ELSE 0 END) AS rejected_count,
            AVG(audits.total_score) AS average_score
        FROM audits
        {where_sql}
        GROUP BY {period_key_expr}
        ORDER BY period_start DESC
        LIMIT ?
        """,
        tuple(list(params) + [limit]),
    ).fetchall()

    series = []
    for row in rows:
        total = row["audits_count"] or 0
        approved = row["approved_count"] or 0
        series.append(
            {
                "period_key": row["period_key"],
                "period_start": row["period_start"],
                "audits_count": total,
                "approved_count": approved,
                "critical_count": row["critical_count"] or 0,
                "rejected_count": row["rejected_count"] or 0,
                "approval_rate": 0 if total == 0 else round((approved / total) * 100),
                "average_score": 0 if total == 0 else round((row["average_score"] or 0), 2),
            }
        )
    return series


def fetch_audit_reports_section_breakdown(filters=None, auditor_user_id=None):
    where_sql, params = build_audits_where_sql(filters, auditor_user_id=auditor_user_id)
    rows = get_db().execute(
        f"""
        SELECT
            audit_items.section_title,
            SUM(CASE WHEN audit_items.status IN ('cumple', 'conforme') THEN 1 ELSE 0 END) AS compliant_count,
            SUM(CASE WHEN audit_items.status IN ('no_cumple', 'nc_menor', 'nc_mayor') THEN 1 ELSE 0 END) AS non_compliant_count,
            SUM(CASE WHEN audit_items.status IN ('no_cumple', 'nc_menor', 'nc_mayor') AND audit_items.is_critical = 1 THEN 1 ELSE 0 END) AS critical_non_compliant_count,
            SUM(CASE WHEN audit_items.status = 'no_aplica' THEN 1 ELSE 0 END) AS not_applicable_count
        FROM audit_items
        INNER JOIN audits ON audits.id = audit_items.audit_id
        {where_sql}
        GROUP BY audit_items.section_title
        ORDER BY non_compliant_count DESC, audit_items.section_title ASC
        """,
        params,
    ).fetchall()

    return [dict(row) for row in rows]


def fetch_audit_reports_critical_findings(filters=None, auditor_user_id=None, limit=500):
    extra_clauses = ["audit_items.status IN ('no_cumple', 'nc_menor', 'nc_mayor')", "audit_items.is_critical = 1"]
    where_sql, params = build_audits_where_sql(
        filters,
        auditor_user_id=auditor_user_id,
        extra_clauses=extra_clauses,
    )

    rows = get_db().execute(
        f"""
        SELECT
            audits.id AS audit_id,
            audits.audit_date,
            audits.auditor_name,
            audits.location,
            audits.installation_type,
            audits.total_score,
            audits.result_status,
            mobile_units.mobile_code,
            COALESCE(technicians.name, audits.technician_display_name) AS technician_name,
            vehicles.plate AS vehicle_plate,
            audit_items.section_title,
            audit_items.item_label,
            audit_items.status,
            audit_items.non_compliance_reason,
            audit_items.notes,
            audit_items.photo_path
        FROM audit_items
        INNER JOIN audits ON audits.id = audit_items.audit_id
        LEFT JOIN mobile_units ON mobile_units.id = audits.mobile_unit_id
        LEFT JOIN technicians ON technicians.id = audits.technician_id
        INNER JOIN vehicles ON vehicles.id = audits.vehicle_id
        {where_sql}
        ORDER BY audits.audit_date DESC, audits.id DESC, audit_items.id ASC
        LIMIT ?
        """,
        tuple(list(params) + [limit]),
    ).fetchall()
    return [dict(row) for row in rows]


def fetch_audit_reports_missing_evidence(filters=None, auditor_user_id=None, limit=500):
    optional_reasons = ("olvido", "perdida", "robo", "no_asignado")
    optional_items = ("extintor", "seguro_vehicular", "oblea_gnc", "rto", "botiquin")
    extra_clauses = [
        "audit_items.status IN ('no_cumple', 'nc_menor', 'nc_mayor')",
        "(audit_items.photo_path IS NULL OR COALESCE(audit_items.photo_path, '') = '')",
        "(audit_items.non_compliance_reason IS NULL OR audit_items.non_compliance_reason NOT IN (?, ?, ?, ?))",
        "(audit_items.item_key NOT IN (?, ?, ?, ?, ?))",
    ]
    where_sql, params = build_audits_where_sql(
        filters,
        auditor_user_id=auditor_user_id,
        extra_clauses=extra_clauses,
        extra_params=list(optional_reasons) + list(optional_items),
    )

    rows = get_db().execute(
        f"""
        SELECT
            audits.id AS audit_id,
            audits.audit_date,
            audits.auditor_name,
            audits.location,
            audits.installation_type,
            audits.total_score,
            audits.result_status,
            mobile_units.mobile_code,
            COALESCE(technicians.name, audits.technician_display_name) AS technician_name,
            vehicles.plate AS vehicle_plate,
            audit_items.section_title,
            audit_items.item_label,
            audit_items.non_compliance_reason,
            audit_items.notes
        FROM audit_items
        INNER JOIN audits ON audits.id = audit_items.audit_id
        LEFT JOIN mobile_units ON mobile_units.id = audits.mobile_unit_id
        LEFT JOIN technicians ON technicians.id = audits.technician_id
        INNER JOIN vehicles ON vehicles.id = audits.vehicle_id
        {where_sql}
        ORDER BY audits.audit_date DESC, audits.id DESC, audit_items.id ASC
        LIMIT ?
        """,
        tuple(list(params) + [limit]),
    ).fetchall()
    return [dict(row) for row in rows]


def fetch_audit_reports_supervisor_responsibility_detail(filters=None, auditor_user_id=None, limit=2000):
    supervisor_reasons = ("no_asignado", "vencido", "no_apta_para_el_uso")
    extra_clauses = [
        "audit_items.status = 'no_cumple'",
        "LOWER(COALESCE(audit_items.non_compliance_reason, '')) IN (?, ?, ?)",
    ]
    where_sql, params = build_audits_where_sql_with_technicians(
        filters,
        auditor_user_id=auditor_user_id,
        extra_clauses=extra_clauses,
        extra_params=list(supervisor_reasons),
    )

    supervisor_expr = "COALESCE(technicians.supervisor_name, 'Sin supervisor')"
    technician_name_expr = "COALESCE(technicians.name, audits.technician_display_name, 'Sin técnico')"
    technician_employee_expr = "COALESCE(technicians.employee_code, audits.technician_employee_code, '')"

    rows = get_db().execute(
        f"""
        SELECT
            audits.id AS audit_id,
            audits.audit_date,
            audits.auditor_name,
            audits.installation_type,
            audits.result_status,
            audits.total_score,
            {supervisor_expr} AS supervisor_name,
            {technician_name_expr} AS technician_name,
            {technician_employee_expr} AS technician_employee_code,
            mobile_units.mobile_code,
            vehicles.plate AS vehicle_plate,
            audits.location,
            audit_items.section_title,
            audit_items.item_label,
            audit_items.non_compliance_reason,
            audit_items.notes
        FROM audit_items
        INNER JOIN audits ON audits.id = audit_items.audit_id
        LEFT JOIN mobile_units ON mobile_units.id = audits.mobile_unit_id
        LEFT JOIN technicians ON technicians.id = audits.technician_id
        INNER JOIN vehicles ON vehicles.id = audits.vehicle_id
        {where_sql}
        ORDER BY audits.audit_date DESC, audits.id DESC, audit_items.id ASC
        LIMIT ?
        """,
        tuple(list(params) + [limit]),
    ).fetchall()
    return [dict(row) for row in rows]


def fetch_audit_reports_supply_requests_detail(filters=None, auditor_user_id=None, limit=2000):
    where_sql, params = build_audits_where_sql(filters, auditor_user_id=auditor_user_id)
    rows = get_db().execute(
        f"""
        SELECT
            audits.id AS audit_id,
            audits.audit_date,
            audits.auditor_name,
            audits.location,
            audits.installation_type,
            audits.total_score,
            audits.result_status,
            mobile_units.mobile_code,
            COALESCE(technicians.name, audits.technician_display_name) AS technician_name,
            vehicles.plate AS vehicle_plate,
            audit_supply_requests.created_at,
            audit_supply_requests.section_title,
            audit_supply_requests.item_label,
            audit_supply_requests.request_type,
            audit_supply_requests.material_code,
            audit_supply_requests.quantity,
            audit_supply_requests.notes
        FROM audit_supply_requests
        INNER JOIN audits ON audits.id = audit_supply_requests.audit_id
        LEFT JOIN mobile_units ON mobile_units.id = audits.mobile_unit_id
        LEFT JOIN technicians ON technicians.id = audits.technician_id
        INNER JOIN vehicles ON vehicles.id = audits.vehicle_id
        {where_sql}
        ORDER BY audits.audit_date DESC, audits.id DESC, audit_supply_requests.id ASC
        LIMIT ?
        """,
        tuple(list(params) + [limit]),
    ).fetchall()

    detail = []
    for row in rows:
        payload = dict(row)
        payload["quantity"] = payload.get("quantity") if payload.get("quantity") is not None else 0
        detail.append(payload)
    return detail


def fetch_audit_reports_supply_requests_summary(filters=None, auditor_user_id=None, limit=2000):
    where_sql, params = build_audits_where_sql(filters, auditor_user_id=auditor_user_id)
    rows = get_db().execute(
        f"""
        SELECT
            audit_supply_requests.request_type,
            audit_supply_requests.material_code,
            COUNT(*) AS requests_count,
            COALESCE(SUM(COALESCE(audit_supply_requests.quantity, 0)), 0) AS total_quantity
        FROM audit_supply_requests
        INNER JOIN audits ON audits.id = audit_supply_requests.audit_id
        {where_sql}
        GROUP BY audit_supply_requests.request_type, audit_supply_requests.material_code
        ORDER BY total_quantity DESC, requests_count DESC, audit_supply_requests.material_code ASC
        LIMIT ?
        """,
        tuple(list(params) + [limit]),
    ).fetchall()
    return [dict(row) for row in rows]


def fetch_audit_detail(audit_id):
    created_at_expr = "audits.created_at" if is_postgres() else "datetime(audits.created_at, 'localtime')"
    row = get_db().execute(
        f"""
        SELECT
            audits.id,
            audits.audit_date,
            audits.auditor_name,
            audits.auditor_user_id,
            audits.sa_number,
            audits.auditor_signature_path,
            audits.technician_signature_path,
            audits.technician_display_name,
            audits.technician_employee_code,
            audits.location,
            audits.installation_type,
            audits.total_score,
            audits.result_status,
            audits.record_scope,
            audits.general_notes,
            audits.serialized_stock_status,
            audits.serialized_stock_notes,
            audits.material_stock_status,
            audits.material_stock_notes,
            audits.technician_id,
            {created_at_expr} AS created_at,
            mobile_units.mobile_code,
            COALESCE(technicians.name, audits.technician_display_name) AS technician_name,
            COALESCE(technicians.employee_code, audits.technician_employee_code) AS employee_code,
            technicians.company_name AS technician_company,
            technicians.supervisor_name AS technician_supervisor,
            technicians.center_name AS technician_center,
            vehicles.plate AS vehicle_plate,
            vehicles.brand AS vehicle_brand,
            vehicles.model AS vehicle_model,
            vehicles.unit_number AS vehicle_unit_number,
            vehicles.odometer_km AS vehicle_odometer_km,
            vehicles.extinguisher_expiry AS vehicle_extinguisher_expiry,
            vehicles.insurance_expiry AS vehicle_insurance_expiry,
            vehicles.gnc_expiry AS vehicle_gnc_expiry,
            vehicles.rto_expiry AS vehicle_rto_expiry,
            vehicles.botiquin_expiry AS vehicle_botiquin_expiry
        FROM audits
        LEFT JOIN mobile_units ON mobile_units.id = audits.mobile_unit_id
        LEFT JOIN technicians ON technicians.id = audits.technician_id
        INNER JOIN vehicles ON vehicles.id = audits.vehicle_id
        WHERE audits.id = ?
        """,
        (audit_id,),
    ).fetchone()
    return dict(row) if row else None


def fetch_audit_items(audit_id):
    rows = get_db().execute(
        """
        SELECT
            id,
            section_key,
            section_title,
            item_key,
            item_label,
            status,
            is_critical,
            non_compliance_reason,
            notes,
            photo_path
        FROM audit_items
        WHERE audit_id = ?
        ORDER BY id ASC
        """,
        (audit_id,),
    ).fetchall()
    return [dict(row) for row in rows]


def fetch_audit_supply_requests(audit_id):
    created_at_expr = "created_at" if is_postgres() else "datetime(created_at, 'localtime')"
    rows = get_db().execute(
        f"""
        SELECT
            id,
            {created_at_expr} AS created_at,
            section_title,
            item_label,
            request_type,
            material_code,
            quantity,
            notes
        FROM audit_supply_requests
        WHERE audit_id = ?
        ORDER BY id ASC
        """,
        (audit_id,),
    ).fetchall()
    return [dict(row) for row in rows]


def create_audit_supply_requests(audit_id, supply_requests):
    if not supply_requests:
        return 0
    connection = get_db()
    connection.executemany(
        """
        INSERT INTO audit_supply_requests (
            audit_id,
            section_key,
            section_title,
            item_key,
            item_label,
            request_type,
            material_code,
            quantity,
            notes
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        [
            (
                audit_id,
                req["section_key"],
                req["section_title"],
                req["item_key"],
                req["item_label"],
                req["request_type"],
                req["material_code"],
                req.get("quantity"),
                req.get("notes"),
            )
            for req in supply_requests
        ],
    )
    connection.commit()
    return len(supply_requests)


def create_audit(audit_data, items, supply_requests=None):
    connection = get_db()
    insert_sql = """
        INSERT INTO audits (
            audit_date,
            auditor_name,
            auditor_user_id,
            sa_number,
            auditor_signature_path,
            technician_signature_path,
            technician_display_name,
            technician_employee_code,
            location,
            installation_type,
            total_score,
            result_status,
            record_scope,
            general_notes,
            serialized_stock_status,
            serialized_stock_notes,
            material_stock_status,
            material_stock_notes,
            mobile_unit_id,
            technician_id,
            vehicle_id
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """
    insert_params = (
        audit_data["audit_date"],
        audit_data["auditor_name"],
        audit_data.get("auditor_user_id"),
        audit_data.get("sa_number"),
        audit_data.get("auditor_signature_path"),
        audit_data.get("technician_signature_path"),
        audit_data.get("technician_display_name"),
        audit_data.get("technician_employee_code"),
        audit_data["location"],
        audit_data["installation_type"],
        audit_data["total_score"],
        audit_data["result_status"],
        normalize_audit_record_scope(audit_data.get("record_scope")),
        audit_data["general_notes"],
        audit_data.get("serialized_stock_status"),
        audit_data.get("serialized_stock_notes"),
        audit_data.get("material_stock_status"),
        audit_data.get("material_stock_notes"),
        audit_data["mobile_unit_id"],
        audit_data.get("technician_id"),
        audit_data["vehicle_id"],
    )

    if is_postgres():
        cursor = connection.execute(insert_sql + " RETURNING id", insert_params)
        new_id_row = cursor.fetchone()
        if not new_id_row:
            audit_id = None
        else:
            audit_id = new_id_row["id"] if isinstance(new_id_row, dict) else new_id_row[0]
    else:
        cursor = connection.execute(insert_sql, insert_params)
        audit_id = cursor.lastrowid

    connection.executemany(
        """
        INSERT INTO audit_items (
            audit_id,
            section_key,
            section_title,
            item_key,
            item_label,
            status,
            is_critical,
            non_compliance_reason,
            notes,
            photo_path
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        [
            (
                audit_id,
                item["section_key"],
                item["section_title"],
                item["item_key"],
                item["item_label"],
                item["status"],
                1 if item["is_critical"] else 0,
                item.get("non_compliance_reason"),
                item["notes"],
                item.get("photo_path"),
            )
            for item in items
        ],
    )

    if supply_requests:
        connection.executemany(
            """
            INSERT INTO audit_supply_requests (
                audit_id,
                section_key,
                section_title,
                item_key,
                item_label,
                request_type,
                material_code,
                quantity,
                notes
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            [
                (
                    audit_id,
                    req["section_key"],
                    req["section_title"],
                    req["item_key"],
                    req["item_label"],
                    req["request_type"],
                    req["material_code"],
                    req.get("quantity"),
                    req.get("notes"),
                )
                for req in supply_requests
            ],
        )
    connection.commit()
    return audit_id


def update_audit_record_scope(audit_id, record_scope):
    safe_scope = normalize_audit_record_scope(record_scope)
    connection = get_db()
    cursor = connection.execute(
        """
        UPDATE audits
        SET record_scope = ?
        WHERE id = ?
        """,
        (safe_scope, audit_id),
    )
    connection.commit()
    return (cursor.rowcount or 0) > 0


def import_technicians(rows):
    connection = get_db()
    created_count = 0
    updated_count = 0
    skipped_rows = []

    for index, row in enumerate(rows, start=2):
        employee_code = (row.get("employee_code") or "").strip()
        name = (row.get("name") or "").strip()
        region = (row.get("region") or "").strip()

        if not employee_code or not name or not region:
            skipped_rows.append(f"Fila {index}: faltan employee_code, name o region.")
            continue

        payload = (
            name,
            region,
            (row.get("phone") or "").strip(),
            (row.get("commune") or "").strip(),
            (row.get("team") or "").strip(),
            normalize_active_value(row.get("is_active")),
            employee_code,
        )

        exists = connection.execute(
            "SELECT id FROM technicians WHERE employee_code = ?",
            (employee_code,),
        ).fetchone()

        if exists:
            connection.execute(
                """
                UPDATE technicians
                SET name = ?, region = ?, phone = ?, commune = ?, team = ?, is_active = ?
                WHERE employee_code = ?
                """,
                payload,
            )
            updated_count += 1
        else:
            connection.execute(
                """
                INSERT INTO technicians (name, employee_code, region, phone, commune, team, is_active)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    name,
                    employee_code,
                    region,
                    (row.get("phone") or "").strip(),
                    (row.get("commune") or "").strip(),
                    (row.get("team") or "").strip(),
                    normalize_active_value(row.get("is_active")),
                ),
            )
            created_count += 1

    connection.commit()
    return {
        "created_count": created_count,
        "updated_count": updated_count,
        "skipped_rows": skipped_rows,
    }


def import_technician_information(rows):
    connection = get_db()
    created_count = 0
    updated_count = 0
    skipped_rows = []

    def pick_first(row_data, keys):
        for key in keys:
            value = (row_data.get(key) or "").strip()
            if value:
                return value
        return ""

    def ensure_unique_employee_code(employee_code_base):
        base = (employee_code_base or "").strip()
        if not base:
            base = "AUTO"
        candidate = base
        suffix = 2
        while True:
            existing = connection.execute(
                "SELECT 1 FROM technicians WHERE employee_code = ?",
                (candidate,),
            ).fetchone()
            if not existing:
                return candidate
            candidate = f"{base}-{suffix}"
            suffix += 1

    def parse_company_union(company_raw, union_raw, combined_raw):
        company = (company_raw or "").strip()
        union = (union_raw or "").strip()
        combined = (combined_raw or "").strip()
        if not company and combined:
            separators = ["|", "/", "-", ","]
            parts = [combined]
            for separator in separators:
                if separator in combined:
                    parts = [part.strip() for part in combined.split(separator) if part.strip()]
                    if len(parts) >= 2:
                        break
            if len(parts) >= 2:
                company = parts[0]
                if not union:
                    union = parts[1]
            else:
                company = combined
        return company, union

    mobile_keys = [
        "movil",
        "movil_tecnico",
        "mobile_code",
        "numero_de_tecnico",
        "numero_tecnico",
        "nro_tecnico",
        "nro_movil",
        "numero_movil",
    ]
    employee_code_keys = [
        "employee_code",
        "codigo_tecnico",
        "cod_tecnico",
        "tecnico_codigo",
        "legajo",
        "legajo_tecnico",
    ]
    technician_name_keys = [
        "titular",
        "nombre_del_tecnico",
        "nombre_tecnico",
        "tecnico",
        "name",
        "nombre",
    ]
    supervisor_keys = [
        "supervisor",
        "nombre_del_supervisor",
        "supervisor_nombre",
        "responsable",
    ]
    center_keys = [
        "centro",
        "ubicacion",
        "centro_nombre",
        "location",
        "localidad",
    ]
    company_keys = [
        "empresa",
        "company",
        "contratista",
        "proveedor",
        "empresa_contratista",
    ]
    union_keys = [
        "sindicato",
        "union",
        "gremio",
    ]
    company_union_keys = [
        "empresa_y_sindicato",
        "empresa_sindicato",
        "empresa_y_gremio",
    ]

    for index, row in enumerate(rows, start=2):
        mobile_code = normalize_mobile_code(pick_first(row, mobile_keys))
        employee_code = pick_first(row, employee_code_keys)
        technician_name = pick_first(row, technician_name_keys)
        supervisor_name = pick_first(row, supervisor_keys)
        center_name = pick_first(row, center_keys)
        company_name_raw = pick_first(row, company_keys)
        union_name_raw = pick_first(row, union_keys)
        company_union_raw = pick_first(row, company_union_keys)
        company_name, union_name = parse_company_union(company_name_raw, union_name_raw, company_union_raw)

        technician_id = None
        technician_row = None

        if employee_code:
            technician_row = connection.execute(
                "SELECT id, region FROM technicians WHERE employee_code = ?",
                (employee_code,),
            ).fetchone()
            if technician_row:
                technician_id = technician_row["id"] if is_postgres() else technician_row[0]
        elif mobile_code:
            linked = connection.execute(
                "SELECT technician_id FROM mobile_units WHERE mobile_code = ?",
                (mobile_code,),
            ).fetchone()
            linked_id = None
            if linked:
                linked_id = linked["technician_id"] if is_postgres() else linked[0]
            if linked_id:
                technician_id = linked_id

        if technician_id is None and technician_name:
            matches = connection.execute(
                "SELECT id FROM technicians WHERE LOWER(name) = LOWER(?)",
                (technician_name,),
            ).fetchall()
            if len(matches) == 1:
                technician_id = matches[0]["id"] if is_postgres() else matches[0][0]
            elif len(matches) > 1:
                skipped_rows.append(
                    f"Fila {index}: hay mas de un tecnico con nombre '{technician_name}'."
                )
                continue

        region_value = (center_name or "").strip()
        if not region_value:
            region_value = "-"

        if technician_id is None:
            if not technician_name:
                skipped_rows.append(f"Fila {index}: falta el titular/nombre del tecnico.")
                continue

            base_employee_code = (employee_code or "").strip()
            if not base_employee_code and mobile_code:
                base_employee_code = mobile_code
            if not base_employee_code:
                skipped_rows.append(f"Fila {index}: falta employee_code o movil para generar codigo.")
                continue

            new_employee_code = ensure_unique_employee_code(base_employee_code)
            connection.execute(
                """
                INSERT INTO technicians (
                    name,
                    employee_code,
                    region,
                    phone,
                    commune,
                    team,
                    company_name,
                    union_name,
                    supervisor_name,
                    center_name,
                    is_active
                ) VALUES (?, ?, ?, '', '', '', ?, ?, ?, ?, 1)
                """,
                (
                    technician_name.strip(),
                    new_employee_code,
                    region_value,
                    company_name or None,
                    union_name or None,
                    supervisor_name or None,
                    center_name or None,
                ),
            )
            technician_row = connection.execute(
                "SELECT id FROM technicians WHERE employee_code = ?",
                (new_employee_code,),
            ).fetchone()
            technician_id = technician_row["id"] if is_postgres() else technician_row[0]
            created_count += 1
        else:
            connection.execute(
                """
                UPDATE technicians
                SET
                    name = COALESCE(NULLIF(?, ''), name),
                    company_name = COALESCE(NULLIF(?, ''), company_name),
                    union_name = COALESCE(NULLIF(?, ''), union_name),
                    supervisor_name = COALESCE(NULLIF(?, ''), supervisor_name),
                    center_name = COALESCE(NULLIF(?, ''), center_name),
                    region = CASE
                        WHEN (region IS NULL OR region = '' OR region = '-')
                            THEN COALESCE(NULLIF(?, ''), region)
                        ELSE region
                    END
                WHERE id = ?
                """,
                (
                    technician_name,
                    company_name,
                    union_name,
                    supervisor_name,
                    center_name,
                    center_name,
                    technician_id,
                ),
            )
            updated_count += 1

        if mobile_code:
            existing_mobile = connection.execute(
                """
                SELECT id, technician_id, user_name
                FROM mobile_units
                WHERE mobile_code = ?
                """,
                (mobile_code,),
            ).fetchone()
            if existing_mobile:
                mobile_id = existing_mobile["id"] if is_postgres() else existing_mobile[0]
                existing_tech_id = existing_mobile["technician_id"] if is_postgres() else existing_mobile[1]
                existing_user_name = existing_mobile["user_name"] if is_postgres() else existing_mobile[2]
                if existing_tech_id != technician_id:
                    connection.execute(
                        "UPDATE mobile_units SET technician_id = ? WHERE id = ?",
                        (technician_id, mobile_id),
                    )
                if technician_name and not (existing_user_name or "").strip():
                    connection.execute(
                        "UPDATE mobile_units SET user_name = ? WHERE id = ?",
                        (technician_name.strip(), mobile_id),
                    )
            else:
                connection.execute(
                    """
                    INSERT INTO mobile_units (
                        mobile_code,
                        technician_id,
                        user_name,
                        warehouse_description,
                        warehouse_type,
                        is_enabled,
                        notes
                    ) VALUES (?, ?, ?, ?, 'movil', 1, '')
                    """,
                    (
                        mobile_code,
                        technician_id,
                        technician_name.strip() if technician_name else "",
                        f"Movil {mobile_code}",
                    ),
                )
                created = connection.execute(
                    "SELECT id FROM mobile_units WHERE mobile_code = ?",
                    (mobile_code,),
                ).fetchone()
                mobile_id = created["id"] if is_postgres() else created[0]

            if center_name:
                exists_storage = connection.execute(
                    """
                    SELECT id
                    FROM storage_locations
                    WHERE center_name = ? AND warehouse_code = ?
                    """,
                    (center_name, mobile_code),
                ).fetchone()
                payload = (
                    mobile_id,
                    f"Movil {mobile_code}",
                    "movil",
                    (technician_name or "").strip() or None,
                    1,
                    center_name,
                    mobile_code,
                )
                if exists_storage:
                    storage_id = exists_storage["id"] if is_postgres() else exists_storage[0]
                    connection.execute(
                        """
                        UPDATE storage_locations
                        SET mobile_unit_id = ?,
                            warehouse_name = ?,
                            warehouse_type = ?,
                            user_name = COALESCE(NULLIF(user_name, ''), NULLIF(?, '')),
                            is_enabled = ?
                        WHERE id = ?
                        """,
                        (
                            payload[0],
                            payload[1],
                            payload[2],
                            payload[3],
                            payload[4],
                            storage_id,
                        ),
                    )
                else:
                    connection.execute(
                        """
                        INSERT INTO storage_locations (
                            mobile_unit_id,
                            center_name,
                            warehouse_code,
                            warehouse_name,
                            warehouse_type,
                            user_name,
                            is_enabled
                        ) VALUES (?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            mobile_id,
                            center_name,
                            mobile_code,
                            f"Movil {mobile_code}",
                            "movil",
                            (technician_name or "").strip() or None,
                            1,
                        ),
                    )

    connection.commit()
    return {
        "created_count": created_count,
        "updated_count": updated_count,
        "skipped_rows": skipped_rows,
    }


def import_checklist_del_dia(rows):
    import re

    connection = get_db()
    created_count = 0
    updated_count = 0
    skipped_rows = []

    def pick_first(row_data, keys):
        for key in keys:
            value = (row_data.get(key) or "").strip()
            if value:
                return value
        return ""

    def parse_unit_plate(value):
        cleaned = (value or "").strip().upper()
        if not cleaned:
            return "", ""
        match = re.search(r"(?P<unit>\d{1,4})\s*[-–—/]\s*(?P<plate>[A-Z0-9]{5,10})", cleaned)
        if match:
            return match.group("unit").strip(), match.group("plate").strip()
        return "", cleaned

    def normalize_plate(value):
        return (value or "").strip().upper().replace(" ", "")

    def normalize_km(value):
        raw = (value or "").strip()
        if not raw:
            return None
        digits = "".join(ch for ch in raw if ch.isdigit())
        if digits:
            try:
                return int(digits)
            except ValueError:
                return None
        numeric = normalize_float_value(raw)
        return int(numeric) if numeric is not None else None

    unit_keys = [
        "nro_camioneta",
        "nro_de_camioneta",
        "numero_camioneta",
        "numero",
        "unidad",
        "nro_unidad",
    ]
    plate_keys = [
        "patente",
        "plate",
        "dominio",
        "matricula",
    ]
    combined_vehicle_keys = [
        "nro_camioneta_patente",
        "camioneta",
        "vehiculo",
        "unidad_patente",
    ]
    km_keys = [
        "km",
        "kms",
        "kilometros",
        "kilometraje",
        "odometro",
        "odometer",
    ]
    employee_code_keys = [
        "employee_code",
        "codigo_tecnico",
        "cod_tecnico",
        "tecnico_codigo",
        "legajo",
    ]
    technician_name_keys = [
        "name",
        "tecnico",
        "nombre_tecnico",
        "tecnico_nombre",
        "nombre",
    ]
    company_keys = [
        "empresa",
        "company",
        "compania",
        "contratista",
        "proveedor",
    ]

    for index, row in enumerate(rows, start=2):
        unit_number = pick_first(row, unit_keys)
        plate = pick_first(row, plate_keys)
        combined_vehicle = pick_first(row, combined_vehicle_keys)
        if combined_vehicle and (not unit_number or not plate):
            parsed_unit, parsed_plate = parse_unit_plate(combined_vehicle)
            unit_number = unit_number or parsed_unit
            plate = plate or parsed_plate

        plate = normalize_plate(plate)
        if not plate:
            skipped_rows.append(f"Fila {index}: no se detecto patente.")
            continue

        odometer_km = normalize_km(pick_first(row, km_keys))
        employee_code = pick_first(row, employee_code_keys)
        technician_name = pick_first(row, technician_name_keys)
        company_name = pick_first(row, company_keys)

        vehicle_row = connection.execute(
            "SELECT id FROM vehicles WHERE plate = ?",
            (plate,),
        ).fetchone()

        if vehicle_row:
            connection.execute(
                """
                UPDATE vehicles
                SET unit_number = CASE WHEN ? != '' THEN ? ELSE unit_number END,
                    odometer_km = CASE WHEN ? IS NOT NULL THEN ? ELSE odometer_km END,
                    assigned_employee_code = CASE WHEN ? != '' THEN ? ELSE assigned_employee_code END
                WHERE id = ?
                """,
                (
                    unit_number,
                    unit_number,
                    odometer_km,
                    odometer_km,
                    employee_code,
                    employee_code,
                    vehicle_row["id"],
                ),
            )
            updated_count += 1
        else:
            connection.execute(
                """
                INSERT INTO vehicles (
                    plate,
                    brand,
                    model,
                    year,
                    status,
                    unit_number,
                    odometer_km,
                    assigned_employee_code,
                    review_date,
                    insurance_expiry
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    plate,
                    "-",
                    "-",
                    None,
                    "activo",
                    unit_number or None,
                    odometer_km,
                    employee_code or None,
                    "",
                    "",
                ),
            )
            created_count += 1

        if company_name:
            technician_row = None
            if employee_code:
                technician_row = connection.execute(
                    "SELECT id FROM technicians WHERE employee_code = ?",
                    (employee_code,),
                ).fetchone()

            if technician_row is None and technician_name:
                matches = connection.execute(
                    "SELECT id FROM technicians WHERE name = ? COLLATE NOCASE",
                    (technician_name,),
                ).fetchall()
                if len(matches) == 1:
                    technician_row = matches[0]
                elif len(matches) > 1:
                    skipped_rows.append(
                        f"Fila {index}: hay mas de un tecnico con nombre '{technician_name}'."
                    )
                    technician_row = None

            if technician_row is not None:
                connection.execute(
                    """
                    UPDATE technicians
                    SET company_name = CASE WHEN ? != '' THEN ? ELSE company_name END
                    WHERE id = ?
                    """,
                    (
                        company_name,
                        company_name,
                        technician_row["id"],
                    ),
                )

    connection.commit()
    return {
        "created_count": created_count,
        "updated_count": updated_count,
        "skipped_rows": skipped_rows,
    }


def import_novedades_diarias(rows):
    import re

    connection = get_db()
    created_count = 0
    updated_count = 0
    skipped_rows = []

    def pick_first(row_data, keys):
        for key in keys:
            value = (row_data.get(key) or "").strip()
            if value:
                return value
        return ""

    def normalize_placeholder(value):
        cleaned_value = (value or "").strip()
        if cleaned_value in {"-", "--", "n/a", "na"}:
            return ""
        return cleaned_value

    def parse_technician_cell(value):
        cleaned_value = " ".join((value or "").strip().split())
        if not cleaned_value:
            return "", ""

        match = re.match(r"^(?P<code>\d+)\s*-\s*(?P<name>.+)$", cleaned_value)
        if match:
            return match.group("code").strip(), match.group("name").strip()

        match = re.match(r"^(?P<code>\d+)\s+(?P<name>.+)$", cleaned_value)
        if match:
            return match.group("code").strip(), match.group("name").strip()

        return "", cleaned_value

    def find_column(header_keys, exact_keys, contains_fragments):
        for key in exact_keys:
            if key in header_keys:
                return key
        for header_key in header_keys:
            for fragment in contains_fragments:
                if fragment in header_key:
                    return header_key
        return None

    employee_code_keys = [
        "employee_code",
        "codigo_tecnico",
        "cod_tecnico",
        "tecnico_codigo",
        "legajo",
        "legajo_tecnico",
        "codigo_empleado",
        "cod_empleado",
    ]
    technician_name_keys = [
        "name",
        "tecnico",
        "nombre_tecnico",
        "tecnico_nombre",
        "nombre",
        "recurso",
        "tecnico_nombre_apellido",
    ]
    supervisor_keys = [
        "supervisor",
        "supervisora",
        "supervisado_por",
        "supervisor_a_cargo",
        "jefe",
        "lider",
        "encargado",
        "coordinador",
        "responsable",
    ]
    center_keys = [
        "centro",
        "centro_de_trabajo",
        "centro_trabajo",
        "centro_operativo",
        "center",
        "base",
        "base_operativa",
        "sede",
        "sucursal",
        "delegacion",
        "ciudad",
        "region",
    ]

    if not rows:
        raise ValueError("El archivo no contiene filas para importar.")

    ordered_keys = list((rows[0] or {}).keys())
    header_keys = set(ordered_keys)
    supervisor_column = find_column(
        header_keys,
        supervisor_keys,
        ["supervis", "jefe", "lider", "encargad", "coordin", "responsab"],
    )
    center_column = find_column(
        header_keys,
        center_keys,
        ["centro", "base", "sede", "sucursal", "deleg", "ciudad"],
    )

    if supervisor_column is None and center_column is None and len(ordered_keys) < 3:
        sample = sorted(header_keys)[:18]
        raise ValueError(
            "No se detectaron columnas de supervisor/centro en NovDiarias. "
            "Encabezados detectados: " + ", ".join(sample)
        )

    employee_code_column = find_column(
        header_keys,
        employee_code_keys,
        ["employee", "empleado", "codigo", "legajo"],
    )
    technician_name_column = find_column(
        header_keys,
        technician_name_keys,
        ["tecnico", "nombre", "recurso"],
    )

    if (supervisor_column is None or center_column is None) and len(ordered_keys) >= 3:
        technician_name_column = technician_name_column or ordered_keys[0]
        supervisor_column = supervisor_column or ordered_keys[1]
        center_column = center_column or ordered_keys[2]

    if supervisor_column is None and center_column is None:
        sample = sorted(header_keys)[:18]
        raise ValueError(
            "No se detectaron columnas de supervisor/centro en NovDiarias. "
            "Encabezados detectados: " + ", ".join(sample)
        )

    for index, row in enumerate(rows, start=2):
        employee_code = (row.get(employee_code_column) or "").strip() if employee_code_column else ""
        technician_name = (row.get(technician_name_column) or "").strip() if technician_name_column else ""

        supervisor_name = normalize_placeholder((row.get(supervisor_column) or "").strip() if supervisor_column else "")
        center_name = normalize_placeholder((row.get(center_column) or "").strip() if center_column else "")

        parsed_code, parsed_name = parse_technician_cell(technician_name)
        if not employee_code and parsed_code:
            employee_code = parsed_code
        technician_name = parsed_name or technician_name

        if not supervisor_name and not center_name:
            skipped_rows.append(f"Fila {index}: no trae supervisor ni centro.")
            continue

        technician_row = None
        if employee_code:
            technician_row = connection.execute(
                "SELECT id FROM technicians WHERE employee_code = ?",
                (employee_code,),
            ).fetchone()

            if technician_row is None and employee_code.isdigit():
                variants = [f"TEC-{employee_code}", f"tec-{employee_code}", f"TEC{employee_code}", f"tec{employee_code}"]
                for variant in variants:
                    technician_row = connection.execute(
                        "SELECT id FROM technicians WHERE employee_code = ?",
                        (variant,),
                    ).fetchone()
                    if technician_row is not None:
                        break

        if technician_row is None and technician_name:
            technician_name = " ".join(technician_name.split())
            matches = connection.execute(
                "SELECT id FROM technicians WHERE name = ? COLLATE NOCASE",
                (technician_name,),
            ).fetchall()
            if len(matches) == 1:
                technician_row = matches[0]
            elif len(matches) > 1:
                skipped_rows.append(
                    f"Fila {index}: hay mas de un tecnico con nombre '{technician_name}'."
                )
                continue

        if technician_row is None:
            reference = employee_code or technician_name or "sin identificador"
            skipped_rows.append(f"Fila {index}: no se encontro tecnico ({reference}).")
            continue

        connection.execute(
            """
            UPDATE technicians
            SET supervisor_name = CASE WHEN ? != '' THEN ? ELSE supervisor_name END,
                center_name = CASE WHEN ? != '' THEN ? ELSE center_name END
            WHERE id = ?
            """,
            (
                supervisor_name,
                supervisor_name,
                center_name,
                center_name,
                technician_row["id"],
            ),
        )
        updated_count += 1

    connection.commit()
    return {
        "created_count": created_count,
        "updated_count": updated_count,
        "skipped_rows": skipped_rows,
    }


def import_vehicles(rows):
    import re

    connection = get_db()
    created_count = 0
    updated_count = 0
    skipped_rows = []

    def pick_first(row_data, keys):
        for key in keys:
            value = (row_data.get(key) or "").strip()
            if value:
                return value
        return ""

    def normalize_plate(value):
        return (value or "").strip().upper().replace(" ", "")

    def parse_unit_plate(value):
        cleaned = (value or "").strip().upper()
        if not cleaned:
            return "", ""
        match = re.search(r"(?P<unit>\d{1,4})\s*[-–—/]\s*(?P<plate>[A-Z0-9]{5,10})", cleaned)
        if match:
            return match.group("unit").strip(), match.group("plate").strip()
        return "", cleaned

    def normalize_km(value):
        raw = (value or "").strip()
        if not raw:
            return None
        digits = "".join(ch for ch in raw if ch.isdigit())
        if digits:
            try:
                return int(digits)
            except ValueError:
                return None
        numeric = normalize_float_value(raw)
        return int(numeric) if numeric is not None else None

    unit_keys = [
        "unit_number",
        "nro_camioneta",
        "nro_de_camioneta",
        "numero_camioneta",
        "numero",
        "unidad",
        "nro_unidad",
    ]
    plate_keys = [
        "plate",
        "patente",
        "dominio",
        "matricula",
    ]
    combined_vehicle_keys = [
        "nro_camioneta_patente",
        "camioneta",
        "vehiculo",
        "unidad_patente",
    ]
    brand_keys = [
        "brand",
        "marca",
    ]
    model_keys = [
        "model",
        "modelo",
    ]
    km_keys = [
        "odometer_km",
        "km",
        "kms",
        "kilometros",
        "kilometraje",
        "odometro",
        "odometer",
    ]

    for index, row in enumerate(rows, start=2):
        unit_number = pick_first(row, unit_keys)
        plate = pick_first(row, plate_keys)
        combined_vehicle = pick_first(row, combined_vehicle_keys)
        if combined_vehicle and (not unit_number or not plate):
            parsed_unit, parsed_plate = parse_unit_plate(combined_vehicle)
            unit_number = unit_number or parsed_unit
            plate = plate or parsed_plate

        plate = normalize_plate(plate)
        if not plate:
            skipped_rows.append(f"Fila {index}: falta patente (plate/patente/dominio).")
            continue

        brand = pick_first(row, brand_keys)
        model = pick_first(row, model_keys)
        year = normalize_integer_value(row.get("year"))
        status = (row.get("status") or "activo").strip().lower()
        odometer_km = normalize_km(pick_first(row, km_keys))
        assigned_employee_code = (row.get("assigned_employee_code") or "").strip()
        review_date = (row.get("review_date") or "").strip()
        insurance_expiry = (row.get("insurance_expiry") or "").strip()

        exists = connection.execute(
            "SELECT id FROM vehicles WHERE plate = ?",
            (plate,),
        ).fetchone()

        if exists:
            connection.execute(
                """
                UPDATE vehicles
                SET brand = CASE WHEN ? != '' AND ? != '-' THEN ? ELSE brand END,
                    model = CASE WHEN ? != '' AND ? != '-' THEN ? ELSE model END,
                    year = COALESCE(?, year),
                    status = CASE WHEN ? != '' THEN ? ELSE status END,
                    unit_number = CASE WHEN ? != '' THEN ? ELSE unit_number END,
                    odometer_km = COALESCE(?, odometer_km),
                    assigned_employee_code = CASE WHEN ? != '' THEN ? ELSE assigned_employee_code END,
                    review_date = CASE WHEN ? != '' THEN ? ELSE review_date END,
                    insurance_expiry = CASE WHEN ? != '' THEN ? ELSE insurance_expiry END
                WHERE plate = ?
                """,
                (
                    brand,
                    brand,
                    brand,
                    model,
                    model,
                    model,
                    year,
                    status,
                    status,
                    unit_number,
                    unit_number,
                    odometer_km,
                    assigned_employee_code,
                    assigned_employee_code,
                    review_date,
                    review_date,
                    insurance_expiry,
                    insurance_expiry,
                    plate,
                ),
            )
            updated_count += 1
        else:
            connection.execute(
                """
                INSERT INTO vehicles (
                    plate,
                    brand,
                    model,
                    year,
                    status,
                    unit_number,
                    odometer_km,
                    assigned_employee_code,
                    review_date,
                    insurance_expiry
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    plate,
                    brand or "-",
                    model or "-",
                    year,
                    status or "activo",
                    unit_number or None,
                    odometer_km,
                    assigned_employee_code or None,
                    review_date,
                    insurance_expiry,
                ),
            )
            created_count += 1

    connection.commit()
    return {
        "created_count": created_count,
        "updated_count": updated_count,
        "skipped_rows": skipped_rows,
    }


def import_material_stock(rows):
    connection = get_db()
    created_materials = 0
    updated_stock_rows = 0
    skipped_rows = []

    if not rows:
        raise ValueError("El archivo no contiene filas para importar stock.")

    material_column = detect_material_column(rows[0].keys())
    mobile_columns = [
        column
        for column in rows[0].keys()
        if column not in {material_column, "total"}
    ]

    if not mobile_columns:
        raise ValueError("No se detectaron columnas de moviles tecnicos en el archivo.")

    mobile_id_map = {}
    for mobile_code in mobile_columns:
        normalized_mobile_code = normalize_mobile_code(mobile_code)
        if not normalized_mobile_code:
            continue
        mobile_id_map[mobile_code] = ensure_mobile_unit(connection, normalized_mobile_code)

    connection.executemany(
        "DELETE FROM material_stock WHERE mobile_unit_id = ?",
        [(mobile_id,) for mobile_id in mobile_id_map.values()],
    )

    for index, row in enumerate(rows, start=2):
        material_label = (row.get(material_column) or "").strip()
        if not material_label:
            skipped_rows.append(f"Fila {index}: no tiene nombre de material.")
            continue

        material_code, material_name = split_material_label(material_label)
        material_id, was_created = ensure_material(connection, material_code, material_name)
        if was_created:
            created_materials += 1

        for original_mobile_code, mobile_id in mobile_id_map.items():
            quantity = normalize_float_value(row.get(original_mobile_code))
            if quantity is None or quantity <= 0:
                continue

            connection.execute(
                """
                INSERT INTO material_stock (material_id, mobile_unit_id, quantity)
                VALUES (?, ?, ?)
                ON CONFLICT(material_id, mobile_unit_id)
                DO UPDATE SET quantity = excluded.quantity
                """,
                (material_id, mobile_id, quantity),
            )
            updated_stock_rows += 1

    connection.commit()
    return {
        "created_count": created_materials,
        "updated_count": updated_stock_rows,
        "skipped_rows": skipped_rows,
    }


def import_storage_locations(rows):
    connection = get_db()
    created_count = 0
    updated_count = 0
    skipped_rows = []

    for index, row in enumerate(rows, start=2):
        warehouse_code = (row.get("codigo") or "").strip()
        normalized_code = normalize_mobile_code(warehouse_code)
        if normalized_code:
            warehouse_code = normalized_code
        user_name = (row.get("usuario") or "").strip()
        warehouse_name = (row.get("descripcion") or "").strip()
        center_name = (row.get("centro") or "").strip()

        if not warehouse_code or not warehouse_name or not center_name:
            skipped_rows.append(f"Fila {index}: faltan codigo, descripcion o centro.")
            continue

        mobile_unit_id = ensure_mobile_unit(
            connection,
            warehouse_code,
            user_name=user_name,
            warehouse_description=warehouse_name,
            warehouse_type=(row.get("tipo_de_almacen") or "").strip(),
            is_enabled=normalize_yes_no_value(row.get("habilitado")),
            notes="Importado desde ALMACENES.xlsx",
        )

        exists = connection.execute(
            """
            SELECT id
            FROM storage_locations
            WHERE center_name = ? AND warehouse_code = ?
            """,
            (center_name, warehouse_code),
        ).fetchone()

        payload = (
            mobile_unit_id,
            warehouse_name,
            (row.get("tipo_de_almacen") or "").strip(),
            user_name,
            normalize_yes_no_value(row.get("habilitado")),
            center_name,
            warehouse_code,
        )

        if exists:
            connection.execute(
                """
                UPDATE storage_locations
                SET mobile_unit_id = ?, warehouse_name = ?, warehouse_type = ?, user_name = ?, is_enabled = ?
                WHERE center_name = ? AND warehouse_code = ?
                """,
                payload,
            )
            updated_count += 1
        else:
            connection.execute(
                """
                INSERT INTO storage_locations (
                    mobile_unit_id,
                    center_name,
                    warehouse_code,
                    warehouse_name,
                    warehouse_type,
                    user_name,
                    is_enabled
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    mobile_unit_id,
                    center_name,
                    warehouse_code,
                    warehouse_name,
                    (row.get("tipo_de_almacen") or "").strip(),
                    user_name,
                    normalize_yes_no_value(row.get("habilitado")),
                ),
            )
            created_count += 1

    connection.commit()
    return {
        "created_count": created_count,
        "updated_count": updated_count,
        "skipped_rows": skipped_rows,
    }


def import_equipment_inventory(rows):
    connection = get_db()
    created_count = 0
    updated_count = 0
    skipped_rows = []

    if not rows:
        raise ValueError("El archivo no contiene filas para importar equipos serializados.")

    warehouse_codes = {
        (row.get("codigo_almacen") or "").strip()
        for row in rows
        if (row.get("codigo_almacen") or "").strip() and (row.get("almacen") or "").strip()
    }
    if warehouse_codes:
        connection.executemany(
            "DELETE FROM equipment_inventory WHERE warehouse_code = ?",
            [(warehouse_code,) for warehouse_code in sorted(warehouse_codes)],
        )

    seen_serials = set()
    for index, row in enumerate(rows, start=2):
        center_name = (row.get("centro") or "").strip()
        warehouse_code = (row.get("codigo_almacen") or "").strip()
        warehouse_name = (row.get("almacen") or "").strip()
        material_code = (row.get("codigo_material") or "").strip()
        material_name = (row.get("material") or "").strip()
        serial_number = (row.get("serial") or "").strip()

        if not warehouse_code or not warehouse_name or not material_code or not material_name or not serial_number:
            skipped_rows.append(
                f"Fila {index}: faltan datos clave de almacen, material o serial."
            )
            continue
        if serial_number in seen_serials:
            skipped_rows.append(f"Fila {index}: serial duplicado {serial_number}.")
            continue
        seen_serials.add(serial_number)

        mobile_unit_id = ensure_mobile_unit(
            connection,
            warehouse_code,
            warehouse_description=warehouse_name,
            notes="Detectado desde StockDeEquipos.xlsx",
        )
        storage_location_id = ensure_storage_location(
            connection,
            mobile_unit_id,
            center_name,
            warehouse_code,
            warehouse_name,
        )

        exists = connection.execute(
            "SELECT id FROM equipment_inventory WHERE serial_number = ?",
            (serial_number,),
        ).fetchone()

        payload = (
            storage_location_id,
            mobile_unit_id,
            center_name,
            warehouse_code,
            warehouse_name,
            material_code,
            material_name,
            serial_number,
        )

        if exists:
            connection.execute(
                """
                UPDATE equipment_inventory
                SET storage_location_id = ?, mobile_unit_id = ?, center_name = ?, warehouse_code = ?, warehouse_name = ?,
                    material_code = ?, material_name = ?
                WHERE serial_number = ?
                """,
                payload,
            )
            updated_count += 1
        else:
            connection.execute(
                """
                INSERT INTO equipment_inventory (
                    storage_location_id,
                    mobile_unit_id,
                    center_name,
                    warehouse_code,
                    warehouse_name,
                    material_code,
                    material_name,
                    serial_number
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                payload,
            )
            created_count += 1

    connection.commit()
    return {
        "created_count": created_count,
        "updated_count": updated_count,
        "skipped_rows": skipped_rows,
    }


def detect_material_column(fieldnames):
    for candidate in ("material", "material_name"):
        if candidate in fieldnames:
            return candidate
    return next(iter(fieldnames))


def detect_tool_matches(source_names):
    normalized_sources = [normalize_text_value(name) for name in source_names if name]
    matches = {}

    for item_key, rule in TOOL_MATCH_RULES.items():
        matched_name = find_first_keyword_match(normalized_sources, rule["keywords"])
        if matched_name:
            matches[item_key] = {
                "label": rule["label"],
                "status": "detected",
                "matched_name": matched_name,
            }
        else:
            matches[item_key] = {
                "label": rule["label"],
                "status": "missing",
                "matched_name": None,
            }

    matches["orden_kit"] = {
        "label": "Maletin ordenado y completo",
        "status": "manual_review",
        "matched_name": None,
    }
    return matches


def build_mobile_audit_alerts(mobile, summary, tool_matches):
    alerts = []

    critical_tools = ("cortadora", "medidor")
    missing_critical_tools = [
        tool_matches[item_key]["label"]
        for item_key in critical_tools
        if tool_matches.get(item_key, {}).get("status") == "missing"
    ]

    if missing_critical_tools:
        alerts.append(
            {
                "severity": "critical",
                "title": "Herramientas criticas sin evidencia",
                "detail": "No se detectaron: " + ", ".join(missing_critical_tools) + ".",
            }
        )

    if summary["equipment_count"] == 0:
        alerts.append(
            {
                "severity": "warning",
                "title": "Sin equipos serializados",
                "detail": "El movil no tiene equipos serializados cargados en la base.",
            }
        )

    if summary["stock_item_count"] == 0:
        alerts.append(
            {
                "severity": "warning",
                "title": "Sin stock cargado",
                "detail": "No hay materiales o herramientas asociadas al movil en inventario.",
            }
        )
    elif summary["stock_units_count"] < 5:
        alerts.append(
            {
                "severity": "warning",
                "title": "Stock muy bajo",
                "detail": "El movil tiene pocas unidades cargadas y conviene revisar su kit antes de auditar.",
            }
        )

    if not mobile.get("technician_id"):
        alerts.append(
            {
                "severity": "info",
                "title": "Movil sin tecnico vinculado",
                "detail": "La auditoria puede guardarse igual, pero conviene relacionar el movil a un tecnico estable.",
            }
        )

    if not alerts:
        alerts.append(
            {
                "severity": "ok",
                "title": "Contexto operativo consistente",
                "detail": "Se detecta evidencia base para auditar herramientas del movil.",
            }
        )

    return alerts


def find_first_keyword_match(normalized_sources, keywords):
    for source in normalized_sources:
        for keyword in keywords:
            if normalize_text_value(keyword) in source:
                return source
    return None


def normalize_text_value(value):
    normalized = (value or "").strip().lower()
    replacements = (
        ("á", "a"),
        ("é", "e"),
        ("í", "i"),
        ("ó", "o"),
        ("ú", "u"),
        ("ñ", "n"),
    )
    for original, replacement in replacements:
        normalized = normalized.replace(original, replacement)
    return normalized


def get_mobile_unit_id_by_code(mobile_code):
    if not mobile_code:
        return None
    row = get_db().execute(
        "SELECT id FROM mobile_units WHERE mobile_code = ?",
        (mobile_code,),
    ).fetchone()
    if not row:
        return None
    return row["id"] if is_postgres() else row[0]


def ensure_mobile_unit(
    connection,
    mobile_code,
    user_name=None,
    warehouse_description=None,
    warehouse_type=None,
    is_enabled=None,
    notes=None,
):
    existing_row = connection.execute(
        "SELECT id FROM mobile_units WHERE mobile_code = ?",
        (mobile_code,),
    ).fetchone()
    if existing_row:
        connection.execute(
            """
            UPDATE mobile_units
            SET
                user_name = COALESCE(?, user_name),
                warehouse_description = COALESCE(?, warehouse_description),
                warehouse_type = COALESCE(?, warehouse_type),
                is_enabled = COALESCE(?, is_enabled),
                notes = COALESCE(?, notes)
            WHERE id = ?
            """,
            (
                empty_as_none(user_name),
                empty_as_none(warehouse_description),
                empty_as_none(warehouse_type),
                is_enabled,
                empty_as_none(notes),
                existing_row["id"] if is_postgres() else existing_row[0],
            ),
        )
        return existing_row["id"] if is_postgres() else existing_row[0]

    insert_sql = """
        INSERT INTO mobile_units (
            mobile_code,
            user_name,
            warehouse_description,
            warehouse_type,
            is_enabled,
            notes
        ) VALUES (?, ?, ?, ?, ?, ?)
        """
    insert_params = (
        mobile_code,
        empty_as_none(user_name),
        empty_as_none(warehouse_description),
        empty_as_none(warehouse_type),
        1 if is_enabled is None else is_enabled,
        empty_as_none(notes) or "Codigo de movil tecnico importado",
    )
    if is_postgres():
        cursor = connection.execute(insert_sql + " RETURNING id", insert_params)
        row = cursor.fetchone()
        if not row:
            return None
        return row["id"] if isinstance(row, dict) else row[0]
    cursor = connection.execute(insert_sql, insert_params)
    return cursor.lastrowid


def ensure_storage_location(connection, mobile_unit_id, center_name, warehouse_code, warehouse_name):
    existing_row = connection.execute(
        """
        SELECT id
        FROM storage_locations
        WHERE center_name = ? AND warehouse_code = ?
        """,
        (center_name, warehouse_code),
    ).fetchone()
    if existing_row:
        connection.execute(
            """
            UPDATE storage_locations
            SET mobile_unit_id = ?, warehouse_name = COALESCE(?, warehouse_name)
            WHERE id = ?
            """,
            (mobile_unit_id, empty_as_none(warehouse_name), existing_row["id"] if is_postgres() else existing_row[0]),
        )
        return existing_row["id"] if is_postgres() else existing_row[0]

    insert_sql = """
        INSERT INTO storage_locations (
            mobile_unit_id,
            center_name,
            warehouse_code,
            warehouse_name,
            is_enabled
        ) VALUES (?, ?, ?, ?, 1)
        """
    insert_params = (mobile_unit_id, center_name or "Sin centro", warehouse_code, warehouse_name or warehouse_code)
    if is_postgres():
        cursor = connection.execute(insert_sql + " RETURNING id", insert_params)
        row = cursor.fetchone()
        if not row:
            return None
        return row["id"] if isinstance(row, dict) else row[0]
    cursor = connection.execute(insert_sql, insert_params)
    return cursor.lastrowid


def ensure_material(connection, material_code, material_name):
    existing_row = connection.execute(
        "SELECT id FROM materials WHERE material_name = ?",
        (material_name,),
    ).fetchone()
    if existing_row:
        connection.execute(
            "UPDATE materials SET material_code = COALESCE(?, material_code) WHERE id = ?",
            (material_code, existing_row["id"] if is_postgres() else existing_row[0]),
        )
        return (existing_row["id"] if is_postgres() else existing_row[0]), False

    insert_sql = "INSERT INTO materials (material_code, material_name) VALUES (?, ?)"
    insert_params = (material_code, material_name)
    if is_postgres():
        cursor = connection.execute(insert_sql + " RETURNING id", insert_params)
        row = cursor.fetchone()
        if not row:
            return None, True
        return (row["id"] if isinstance(row, dict) else row[0]), True
    cursor = connection.execute(insert_sql, insert_params)
    return cursor.lastrowid, True


def split_material_label(material_label):
    cleaned_label = material_label.strip()
    if cleaned_label.startswith("[") and "]" in cleaned_label:
        material_code, material_name = cleaned_label[1:].split("]", 1)
        return material_code.strip(), material_name.strip()
    return None, cleaned_label


def normalize_mobile_code(value):
    cleaned_value = (value or "").strip()
    if cleaned_value.lower() == "total":
        return None
    if cleaned_value and all(ch.isdigit() or ch in {".", ","} for ch in cleaned_value) and (
        "." in cleaned_value or "," in cleaned_value
    ):
        numeric_value = normalize_float_value(cleaned_value)
        if numeric_value is not None and float(numeric_value).is_integer():
            return str(int(numeric_value))
    return cleaned_value


def normalize_active_value(value):
    normalized = (value or "1").strip().lower()
    return 0 if normalized in {"0", "false", "no", "inactivo"} else 1


def normalize_integer_value(value):
    cleaned_value = (value or "").strip()
    if not cleaned_value:
        return None
    try:
        return int(cleaned_value)
    except ValueError:
        return None


def normalize_float_value(value):
    cleaned_value = (value or "").strip().replace(",", ".")
    if not cleaned_value:
        return None
    try:
        return float(cleaned_value)
    except ValueError:
        return None


def normalize_yes_no_value(value):
    normalized = (value or "").strip().lower()
    if normalized in {"si", "sí", "1", "true", "activo", "habilitado"}:
        return 1
    if normalized in {"no", "0", "false", "inactivo", "deshabilitado"}:
        return 0
    return 1


def empty_as_none(value):
    cleaned_value = (value or "").strip()
    return cleaned_value or None
