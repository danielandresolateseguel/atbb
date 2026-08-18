import sqlite3
import unicodedata
import json
from datetime import datetime, timedelta, timezone

from flask import current_app, g
from werkzeug.security import generate_password_hash

from app.checklist import TOOL_MATCH_RULES

try:
    from zoneinfo import ZoneInfo
except ImportError:
    ZoneInfo = None


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


def _app_timezone():
    name = (current_app.config.get("APP_TIMEZONE") or "").strip() or "America/Argentina/Buenos_Aires"
    if ZoneInfo:
        try:
            return ZoneInfo(name)
        except Exception:
            return timezone(timedelta(hours=-3))
    return timezone(timedelta(hours=-3))


def _today_in_app_tz():
    return datetime.now(timezone.utc).astimezone(_app_timezone()).date()


def _date_range_end_in_app_tz(days):
    return _today_in_app_tz() + timedelta(days=int(days or 0))


def _pending_validation_cutoff_in_app_tz(days):
    return _today_in_app_tz() - timedelta(days=max(0, int(days or 0)))


TREATMENT_REASON_OPTIONS = [
    ("esperando_proveedor", "Esperando proveedor"),
    ("sin_stock", "Sin stock"),
    ("esperando_aprobacion", "Esperando aprobacion"),
    ("pendiente_programacion", "Pendiente programacion"),
    ("en_ejecucion", "En ejecucion"),
    ("bloqueado_tercero", "Bloqueado por tercero"),
    ("otro", "Otro"),
]

TREATMENT_REASON_LABELS = {value: label for value, label in TREATMENT_REASON_OPTIONS}


AUDIT_SCOPE_OFFICIAL = "oficial"
AUDIT_SCOPE_TESTING = "pruebas"

AUDIT_MATERIAL_STOCK_PRIORITY_NAMES = [
    "CBL.DROP PLANO 70M G657 CONECT.RE. FORZ",
    "CONECT.OPT.MEC.SC/APC P/CBL.DROP",
    "CTRL.REM.P/DECO ANDROID TV (FLOW) V3",
    "PILAS AAA",
    "TALONARIO DE GARANTIAS 30 DÍAS",
    "VASO TERMICO - INVIERNO 2025",
]


def normalize_audit_record_scope(value):
    normalized = (value or AUDIT_SCOPE_OFFICIAL).strip().lower()
    if normalized == AUDIT_SCOPE_TESTING:
        return AUDIT_SCOPE_TESTING
    return AUDIT_SCOPE_OFFICIAL


def normalize_material_name(value):
    raw = " ".join(str(value or "").strip().upper().split())
    if not raw:
        return ""
    normalized = unicodedata.normalize("NFKD", raw)
    return "".join(char for char in normalized if not unicodedata.combining(char))


_AUDIT_MATERIAL_STOCK_PRIORITY_TOKENS = [
    normalize_material_name(name) for name in AUDIT_MATERIAL_STOCK_PRIORITY_NAMES
]


def _audit_material_stock_priority_index(material_name):
    normalized = normalize_material_name(material_name)
    if not normalized:
        return None
    for idx, token in enumerate(_AUDIT_MATERIAL_STOCK_PRIORITY_TOKENS):
        if normalized == token or token in normalized:
            return idx
    return None


def normalize_supervisor_scope_name(value):
    return " ".join((value or "").strip().split()).upper()


def normalize_supervisor_scope_names(values):
    normalized_values = []
    seen = set()
    for value in values or []:
        normalized = normalize_supervisor_scope_name(value)
        if not normalized or normalized in seen:
            continue
        seen.add(normalized)
        normalized_values.append(normalized)
    return normalized_values


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


def _sqlite_greatest(*args):
    non_null = [a for a in args if a is not None]
    if not non_null:
        return None
    return max(non_null)


def _sqlite_least(*args):
    non_null = [a for a in args if a is not None]
    if not non_null:
        return None
    return min(non_null)


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
            try:
                connection.create_function("GREATEST", -1, _sqlite_greatest)
                connection.create_function("LEAST", -1, _sqlite_least)
            except Exception:
                pass
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

        CREATE TABLE IF NOT EXISTS user_supervisor_scopes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            user_id INTEGER NOT NULL,
            supervisor_name TEXT NOT NULL,
            is_active INTEGER NOT NULL DEFAULT 1,
            UNIQUE(user_id, supervisor_name),
            FOREIGN KEY (user_id) REFERENCES users (id)
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

        CREATE TABLE IF NOT EXISTS import_batches (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            status TEXT NOT NULL DEFAULT 'completed',
            import_type TEXT NOT NULL,
            import_label TEXT NOT NULL,
            filename TEXT,
            file_sha256 TEXT,
            uploaded_by_user_id INTEGER,
            uploaded_by_username TEXT,
            uploaded_by_role TEXT,
            row_count INTEGER NOT NULL DEFAULT 0,
            created_count INTEGER NOT NULL DEFAULT 0,
            updated_count INTEGER NOT NULL DEFAULT 0,
            skipped_rows_json TEXT,
            scope_json TEXT,
            can_rollback INTEGER NOT NULL DEFAULT 0,
            rolled_back_at TEXT,
            rolled_back_by_user_id INTEGER,
            error_message TEXT,
            FOREIGN KEY (uploaded_by_user_id) REFERENCES users (id),
            FOREIGN KEY (rolled_back_by_user_id) REFERENCES users (id)
        );

        CREATE TABLE IF NOT EXISTS material_stock_import_backups (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            batch_id INTEGER NOT NULL,
            mobile_unit_id INTEGER NOT NULL,
            material_id INTEGER NOT NULL,
            quantity REAL NOT NULL DEFAULT 0,
            UNIQUE(batch_id, mobile_unit_id, material_id),
            FOREIGN KEY (batch_id) REFERENCES import_batches (id),
            FOREIGN KEY (mobile_unit_id) REFERENCES mobile_units (id),
            FOREIGN KEY (material_id) REFERENCES materials (id)
        );

        CREATE TABLE IF NOT EXISTS equipment_inventory_import_backups (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            batch_id INTEGER NOT NULL,
            storage_location_id INTEGER,
            mobile_unit_id INTEGER,
            center_name TEXT NOT NULL,
            warehouse_code TEXT NOT NULL,
            warehouse_name TEXT NOT NULL,
            material_code TEXT NOT NULL,
            material_name TEXT NOT NULL,
            serial_number TEXT NOT NULL,
            UNIQUE(batch_id, serial_number),
            FOREIGN KEY (batch_id) REFERENCES import_batches (id),
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
            technician_company_snapshot TEXT,
            technician_supervisor_snapshot TEXT,
            technician_center_snapshot TEXT,
            location TEXT NOT NULL,
            address TEXT,
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

        CREATE TABLE IF NOT EXISTS audit_findings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            audit_id INTEGER NOT NULL,
            audit_item_id INTEGER NOT NULL,
            technician_id INTEGER,
            supervisor_name TEXT,
            owner_user_id INTEGER,
            item_status TEXT NOT NULL,
            finding_status TEXT NOT NULL DEFAULT 'nuevo',
            priority TEXT NOT NULL DEFAULT 'media',
            response_notes TEXT,
            treatment_reason TEXT,
            treatment_note TEXT,
            treatment_next_step TEXT,
            treatment_commitment_date TEXT,
            evidence_path TEXT,
            closure_criteria TEXT,
            effectiveness_due_date TEXT,
            effectiveness_status TEXT,
            effectiveness_notes TEXT,
            effectiveness_verified_at TEXT,
            effectiveness_verified_by_user_id INTEGER,
            responded_by_user_id INTEGER,
            responded_at TEXT,
            resolved_at TEXT,
            validated_by_user_id INTEGER,
            validated_at TEXT,
            validation_status TEXT,
            validation_notes TEXT,
            FOREIGN KEY (audit_id) REFERENCES audits (id),
            FOREIGN KEY (audit_item_id) REFERENCES audit_items (id),
            FOREIGN KEY (technician_id) REFERENCES technicians (id),
            FOREIGN KEY (owner_user_id) REFERENCES users (id),
            FOREIGN KEY (effectiveness_verified_by_user_id) REFERENCES users (id),
            FOREIGN KEY (responded_by_user_id) REFERENCES users (id),
            FOREIGN KEY (validated_by_user_id) REFERENCES users (id)
        );

        CREATE TABLE IF NOT EXISTS audit_finding_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            finding_id INTEGER NOT NULL,
            actor_user_id INTEGER,
            event_type TEXT NOT NULL,
            detail TEXT,
            FOREIGN KEY (finding_id) REFERENCES audit_findings (id),
            FOREIGN KEY (actor_user_id) REFERENCES users (id)
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
            router_optimal_location INTEGER,
            environment_clean_order INTEGER,
            speedtest_done INTEGER,
            comment TEXT,
            customer_name TEXT,
            technician_id INTEGER,
            audit_id INTEGER,
            qc_session_id INTEGER,
            FOREIGN KEY (technician_id) REFERENCES technicians (id),
            FOREIGN KEY (audit_id) REFERENCES audits (id),
            FOREIGN KEY (qc_session_id) REFERENCES qc_sessions (id)
        );

        CREATE TABLE IF NOT EXISTS qc_sessions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            qc_date TEXT NOT NULL,
            auditor_name TEXT NOT NULL,
            auditor_user_id INTEGER,
            sa_number TEXT,
            technician_display_name TEXT,
            technician_employee_code TEXT,
            technician_company_snapshot TEXT,
            technician_supervisor_snapshot TEXT,
            technician_center_snapshot TEXT,
            technician_id INTEGER NOT NULL,
            audit_id INTEGER,
            location TEXT NOT NULL,
            address TEXT,
            installation_type TEXT NOT NULL,
            total_score REAL NOT NULL DEFAULT 0,
            result_status TEXT NOT NULL,
            record_scope TEXT NOT NULL DEFAULT 'oficial',
            general_notes TEXT,
            photo_path TEXT,
            qc_live_installation INTEGER NOT NULL DEFAULT 0,
            installation_duration_minutes INTEGER,
            cable_type TEXT,
            cable_meters INTEGER,
            FOREIGN KEY (technician_id) REFERENCES technicians (id),
            FOREIGN KEY (audit_id) REFERENCES audits (id),
            FOREIGN KEY (auditor_user_id) REFERENCES users (id)
        );

        CREATE TABLE IF NOT EXISTS qc_items (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            qc_session_id INTEGER NOT NULL,
            section_key TEXT NOT NULL,
            section_title TEXT NOT NULL,
            item_key TEXT NOT NULL,
            item_label TEXT NOT NULL,
            status TEXT NOT NULL,
            is_critical INTEGER NOT NULL DEFAULT 0,
            non_compliance_reason TEXT,
            notes TEXT,
            photo_path TEXT,
            FOREIGN KEY (qc_session_id) REFERENCES qc_sessions (id)
        );

        CREATE TABLE IF NOT EXISTS service_sessions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            service_date TEXT NOT NULL,
            auditor_name TEXT NOT NULL,
            auditor_user_id INTEGER,
            sa_number TEXT,
            technician_display_name TEXT,
            technician_employee_code TEXT,
            technician_company_snapshot TEXT,
            technician_supervisor_snapshot TEXT,
            technician_center_snapshot TEXT,
            technician_id INTEGER NOT NULL,
            location TEXT NOT NULL,
            address TEXT,
            optical_expected_dbm REAL,
            optical_measured_dbm REAL,
            optical_delta_dbm REAL,
            total_score REAL NOT NULL DEFAULT 0,
            result_status TEXT NOT NULL,
            record_scope TEXT NOT NULL DEFAULT 'oficial',
            general_notes TEXT,
            photo_path TEXT,
            FOREIGN KEY (technician_id) REFERENCES technicians (id),
            FOREIGN KEY (auditor_user_id) REFERENCES users (id)
        );

        CREATE TABLE IF NOT EXISTS service_items (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            service_session_id INTEGER NOT NULL,
            item_key TEXT NOT NULL,
            item_label TEXT NOT NULL,
            status TEXT NOT NULL,
            is_critical INTEGER NOT NULL DEFAULT 0,
            notes TEXT,
            photo_path TEXT,
            FOREIGN KEY (service_session_id) REFERENCES service_sessions (id)
        );

        CREATE TABLE IF NOT EXISTS service_speedtests (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            service_session_id INTEGER NOT NULL,
            space_key TEXT NOT NULL,
            space_label TEXT NOT NULL,
            download_mbps REAL,
            upload_mbps REAL,
            ping_ms REAL,
            FOREIGN KEY (service_session_id) REFERENCES service_sessions (id)
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
        CREATE TABLE IF NOT EXISTS user_supervisor_scopes (
            id SERIAL PRIMARY KEY,
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            user_id INTEGER NOT NULL REFERENCES users (id),
            supervisor_name TEXT NOT NULL,
            is_active INTEGER NOT NULL DEFAULT 1,
            UNIQUE(user_id, supervisor_name)
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
        CREATE TABLE IF NOT EXISTS import_batches (
            id SERIAL PRIMARY KEY,
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            status TEXT NOT NULL DEFAULT 'completed',
            import_type TEXT NOT NULL,
            import_label TEXT NOT NULL,
            filename TEXT,
            file_sha256 TEXT,
            uploaded_by_user_id INTEGER REFERENCES users (id),
            uploaded_by_username TEXT,
            uploaded_by_role TEXT,
            row_count INTEGER NOT NULL DEFAULT 0,
            created_count INTEGER NOT NULL DEFAULT 0,
            updated_count INTEGER NOT NULL DEFAULT 0,
            skipped_rows_json TEXT,
            scope_json TEXT,
            can_rollback INTEGER NOT NULL DEFAULT 0,
            rolled_back_at TIMESTAMPTZ,
            rolled_back_by_user_id INTEGER REFERENCES users (id),
            error_message TEXT
        )
        """
    )
    cursor.execute("ALTER TABLE import_batches ADD COLUMN IF NOT EXISTS scope_json TEXT")

    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS material_stock_import_backups (
            id SERIAL PRIMARY KEY,
            batch_id INTEGER NOT NULL REFERENCES import_batches (id) ON DELETE CASCADE,
            mobile_unit_id INTEGER NOT NULL REFERENCES mobile_units (id),
            material_id INTEGER NOT NULL REFERENCES materials (id),
            quantity DOUBLE PRECISION NOT NULL DEFAULT 0,
            UNIQUE(batch_id, mobile_unit_id, material_id)
        )
        """
    )

    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS equipment_inventory_import_backups (
            id SERIAL PRIMARY KEY,
            batch_id INTEGER NOT NULL REFERENCES import_batches (id) ON DELETE CASCADE,
            storage_location_id INTEGER REFERENCES storage_locations (id),
            mobile_unit_id INTEGER REFERENCES mobile_units (id),
            center_name TEXT NOT NULL,
            warehouse_code TEXT NOT NULL,
            warehouse_name TEXT NOT NULL,
            material_code TEXT NOT NULL,
            material_name TEXT NOT NULL,
            serial_number TEXT NOT NULL,
            UNIQUE(batch_id, serial_number)
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
            technician_company_snapshot TEXT,
            technician_supervisor_snapshot TEXT,
            technician_center_snapshot TEXT,
            location TEXT NOT NULL,
            address TEXT,
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
        CREATE TABLE IF NOT EXISTS audit_findings (
            id SERIAL PRIMARY KEY,
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            audit_id INTEGER NOT NULL REFERENCES audits (id),
            audit_item_id INTEGER NOT NULL REFERENCES audit_items (id),
            technician_id INTEGER REFERENCES technicians (id),
            supervisor_name TEXT,
            owner_user_id INTEGER REFERENCES users (id),
            item_status TEXT NOT NULL,
            finding_status TEXT NOT NULL DEFAULT 'nuevo',
            priority TEXT NOT NULL DEFAULT 'media',
            response_notes TEXT,
            treatment_reason TEXT,
            treatment_note TEXT,
            treatment_next_step TEXT,
            treatment_commitment_date TEXT,
            evidence_path TEXT,
            closure_criteria TEXT,
            effectiveness_due_date TEXT,
            effectiveness_status TEXT,
            effectiveness_notes TEXT,
            effectiveness_verified_at TIMESTAMPTZ,
            effectiveness_verified_by_user_id INTEGER REFERENCES users (id),
            responded_by_user_id INTEGER REFERENCES users (id),
            responded_at TIMESTAMPTZ,
            resolved_at TIMESTAMPTZ,
            validated_by_user_id INTEGER REFERENCES users (id),
            validated_at TIMESTAMPTZ,
            validation_status TEXT,
            validation_notes TEXT
        )
        """
    )

    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS audit_finding_events (
            id SERIAL PRIMARY KEY,
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            finding_id INTEGER NOT NULL REFERENCES audit_findings (id),
            actor_user_id INTEGER REFERENCES users (id),
            event_type TEXT NOT NULL,
            detail TEXT
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
            router_optimal_location INTEGER,
            environment_clean_order INTEGER,
            speedtest_done INTEGER,
            comment TEXT,
            customer_name TEXT,
            technician_id INTEGER REFERENCES technicians (id),
            audit_id INTEGER REFERENCES audits (id),
            qc_session_id INTEGER
        )
        """
    )

    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS qc_sessions (
            id SERIAL PRIMARY KEY,
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            qc_date TEXT NOT NULL,
            auditor_name TEXT NOT NULL,
            auditor_user_id INTEGER REFERENCES users (id),
            sa_number TEXT,
            technician_display_name TEXT,
            technician_employee_code TEXT,
            technician_company_snapshot TEXT,
            technician_supervisor_snapshot TEXT,
            technician_center_snapshot TEXT,
            technician_id INTEGER NOT NULL REFERENCES technicians (id),
            audit_id INTEGER REFERENCES audits (id),
            location TEXT NOT NULL,
            address TEXT,
            installation_type TEXT NOT NULL,
            total_score DOUBLE PRECISION NOT NULL DEFAULT 0,
            result_status TEXT NOT NULL,
            record_scope TEXT NOT NULL DEFAULT 'oficial',
            general_notes TEXT,
            photo_path TEXT,
            qc_live_installation INTEGER NOT NULL DEFAULT 0,
            installation_duration_minutes INTEGER,
            cable_type TEXT,
            cable_meters INTEGER
        )
        """
    )

    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS qc_items (
            id SERIAL PRIMARY KEY,
            qc_session_id INTEGER NOT NULL REFERENCES qc_sessions (id),
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
        CREATE TABLE IF NOT EXISTS service_sessions (
            id SERIAL PRIMARY KEY,
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            service_date TEXT NOT NULL,
            auditor_name TEXT NOT NULL,
            auditor_user_id INTEGER REFERENCES users (id),
            sa_number TEXT,
            technician_display_name TEXT,
            technician_employee_code TEXT,
            technician_company_snapshot TEXT,
            technician_supervisor_snapshot TEXT,
            technician_center_snapshot TEXT,
            technician_id INTEGER NOT NULL REFERENCES technicians (id),
            location TEXT NOT NULL,
            address TEXT,
            optical_expected_dbm DOUBLE PRECISION,
            optical_measured_dbm DOUBLE PRECISION,
            optical_delta_dbm DOUBLE PRECISION,
            total_score DOUBLE PRECISION NOT NULL DEFAULT 0,
            result_status TEXT NOT NULL,
            record_scope TEXT NOT NULL DEFAULT 'oficial',
            general_notes TEXT,
            photo_path TEXT
        )
        """
    )

    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS service_items (
            id SERIAL PRIMARY KEY,
            service_session_id INTEGER NOT NULL REFERENCES service_sessions (id),
            item_key TEXT NOT NULL,
            item_label TEXT NOT NULL,
            status TEXT NOT NULL,
            is_critical INTEGER NOT NULL DEFAULT 0,
            notes TEXT,
            photo_path TEXT
        )
        """
    )

    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS service_speedtests (
            id SERIAL PRIMARY KEY,
            service_session_id INTEGER NOT NULL REFERENCES service_sessions (id),
            space_key TEXT NOT NULL,
            space_label TEXT NOT NULL,
            download_mbps DOUBLE PRECISION,
            upload_mbps DOUBLE PRECISION,
            ping_ms DOUBLE PRECISION
        )
        """
    )

    ensure_technicians_columns_postgres(cursor)
    ensure_audits_columns_postgres(cursor)
    ensure_audit_findings_columns_postgres(cursor)
    ensure_tnps_columns_postgres(cursor)
    ensure_qc_columns_postgres(cursor)
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
        SELECT
            users.id,
            users.username,
            users.password_hash,
            users.role,
            users.is_active,
            COALESCE((
                SELECT COUNT(*)
                FROM user_supervisor_scopes
                WHERE user_supervisor_scopes.user_id = users.id
                  AND user_supervisor_scopes.is_active = 1
            ), 0) AS supervisor_scope_count
        FROM users
        WHERE users.id = ?
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
        SELECT
            users.id,
            users.username,
            users.password_hash,
            users.role,
            users.is_active,
            COALESCE((
                SELECT COUNT(*)
                FROM user_supervisor_scopes
                WHERE user_supervisor_scopes.user_id = users.id
                  AND user_supervisor_scopes.is_active = 1
            ), 0) AS supervisor_scope_count
        FROM users
        WHERE users.username = ?
        """,
        (normalized,),
    ).fetchone()
    return dict(row) if row else None


def fetch_users():
    created_at_expr = "created_at"
    rows = get_db().execute(
        f"""
        SELECT
            users.id,
            users.username,
            users.role,
            users.is_active,
            {created_at_expr} AS created_at,
            COALESCE((
                SELECT COUNT(*)
                FROM user_supervisor_scopes
                WHERE user_supervisor_scopes.user_id = users.id
                  AND user_supervisor_scopes.is_active = 1
            ), 0) AS supervisor_scope_count
        FROM users
        ORDER BY users.username ASC
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


def fetch_user_supervisor_scopes(user_id, only_active=True):
    where_clauses = ["user_id = ?"]
    params = [user_id]
    if only_active:
        where_clauses.append("is_active = 1")

    rows = get_db().execute(
        f"""
        SELECT
            id,
            user_id,
            supervisor_name,
            is_active,
            created_at
        FROM user_supervisor_scopes
        WHERE {' AND '.join(where_clauses)}
        ORDER BY supervisor_name ASC
        """,
        tuple(params),
    ).fetchall()
    return [dict(row) for row in rows]


def fetch_user_supervisor_scope_names(user_id, only_active=True):
    return [row["supervisor_name"] for row in fetch_user_supervisor_scopes(user_id, only_active=only_active)]


def replace_user_supervisor_scopes(user_id, supervisor_names):
    normalized_names = normalize_supervisor_scope_names(supervisor_names)
    connection = get_db()
    connection.execute("DELETE FROM user_supervisor_scopes WHERE user_id = ?", (user_id,))
    if normalized_names:
        connection.executemany(
            """
            INSERT INTO user_supervisor_scopes (user_id, supervisor_name, is_active)
            VALUES (?, ?, 1)
            """,
            [(user_id, name) for name in normalized_names],
        )
    connection.commit()
    return normalized_names


def find_owner_user_id_by_supervisor_name(supervisor_name):
    normalized_name = normalize_supervisor_scope_name(supervisor_name)
    if not normalized_name:
        return None

    rows = get_db().execute(
        """
        SELECT users.id
        FROM users
        INNER JOIN user_supervisor_scopes ON user_supervisor_scopes.user_id = users.id
        WHERE users.role = 'supervisor'
          AND users.is_active = 1
          AND user_supervisor_scopes.is_active = 1
          AND user_supervisor_scopes.supervisor_name = ?
        ORDER BY users.username ASC
        """,
        (normalized_name,),
    ).fetchall()
    if len(rows) != 1:
        return None
    row = rows[0]
    return row["id"] if isinstance(row, dict) else row[0]


def append_supervisor_scope_filters(where_clauses, params, supervisor_scope_names=None, audit_table_alias="audits"):
    if supervisor_scope_names is None:
        return

    normalized_names = normalize_supervisor_scope_names(supervisor_scope_names)
    if not normalized_names:
        where_clauses.append("1 = 0")
        return

    placeholders = ", ".join(["?"] * len(normalized_names))
    where_clauses.append(
        f"""
        (
            UPPER(TRIM(COALESCE({audit_table_alias}.technician_supervisor_snapshot, ''))) IN ({placeholders})
            OR (
                COALESCE({audit_table_alias}.technician_supervisor_snapshot, '') = ''
                AND {audit_table_alias}.technician_id IN (
                    SELECT technicians.id
                    FROM technicians
                    WHERE UPPER(TRIM(COALESCE(technicians.supervisor_name, ''))) IN ({placeholders})
                )
            )
        )
        """
    )
    params.extend(normalized_names)
    params.extend(normalized_names)


def create_user(username, password, role="auditor", is_active=1):
    normalized = (username or "").strip()
    if not normalized:
        raise ValueError("El usuario es obligatorio.")
    raw_password = (password or "").strip()
    if not raw_password:
        raise ValueError("La contraseña es obligatoria.")

    safe_role = (role or "auditor").strip().lower()
    if safe_role not in {"admin", "auditor", "gerente", "supervisor"}:
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
    if safe_role not in {"admin", "auditor", "gerente", "supervisor"}:
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
    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS user_supervisor_scopes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            user_id INTEGER NOT NULL,
            supervisor_name TEXT NOT NULL,
            is_active INTEGER NOT NULL DEFAULT 1,
            UNIQUE(user_id, supervisor_name),
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
        """
    )
    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS import_batches (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            status TEXT NOT NULL DEFAULT 'completed',
            import_type TEXT NOT NULL,
            import_label TEXT NOT NULL,
            filename TEXT,
            file_sha256 TEXT,
            uploaded_by_user_id INTEGER,
            uploaded_by_username TEXT,
            uploaded_by_role TEXT,
            row_count INTEGER NOT NULL DEFAULT 0,
            created_count INTEGER NOT NULL DEFAULT 0,
            updated_count INTEGER NOT NULL DEFAULT 0,
            skipped_rows_json TEXT,
            scope_json TEXT,
            can_rollback INTEGER NOT NULL DEFAULT 0,
            rolled_back_at TEXT,
            rolled_back_by_user_id INTEGER,
            error_message TEXT,
            FOREIGN KEY (uploaded_by_user_id) REFERENCES users (id),
            FOREIGN KEY (rolled_back_by_user_id) REFERENCES users (id)
        )
        """
    )
    add_column_if_missing(connection, "import_batches", "scope_json", "TEXT")
    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS material_stock_import_backups (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            batch_id INTEGER NOT NULL,
            mobile_unit_id INTEGER NOT NULL,
            material_id INTEGER NOT NULL,
            quantity REAL NOT NULL DEFAULT 0,
            UNIQUE(batch_id, mobile_unit_id, material_id),
            FOREIGN KEY (batch_id) REFERENCES import_batches (id),
            FOREIGN KEY (mobile_unit_id) REFERENCES mobile_units (id),
            FOREIGN KEY (material_id) REFERENCES materials (id)
        )
        """
    )
    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS equipment_inventory_import_backups (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            batch_id INTEGER NOT NULL,
            storage_location_id INTEGER,
            mobile_unit_id INTEGER,
            center_name TEXT NOT NULL,
            warehouse_code TEXT NOT NULL,
            warehouse_name TEXT NOT NULL,
            material_code TEXT NOT NULL,
            material_name TEXT NOT NULL,
            serial_number TEXT NOT NULL,
            UNIQUE(batch_id, serial_number),
            FOREIGN KEY (batch_id) REFERENCES import_batches (id),
            FOREIGN KEY (storage_location_id) REFERENCES storage_locations (id),
            FOREIGN KEY (mobile_unit_id) REFERENCES mobile_units (id)
        )
        """
    )
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
    add_column_if_missing(connection, "audits", "technician_company_snapshot", "TEXT")
    add_column_if_missing(connection, "audits", "technician_supervisor_snapshot", "TEXT")
    add_column_if_missing(connection, "audits", "technician_center_snapshot", "TEXT")
    add_column_if_missing(connection, "audits", "address", "TEXT")
    add_column_if_missing(connection, "audits", "record_scope", "TEXT NOT NULL DEFAULT 'oficial'")
    add_column_if_missing(connection, "audits", "serialized_stock_status", "TEXT")
    add_column_if_missing(connection, "audits", "serialized_stock_notes", "TEXT")
    add_column_if_missing(connection, "audits", "material_stock_status", "TEXT")
    add_column_if_missing(connection, "audits", "material_stock_notes", "TEXT")
    add_column_if_missing(connection, "audit_items", "non_compliance_reason", "TEXT")
    add_column_if_missing(connection, "audit_items", "photo_path", "TEXT")
    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS audit_findings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            audit_id INTEGER NOT NULL,
            audit_item_id INTEGER NOT NULL,
            technician_id INTEGER,
            supervisor_name TEXT,
            owner_user_id INTEGER,
            item_status TEXT NOT NULL,
            finding_status TEXT NOT NULL DEFAULT 'nuevo',
            priority TEXT NOT NULL DEFAULT 'media',
            response_notes TEXT,
            treatment_reason TEXT,
            treatment_note TEXT,
            treatment_next_step TEXT,
            treatment_commitment_date TEXT,
            evidence_path TEXT,
            closure_criteria TEXT,
            effectiveness_due_date TEXT,
            effectiveness_status TEXT,
            effectiveness_notes TEXT,
            effectiveness_verified_at TEXT,
            effectiveness_verified_by_user_id INTEGER,
            responded_by_user_id INTEGER,
            responded_at TEXT,
            resolved_at TEXT,
            validated_by_user_id INTEGER,
            validated_at TEXT,
            validation_status TEXT,
            validation_notes TEXT,
            FOREIGN KEY (audit_id) REFERENCES audits (id),
            FOREIGN KEY (audit_item_id) REFERENCES audit_items (id),
            FOREIGN KEY (technician_id) REFERENCES technicians (id),
            FOREIGN KEY (owner_user_id) REFERENCES users (id),
            FOREIGN KEY (effectiveness_verified_by_user_id) REFERENCES users (id),
            FOREIGN KEY (responded_by_user_id) REFERENCES users (id),
            FOREIGN KEY (validated_by_user_id) REFERENCES users (id)
        )
        """
    )
    add_column_if_missing(connection, "audit_findings", "closure_criteria", "TEXT")
    add_column_if_missing(connection, "audit_findings", "effectiveness_due_date", "TEXT")
    add_column_if_missing(connection, "audit_findings", "effectiveness_status", "TEXT")
    add_column_if_missing(connection, "audit_findings", "effectiveness_notes", "TEXT")
    add_column_if_missing(connection, "audit_findings", "effectiveness_verified_at", "TEXT")
    add_column_if_missing(connection, "audit_findings", "effectiveness_verified_by_user_id", "INTEGER")
    add_column_if_missing(connection, "audit_findings", "treatment_reason", "TEXT")
    add_column_if_missing(connection, "audit_findings", "treatment_note", "TEXT")
    add_column_if_missing(connection, "audit_findings", "treatment_next_step", "TEXT")
    add_column_if_missing(connection, "audit_findings", "treatment_commitment_date", "TEXT")
    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS audit_finding_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            finding_id INTEGER NOT NULL,
            actor_user_id INTEGER,
            event_type TEXT NOT NULL,
            detail TEXT,
            FOREIGN KEY (finding_id) REFERENCES audit_findings (id),
            FOREIGN KEY (actor_user_id) REFERENCES users (id)
        )
        """
    )
    add_column_if_missing(connection, "tnps_responses", "booking_ease_score", "INTEGER")
    add_column_if_missing(connection, "tnps_responses", "punctuality_score", "INTEGER")
    add_column_if_missing(connection, "tnps_responses", "communication_clarity_score", "INTEGER")
    add_column_if_missing(connection, "tnps_responses", "issue_resolved_first_visit", "INTEGER")
    add_column_if_missing(connection, "tnps_responses", "router_optimal_location", "INTEGER")
    add_column_if_missing(connection, "tnps_responses", "environment_clean_order", "INTEGER")
    add_column_if_missing(connection, "tnps_responses", "speedtest_done", "INTEGER")
    add_column_if_missing(connection, "tnps_responses", "qc_session_id", "INTEGER")
    add_column_if_missing(connection, "qc_sessions", "photo_path", "TEXT")
    add_column_if_missing(connection, "qc_sessions", "qc_live_installation", "INTEGER NOT NULL DEFAULT 0")
    add_column_if_missing(connection, "qc_sessions", "installation_duration_minutes", "INTEGER")
    add_column_if_missing(connection, "qc_sessions", "cable_type", "TEXT")
    add_column_if_missing(connection, "qc_sessions", "cable_meters", "INTEGER")
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
            technician_company_snapshot TEXT,
            technician_supervisor_snapshot TEXT,
            technician_center_snapshot TEXT,
            location TEXT NOT NULL,
            address TEXT,
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
            technician_company_snapshot,
            technician_supervisor_snapshot,
            technician_center_snapshot,
            location,
            address,
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
            technician_company_snapshot,
            technician_supervisor_snapshot,
            technician_center_snapshot,
            location,
            address,
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
    cursor.execute("ALTER TABLE audits ADD COLUMN IF NOT EXISTS address TEXT")
    cursor.execute("ALTER TABLE audits ADD COLUMN IF NOT EXISTS record_scope TEXT NOT NULL DEFAULT 'oficial'")
    cursor.execute("ALTER TABLE audits ADD COLUMN IF NOT EXISTS technician_company_snapshot TEXT")
    cursor.execute("ALTER TABLE audits ADD COLUMN IF NOT EXISTS technician_supervisor_snapshot TEXT")
    cursor.execute("ALTER TABLE audits ADD COLUMN IF NOT EXISTS technician_center_snapshot TEXT")


def ensure_audit_findings_columns_postgres(cursor):
    cursor.execute("ALTER TABLE audit_findings ADD COLUMN IF NOT EXISTS closure_criteria TEXT")
    cursor.execute("ALTER TABLE audit_findings ADD COLUMN IF NOT EXISTS effectiveness_due_date TEXT")
    cursor.execute("ALTER TABLE audit_findings ADD COLUMN IF NOT EXISTS effectiveness_status TEXT")
    cursor.execute("ALTER TABLE audit_findings ADD COLUMN IF NOT EXISTS effectiveness_notes TEXT")
    cursor.execute("ALTER TABLE audit_findings ADD COLUMN IF NOT EXISTS effectiveness_verified_at TIMESTAMPTZ")
    cursor.execute("ALTER TABLE audit_findings ADD COLUMN IF NOT EXISTS treatment_reason TEXT")
    cursor.execute("ALTER TABLE audit_findings ADD COLUMN IF NOT EXISTS treatment_note TEXT")
    cursor.execute("ALTER TABLE audit_findings ADD COLUMN IF NOT EXISTS treatment_next_step TEXT")
    cursor.execute("ALTER TABLE audit_findings ADD COLUMN IF NOT EXISTS treatment_commitment_date TEXT")
    cursor.execute(
        "ALTER TABLE audit_findings ADD COLUMN IF NOT EXISTS effectiveness_verified_by_user_id INTEGER REFERENCES users (id)"
    )
    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS audit_finding_events (
            id SERIAL PRIMARY KEY,
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            finding_id INTEGER NOT NULL REFERENCES audit_findings (id),
            actor_user_id INTEGER REFERENCES users (id),
            event_type TEXT NOT NULL,
            detail TEXT
        )
        """
    )


def ensure_tnps_columns_postgres(cursor):
    cursor.execute("ALTER TABLE tnps_responses ADD COLUMN IF NOT EXISTS qc_session_id INTEGER")
    cursor.execute("ALTER TABLE tnps_responses ADD COLUMN IF NOT EXISTS router_optimal_location INTEGER")
    cursor.execute("ALTER TABLE tnps_responses ADD COLUMN IF NOT EXISTS environment_clean_order INTEGER")
    cursor.execute("ALTER TABLE tnps_responses ADD COLUMN IF NOT EXISTS speedtest_done INTEGER")


def ensure_qc_columns_postgres(cursor):
    cursor.execute("ALTER TABLE qc_sessions ADD COLUMN IF NOT EXISTS photo_path TEXT")
    cursor.execute("ALTER TABLE qc_sessions ADD COLUMN IF NOT EXISTS qc_live_installation INTEGER")
    cursor.execute("ALTER TABLE qc_sessions ADD COLUMN IF NOT EXISTS installation_duration_minutes INTEGER")
    cursor.execute("ALTER TABLE qc_sessions ADD COLUMN IF NOT EXISTS cable_type TEXT")
    cursor.execute("ALTER TABLE qc_sessions ADD COLUMN IF NOT EXISTS cable_meters INTEGER")
    cursor.execute("UPDATE qc_sessions SET qc_live_installation = 0 WHERE qc_live_installation IS NULL")
    cursor.execute("ALTER TABLE qc_sessions ALTER COLUMN qc_live_installation SET DEFAULT 0")
    cursor.execute("ALTER TABLE qc_sessions ALTER COLUMN qc_live_installation SET NOT NULL")


def create_finding_event(finding_id, actor_user_id, event_type, detail=None, connection=None):
    safe_type = (event_type or "").strip().lower()
    if not safe_type:
        return False
    detail_value = None
    if detail is not None:
        if isinstance(detail, str):
            detail_value = detail.strip() or None
        else:
            detail_value = json.dumps(detail, ensure_ascii=False)

    active_connection = connection or get_db()
    active_connection.execute(
        """
        INSERT INTO audit_finding_events (finding_id, actor_user_id, event_type, detail)
        VALUES (?, ?, ?, ?)
        """,
        (finding_id, actor_user_id, safe_type, detail_value),
    )
    return True


def fetch_finding_events(finding_id, limit=100):
    created_at_expr = "audit_finding_events.created_at"
    rows = get_db().execute(
        f"""
        SELECT
            audit_finding_events.id,
            {created_at_expr} AS created_at,
            audit_finding_events.event_type,
            audit_finding_events.detail,
            users.username AS actor_username
        FROM audit_finding_events
        LEFT JOIN users ON users.id = audit_finding_events.actor_user_id
        WHERE audit_finding_events.finding_id = ?
        ORDER BY audit_finding_events.id DESC
        LIMIT ?
        """,
        (finding_id, limit),
    ).fetchall()
    return [dict(row) for row in rows]


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
    stock_payload = [dict(row) for row in stock_rows]
    def stock_sort_key(row):
        material_name = row.get("material_name")
        normalized_name = normalize_material_name(material_name)
        priority_idx = _audit_material_stock_priority_index(material_name)
        if priority_idx is None:
            return (1, normalized_name)
        return (0, priority_idx, normalized_name)

    stock_payload.sort(key=stock_sort_key)

    return {
        "mobile": mobile,
        "summary": summary,
        "equipment_rows": [dict(row) for row in equipment_rows],
        "_debug_equipment_rows": [dict(row) for row in equipment_rows], # DEBUG: Para inspeccionar los datos de seriales
        "stock_rows": stock_payload,
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


def fetch_dashboard_stats(auditor_user_id=None, supervisor_scope_names=None):
    where_clauses = []
    params = []

    append_audit_visibility_filters(where_clauses, params)
    append_supervisor_scope_filters(where_clauses, params, supervisor_scope_names=supervisor_scope_names)

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
    router_optimal_location=None,
    environment_clean_order=None,
    speedtest_done=None,
    comment=None,
    customer_name=None,
    technician_id=None,
    audit_id=None,
    qc_session_id=None,
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
                    router_optimal_location = ?,
                    environment_clean_order = ?,
                    speedtest_done = ?,
                    comment = ?,
                    customer_name = ?,
                    technician_id = ?,
                    qc_session_id = COALESCE(?, qc_session_id)
                WHERE id = ?
                """,
                (
                    response_date,
                    score,
                    booking_ease_score,
                    punctuality_score,
                    communication_clarity_score,
                    issue_resolved_first_visit,
                    router_optimal_location,
                    environment_clean_order,
                    speedtest_done,
                    (comment or "").strip() or None,
                    (customer_name or "").strip() or None,
                    technician_id,
                    qc_session_id,
                    existing["id"],
                ),
            )
            connection.commit()
            return existing["id"]

    if qc_session_id is not None:
        existing = connection.execute(
            "SELECT id FROM tnps_responses WHERE qc_session_id = ? ORDER BY id DESC LIMIT 1",
            (qc_session_id,),
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
                    router_optimal_location = ?,
                    environment_clean_order = ?,
                    speedtest_done = ?,
                    comment = ?,
                    customer_name = ?,
                    technician_id = ?,
                    audit_id = COALESCE(?, audit_id)
                WHERE id = ?
                """,
                (
                    response_date,
                    score,
                    booking_ease_score,
                    punctuality_score,
                    communication_clarity_score,
                    issue_resolved_first_visit,
                    router_optimal_location,
                    environment_clean_order,
                    speedtest_done,
                    (comment or "").strip() or None,
                    (customer_name or "").strip() or None,
                    technician_id,
                    audit_id,
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
            router_optimal_location,
            environment_clean_order,
            speedtest_done,
            comment,
            customer_name,
            technician_id,
            audit_id,
            qc_session_id
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """
    insert_params = (
        response_date,
        score,
        booking_ease_score,
        punctuality_score,
        communication_clarity_score,
        issue_resolved_first_visit,
        router_optimal_location,
        environment_clean_order,
        speedtest_done,
        (comment or "").strip() or None,
        (customer_name or "").strip() or None,
        technician_id,
        audit_id,
        qc_session_id,
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


def _pearson_correlation(pairs, min_samples=5):
    values = [(float(x), float(y)) for x, y in pairs if x is not None and y is not None]
    n = len(values)
    if n < min_samples:
        return None, n
    xs = [v[0] for v in values]
    ys = [v[1] for v in values]
    mean_x = sum(xs) / n
    mean_y = sum(ys) / n
    sum_xy = 0.0
    sum_x2 = 0.0
    sum_y2 = 0.0
    for x, y in values:
        dx = x - mean_x
        dy = y - mean_y
        sum_xy += dx * dy
        sum_x2 += dx * dx
        sum_y2 += dy * dy
    denom = (sum_x2 * sum_y2) ** 0.5
    if denom == 0:
        return None, n
    return sum_xy / denom, n


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

    driver_row = get_db().execute(
        f"""
        SELECT
            COUNT(booking_ease_score) AS booking_ease_total,
            AVG(booking_ease_score) AS booking_ease_avg,
            SUM(CASE WHEN booking_ease_score BETWEEN 9 AND 10 THEN 1 ELSE 0 END) AS booking_ease_promoters,
            SUM(CASE WHEN booking_ease_score BETWEEN 1 AND 6 THEN 1 ELSE 0 END) AS booking_ease_detractors,

            COUNT(punctuality_score) AS punctuality_total,
            AVG(punctuality_score) AS punctuality_avg,
            SUM(CASE WHEN punctuality_score BETWEEN 9 AND 10 THEN 1 ELSE 0 END) AS punctuality_promoters,
            SUM(CASE WHEN punctuality_score BETWEEN 1 AND 6 THEN 1 ELSE 0 END) AS punctuality_detractors,

            COUNT(communication_clarity_score) AS clarity_total,
            AVG(communication_clarity_score) AS clarity_avg,
            SUM(CASE WHEN communication_clarity_score BETWEEN 9 AND 10 THEN 1 ELSE 0 END) AS clarity_promoters,
            SUM(CASE WHEN communication_clarity_score BETWEEN 1 AND 6 THEN 1 ELSE 0 END) AS clarity_detractors,

            COUNT(issue_resolved_first_visit) AS first_visit_total,
            AVG(issue_resolved_first_visit) AS first_visit_yes_rate,

            COUNT(router_optimal_location) AS router_optimal_total,
            AVG(router_optimal_location) AS router_optimal_yes_rate,

            COUNT(environment_clean_order) AS clean_order_total,
            AVG(environment_clean_order) AS clean_order_yes_rate,

            COUNT(speedtest_done) AS speedtest_total,
            AVG(speedtest_done) AS speedtest_yes_rate
        FROM tnps_responses
        {where_sql}
        """,
        tuple(params),
    ).fetchone()

    calc_attr_nps = lambda promoters_count, detractors_count, total_count: (
        None
        if not total_count
        else round(((promoters_count / total_count) - (detractors_count / total_count)) * 100)
    )

    booking_ease_total = driver_row["booking_ease_total"] or 0
    punctuality_total = driver_row["punctuality_total"] or 0
    clarity_total = driver_row["clarity_total"] or 0
    first_visit_total = driver_row["first_visit_total"] or 0
    router_optimal_total = driver_row["router_optimal_total"] or 0
    clean_order_total = driver_row["clean_order_total"] or 0
    speedtest_total = driver_row["speedtest_total"] or 0

    booking_ease_avg = None if booking_ease_total == 0 else round((driver_row["booking_ease_avg"] or 0), 2)
    punctuality_avg = None if punctuality_total == 0 else round((driver_row["punctuality_avg"] or 0), 2)
    clarity_avg = None if clarity_total == 0 else round((driver_row["clarity_avg"] or 0), 2)
    first_visit_yes_rate = None if first_visit_total == 0 else round(((driver_row["first_visit_yes_rate"] or 0) * 100), 1)
    router_optimal_yes_rate = (
        None if router_optimal_total == 0 else round(((driver_row["router_optimal_yes_rate"] or 0) * 100), 1)
    )
    clean_order_yes_rate = None if clean_order_total == 0 else round(((driver_row["clean_order_yes_rate"] or 0) * 100), 1)
    speedtest_yes_rate = None if speedtest_total == 0 else round(((driver_row["speedtest_yes_rate"] or 0) * 100), 1)

    booking_ease_nps = calc_attr_nps(
        float(driver_row["booking_ease_promoters"] or 0),
        float(driver_row["booking_ease_detractors"] or 0),
        float(booking_ease_total),
    )
    punctuality_nps = calc_attr_nps(
        float(driver_row["punctuality_promoters"] or 0),
        float(driver_row["punctuality_detractors"] or 0),
        float(punctuality_total),
    )
    clarity_nps = calc_attr_nps(
        float(driver_row["clarity_promoters"] or 0),
        float(driver_row["clarity_detractors"] or 0),
        float(clarity_total),
    )

    impact_rows = get_db().execute(
        f"""
        SELECT
            score,
            booking_ease_score,
            punctuality_score,
            communication_clarity_score,
            issue_resolved_first_visit,
            router_optimal_location,
            environment_clean_order,
            speedtest_done
        FROM tnps_responses
        {where_sql}
        """,
        tuple(params),
    ).fetchall()

    booking_corr, booking_corr_n = _pearson_correlation(
        [(row["booking_ease_score"], row["score"]) for row in impact_rows]
    )
    punctuality_corr, punctuality_corr_n = _pearson_correlation(
        [(row["punctuality_score"], row["score"]) for row in impact_rows]
    )
    clarity_corr, clarity_corr_n = _pearson_correlation(
        [(row["communication_clarity_score"], row["score"]) for row in impact_rows]
    )
    first_visit_corr, first_visit_corr_n = _pearson_correlation(
        [(row["issue_resolved_first_visit"], row["score"]) for row in impact_rows]
    )
    router_optimal_corr, router_optimal_corr_n = _pearson_correlation(
        [(row["router_optimal_location"], row["score"]) for row in impact_rows]
    )
    clean_order_corr, clean_order_corr_n = _pearson_correlation(
        [(row["environment_clean_order"], row["score"]) for row in impact_rows]
    )
    speedtest_corr, speedtest_corr_n = _pearson_correlation(
        [(row["speedtest_done"], row["score"]) for row in impact_rows]
    )

    drivers = [
        {
            "key": "booking_ease",
            "label": "Facilidad para coordinar",
            "value": booking_ease_avg,
            "value_suffix": "/10",
            "count": booking_ease_total,
            "nps": booking_ease_nps,
            "impact": None if booking_corr is None else round(booking_corr, 2),
            "impact_count": booking_corr_n,
        },
        {
            "key": "punctuality",
            "label": "Puntualidad del técnico",
            "value": punctuality_avg,
            "value_suffix": "/10",
            "count": punctuality_total,
            "nps": punctuality_nps,
            "impact": None if punctuality_corr is None else round(punctuality_corr, 2),
            "impact_count": punctuality_corr_n,
        },
        {
            "key": "clarity",
            "label": "Claridad de la explicación",
            "value": clarity_avg,
            "value_suffix": "/10",
            "count": clarity_total,
            "nps": clarity_nps,
            "impact": None if clarity_corr is None else round(clarity_corr, 2),
            "impact_count": clarity_corr_n,
        },
        {
            "key": "first_visit_resolution",
            "label": "Resolución en primera visita",
            "value": first_visit_yes_rate,
            "value_suffix": "% sí",
            "count": first_visit_total,
            "nps": None,
            "impact": None if first_visit_corr is None else round(first_visit_corr, 2),
            "impact_count": first_visit_corr_n,
        },
        {
            "key": "router_optimal_location",
            "label": "Router en el lugar óptimo",
            "value": router_optimal_yes_rate,
            "value_suffix": "% sí",
            "count": router_optimal_total,
            "nps": None,
            "impact": None if router_optimal_corr is None else round(router_optimal_corr, 2),
            "impact_count": router_optimal_corr_n,
        },
        {
            "key": "environment_clean_order",
            "label": "Orden y limpieza del entorno",
            "value": clean_order_yes_rate,
            "value_suffix": "% sí",
            "count": clean_order_total,
            "nps": None,
            "impact": None if clean_order_corr is None else round(clean_order_corr, 2),
            "impact_count": clean_order_corr_n,
        },
        {
            "key": "speedtest_done",
            "label": "Speedtest frente al cliente",
            "value": speedtest_yes_rate,
            "value_suffix": "% sí",
            "count": speedtest_total,
            "nps": None,
            "impact": None if speedtest_corr is None else round(speedtest_corr, 2),
            "impact_count": speedtest_corr_n,
        },
    ]

    def driver_priority_key(driver):
        impact = driver.get("impact")
        value = driver.get("value")
        value_rank = 9999 if value is None else float(value)
        if impact is None:
            return (2, 0, value_rank, driver.get("label") or "")
        impact_value = float(impact)
        impact_group = 0 if impact_value > 0 else 1
        return (impact_group, -abs(impact_value), value_rank, driver.get("label") or "")

    drivers.sort(key=driver_priority_key)

    return {
        "total_responses": total,
        "promoters_count": promoters,
        "passives_count": passives,
        "detractors_count": detractors,
        "average_score": average_score,
        "tnps_score": tnps_score,
        "drivers": drivers,
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

    created_at_expr = "tnps_responses.created_at"
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
            tnps_responses.router_optimal_location,
            tnps_responses.environment_clean_order,
            tnps_responses.speedtest_done,
            tnps_responses.comment,
            tnps_responses.customer_name,
            tnps_responses.audit_id,
            tnps_responses.qc_session_id,
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
    created_at_expr = "tnps_responses.created_at"
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
            tnps_responses.router_optimal_location,
            tnps_responses.environment_clean_order,
            tnps_responses.speedtest_done,
            tnps_responses.comment,
            tnps_responses.customer_name,
            tnps_responses.audit_id,
            tnps_responses.qc_session_id,
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


def fetch_tnps_response_for_qc(qc_session_id):
    created_at_expr = "tnps_responses.created_at"
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
            tnps_responses.router_optimal_location,
            tnps_responses.environment_clean_order,
            tnps_responses.speedtest_done,
            tnps_responses.comment,
            tnps_responses.customer_name,
            tnps_responses.audit_id,
            tnps_responses.qc_session_id,
            tnps_responses.technician_id,
            {created_at_expr} AS created_at,
            technicians.name AS technician_name,
            technicians.employee_code AS technician_employee_code
        FROM tnps_responses
        LEFT JOIN technicians ON technicians.id = tnps_responses.technician_id
        WHERE tnps_responses.qc_session_id = ?
        ORDER BY tnps_responses.id DESC
        LIMIT 1
        """,
        (qc_session_id,),
    ).fetchone()
    return dict(row) if row else None


def fetch_tnps_technician_rankings(filters=None, min_responses=20, limit=200):
    filters = filters or {}
    where_clauses = ["tnps_responses.technician_id IS NOT NULL"]
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

    where_sql = "WHERE " + " AND ".join(where_clauses)

    rows = get_db().execute(
        f"""
        SELECT
            tnps_responses.technician_id,
            technicians.name AS technician_name,
            technicians.employee_code AS technician_employee_code,
            COUNT(*) AS total_responses,
            SUM(CASE WHEN score BETWEEN 9 AND 10 THEN 1 ELSE 0 END) AS promoters_count,
            SUM(CASE WHEN score BETWEEN 0 AND 6 THEN 1 ELSE 0 END) AS detractors_count,
            AVG(score) AS average_score,

            COUNT(booking_ease_score) AS booking_ease_total,
            AVG(booking_ease_score) AS booking_ease_avg,

            COUNT(punctuality_score) AS punctuality_total,
            AVG(punctuality_score) AS punctuality_avg,

            COUNT(communication_clarity_score) AS clarity_total,
            AVG(communication_clarity_score) AS clarity_avg,

            COUNT(issue_resolved_first_visit) AS first_visit_total,
            AVG(issue_resolved_first_visit) AS first_visit_yes_rate
        FROM tnps_responses
        LEFT JOIN technicians ON technicians.id = tnps_responses.technician_id
        {where_sql}
        GROUP BY tnps_responses.technician_id, technicians.name, technicians.employee_code
        """,
        tuple(params),
    ).fetchall()

    result = []
    for row in rows:
        total = row["total_responses"] or 0
        if total < int(min_responses or 0):
            continue
        promoters = row["promoters_count"] or 0
        detractors = row["detractors_count"] or 0
        tnps_score = round(((promoters / total) - (detractors / total)) * 100) if total else 0

        booking_total = row["booking_ease_total"] or 0
        punctuality_total = row["punctuality_total"] or 0
        clarity_total = row["clarity_total"] or 0
        first_visit_total = row["first_visit_total"] or 0

        result.append(
            {
                "technician_id": row["technician_id"],
                "technician_name": row["technician_name"] or "-",
                "technician_employee_code": row["technician_employee_code"] or "-",
                "total_responses": total,
                "tnps_score": tnps_score,
                "average_score": round((row["average_score"] or 0), 2) if total else 0,
                "booking_ease_avg": None if booking_total == 0 else round((row["booking_ease_avg"] or 0), 2),
                "punctuality_avg": None if punctuality_total == 0 else round((row["punctuality_avg"] or 0), 2),
                "clarity_avg": None if clarity_total == 0 else round((row["clarity_avg"] or 0), 2),
                "first_visit_yes_rate": None
                if first_visit_total == 0
                else round(((row["first_visit_yes_rate"] or 0) * 100), 1),
            }
        )

    result.sort(key=lambda r: (r["tnps_score"], -r["total_responses"], r["technician_name"]))
    return result[:limit]


def fetch_recent_audits(limit=5, auditor_user_id=None, supervisor_scope_names=None):
    where_clauses = []
    params = []

    append_audit_visibility_filters(where_clauses, params)
    append_supervisor_scope_filters(where_clauses, params, supervisor_scope_names=supervisor_scope_names)

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


def fetch_all_audits(filters=None, auditor_user_id=None, supervisor_scope_names=None):
    where_sql, params = build_audits_where_sql(
        filters,
        auditor_user_id=auditor_user_id,
        supervisor_scope_names=supervisor_scope_names,
    )
    filters = filters or {}
    sort_key = (filters.get("sort") or "").strip()
    sort_dir = (filters.get("dir") or "").strip().lower()
    if sort_dir not in {"asc", "desc"}:
        sort_dir = "desc"

    sort_columns = {
        "audit_date": "audits.audit_date",
        "auditor_name": "COALESCE(audits.auditor_name, '')",
        "mobile_code": "COALESCE(mobile_units.mobile_code, '')",
        "technician_name": "COALESCE(technicians.name, audits.technician_display_name, '')",
        "vehicle_plate": "vehicles.plate",
        "location": "audits.location",
        "result_status": "audits.result_status",
        "total_score": "audits.total_score",
    }
    sort_expr = sort_columns.get(sort_key)
    if sort_expr:
        order_sql = f"ORDER BY {sort_expr} {sort_dir.upper()}, audits.created_at DESC"
    else:
        order_sql = "ORDER BY audits.created_at DESC"
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
        {order_sql}
        """,
        params,
    ).fetchall()
    return [dict(row) for row in rows]


def build_audit_picker_where_sql(filters=None, auditor_user_id=None, supervisor_scope_names=None):
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
        supervisor_scope_names=supervisor_scope_names,
        extra_clauses=extra_clauses,
        extra_params=extra_params,
    )


def count_audit_picker_audits(filters=None, auditor_user_id=None, supervisor_scope_names=None):
    where_sql, params = build_audit_picker_where_sql(
        filters,
        auditor_user_id=auditor_user_id,
        supervisor_scope_names=supervisor_scope_names,
    )
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


def fetch_audit_picker_audits(filters=None, auditor_user_id=None, supervisor_scope_names=None, limit=25, offset=0):
    where_sql, params = build_audit_picker_where_sql(
        filters,
        auditor_user_id=auditor_user_id,
        supervisor_scope_names=supervisor_scope_names,
    )
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


def build_audits_where_sql(
    filters=None,
    auditor_user_id=None,
    supervisor_scope_names=None,
    extra_clauses=None,
    extra_params=None,
):
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

    append_supervisor_scope_filters(where_clauses, params, supervisor_scope_names=supervisor_scope_names)

    if extra_clauses:
        where_clauses.extend(extra_clauses)
        params.extend(list(extra_params))

    where_sql = ""
    if where_clauses:
        where_sql = "WHERE " + " AND ".join(where_clauses)

    return where_sql, tuple(params)


def build_audits_where_sql_with_technicians(
    filters=None,
    auditor_user_id=None,
    supervisor_scope_names=None,
    extra_clauses=None,
    extra_params=None,
):
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
        supervisor_scope_names=supervisor_scope_names,
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


def fetch_distinct_finding_locations(filters=None, auditor_user_id=None, supervisor_scope_names=None):
    option_filters = dict(filters or {})
    option_filters["location"] = ""
    where_sql, params = _build_findings_where_sql(
        option_filters,
        auditor_user_id=auditor_user_id,
        supervisor_scope_names=supervisor_scope_names,
    )
    rows = get_db().execute(
        f"""
        SELECT DISTINCT TRIM(COALESCE(audits.location, '')) AS location
        FROM audit_findings
        INNER JOIN audits ON audits.id = audit_findings.audit_id
        LEFT JOIN users AS auditor_users ON auditor_users.id = audits.auditor_user_id
        {where_sql}
        {"AND" if where_sql else "WHERE"} TRIM(COALESCE(audits.location, '')) != ''
        ORDER BY location ASC
        """,
        params,
    ).fetchall()
    return [dict(row)["location"] for row in rows]


def fetch_distinct_finding_auditors(filters=None, auditor_user_id=None, supervisor_scope_names=None):
    option_filters = dict(filters or {})
    option_filters["auditor"] = ""
    where_sql, params = _build_findings_where_sql(
        option_filters,
        auditor_user_id=auditor_user_id,
        supervisor_scope_names=supervisor_scope_names,
    )
    rows = get_db().execute(
        f"""
        SELECT DISTINCT TRIM(COALESCE(auditor_users.username, audits.auditor_name, '')) AS auditor_name
        FROM audit_findings
        INNER JOIN audits ON audits.id = audit_findings.audit_id
        LEFT JOIN users AS auditor_users ON auditor_users.id = audits.auditor_user_id
        {where_sql}
        {"AND" if where_sql else "WHERE"} TRIM(COALESCE(auditor_users.username, audits.auditor_name, '')) != ''
        ORDER BY auditor_name ASC
        """,
        params,
    ).fetchall()
    return [dict(row)["auditor_name"] for row in rows]


def fetch_distinct_finding_supervisors(filters=None, auditor_user_id=None, supervisor_scope_names=None):
    option_filters = dict(filters or {})
    option_filters["technician_supervisor"] = ""
    where_sql, params = _build_findings_where_sql(
        option_filters,
        auditor_user_id=auditor_user_id,
        supervisor_scope_names=supervisor_scope_names,
    )
    rows = get_db().execute(
        f"""
        SELECT DISTINCT TRIM(COALESCE(audits.technician_supervisor_snapshot, technicians.supervisor_name, '')) AS supervisor_name
        FROM audit_findings
        INNER JOIN audits ON audits.id = audit_findings.audit_id
        LEFT JOIN technicians ON technicians.id = audits.technician_id
        LEFT JOIN users AS auditor_users ON auditor_users.id = audits.auditor_user_id
        LEFT JOIN users AS owners ON owners.id = audit_findings.owner_user_id
        {where_sql}
        {"AND" if where_sql else "WHERE"} TRIM(COALESCE(audits.technician_supervisor_snapshot, technicians.supervisor_name, '')) != ''
        ORDER BY supervisor_name ASC
        """,
        params,
    ).fetchall()
    return [dict(row)["supervisor_name"] for row in rows]


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


def fetch_audit_detail(audit_id, supervisor_scope_names=None):
    created_at_expr = "audits.created_at"
    where_clauses = ["audits.id = ?"]
    params = [audit_id]
    append_supervisor_scope_filters(where_clauses, params, supervisor_scope_names=supervisor_scope_names)
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
            audits.technician_company_snapshot,
            audits.technician_supervisor_snapshot,
            audits.technician_center_snapshot,
            audits.location,
            audits.address,
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
            COALESCE(audits.technician_company_snapshot, technicians.company_name) AS technician_company,
            COALESCE(audits.technician_supervisor_snapshot, technicians.supervisor_name) AS technician_supervisor,
            COALESCE(audits.technician_center_snapshot, technicians.center_name) AS technician_center,
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
        WHERE {' AND '.join(where_clauses)}
        """,
        tuple(params),
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
    created_at_expr = "created_at"
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


def fetch_supply_requests_feed(filters=None, auditor_user_id=None, supervisor_scope_names=None, limit=200):
    filters = filters or {}
    where_clauses = []
    params = []

    append_audit_visibility_filters(where_clauses, params, include_pruebas=False)
    append_supervisor_scope_filters(where_clauses, params, supervisor_scope_names=supervisor_scope_names)

    from_date = (filters.get("from_date") or "").strip()
    to_date = (filters.get("to_date") or "").strip()
    if from_date:
        where_clauses.append("audits.audit_date >= ?")
        params.append(from_date)
    if to_date:
        where_clauses.append("audits.audit_date <= ?")
        params.append(to_date)

    if auditor_user_id is not None:
        where_clauses.append("audits.auditor_user_id = ?")
        params.append(auditor_user_id)

    query = (filters.get("q") or "").strip()
    if query:
        like_value = f"%{query}%"
        if is_postgres():
            where_clauses.append(
                "("
                "COALESCE(audits.sa_number, '') ILIKE ? OR "
                "CAST(audits.id AS TEXT) ILIKE ? OR "
                "COALESCE(mobile_units.mobile_code, '') ILIKE ? OR "
                "COALESCE(technicians.name, audits.technician_display_name, '') ILIKE ? OR "
                "COALESCE(vehicles.plate, '') ILIKE ? OR "
                "COALESCE(audits.location, '') ILIKE ? OR "
                "COALESCE(audit_supply_requests.material_code, '') ILIKE ? OR "
                "COALESCE(audit_supply_requests.item_label, '') ILIKE ? OR "
                "COALESCE(audit_supply_requests.notes, '') ILIKE ?"
                ")"
            )
            params.extend([like_value] * 9)
        else:
            where_clauses.append(
                "("
                "LOWER(COALESCE(audits.sa_number, '')) LIKE ? OR "
                "LOWER(CAST(audits.id AS TEXT)) LIKE ? OR "
                "LOWER(COALESCE(mobile_units.mobile_code, '')) LIKE ? OR "
                "LOWER(COALESCE(technicians.name, audits.technician_display_name, '')) LIKE ? OR "
                "LOWER(COALESCE(vehicles.plate, '')) LIKE ? OR "
                "LOWER(COALESCE(audits.location, '')) LIKE ? OR "
                "LOWER(COALESCE(audit_supply_requests.material_code, '')) LIKE ? OR "
                "LOWER(COALESCE(audit_supply_requests.item_label, '')) LIKE ? OR "
                "LOWER(COALESCE(audit_supply_requests.notes, '')) LIKE ?"
                ")"
            )
            params.extend([like_value.lower()] * 9)

    where_sql = ""
    if where_clauses:
        where_sql = "WHERE " + " AND ".join(where_clauses)

    request_created_at_expr = "audit_supply_requests.created_at"
    rows = get_db().execute(
        f"""
        SELECT
            audit_supply_requests.id,
            {request_created_at_expr} AS created_at,
            audits.id AS audit_id,
            audits.audit_date,
            audits.sa_number,
            audits.location,
            audits.result_status,
            mobile_units.mobile_code,
            COALESCE(technicians.name, audits.technician_display_name) AS technician_name,
            vehicles.plate AS vehicle_plate,
            audit_supply_requests.request_type,
            audit_supply_requests.item_label,
            audit_supply_requests.material_code,
            audit_supply_requests.quantity,
            audit_supply_requests.notes
        FROM audit_supply_requests
        INNER JOIN audits ON audits.id = audit_supply_requests.audit_id
        LEFT JOIN mobile_units ON mobile_units.id = audits.mobile_unit_id
        LEFT JOIN technicians ON technicians.id = audits.technician_id
        INNER JOIN vehicles ON vehicles.id = audits.vehicle_id
        {where_sql}
        ORDER BY audit_supply_requests.created_at DESC, audit_supply_requests.id DESC
        LIMIT ?
        """,
        tuple(list(params) + [int(limit or 200)]),
    ).fetchall()
    normalized = [dict(row) for row in rows]
    return normalized


def fetch_audit_findings(audit_id):
    created_at_expr = "audit_findings.created_at"
    updated_at_expr = "audit_findings.updated_at"
    responded_at_expr = "audit_findings.responded_at"
    validated_at_expr = "audit_findings.validated_at"
    resolved_at_expr = "audit_findings.resolved_at"
    rows = get_db().execute(
        f"""
        SELECT
            audit_findings.id,
            audit_findings.audit_id,
            audit_findings.audit_item_id,
            audit_findings.supervisor_name,
            audit_findings.item_status,
            audit_findings.finding_status,
            audit_findings.priority,
            audit_findings.response_notes,
            audit_findings.evidence_path,
            audit_findings.validation_status,
            audit_findings.validation_notes,
            {created_at_expr} AS created_at,
            {updated_at_expr} AS updated_at,
            {responded_at_expr} AS responded_at,
            {validated_at_expr} AS validated_at,
            {resolved_at_expr} AS resolved_at,
            audit_items.section_title,
            audit_items.item_label,
            audit_items.is_critical,
            audit_items.non_compliance_reason,
            audit_items.notes AS item_notes,
            owners.username AS owner_username,
            responders.username AS responded_by_username,
            validators.username AS validated_by_username
        FROM audit_findings
        INNER JOIN audit_items ON audit_items.id = audit_findings.audit_item_id
        LEFT JOIN users AS owners ON owners.id = audit_findings.owner_user_id
        LEFT JOIN users AS responders ON responders.id = audit_findings.responded_by_user_id
        LEFT JOIN users AS validators ON validators.id = audit_findings.validated_by_user_id
        WHERE audit_findings.audit_id = ?
        ORDER BY audit_items.section_title ASC, audit_items.item_label ASC, audit_findings.id ASC
        """,
        (audit_id,),
    ).fetchall()
    return [dict(row) for row in rows]


def _append_pending_validation_where(where_clauses, params, overdue_only=False):
    where_clauses.append("audit_findings.finding_status = 'resuelto'")
    where_clauses.append("COALESCE(audit_findings.validation_status, '') != 'validado'")
    if not overdue_only:
        return

    cutoff_iso = _pending_validation_cutoff_in_app_tz(_pending_validation_alert_window_days()).isoformat()
    if is_postgres():
        where_clauses.append("audit_findings.resolved_at IS NOT NULL")
        where_clauses.append("(audit_findings.resolved_at AT TIME ZONE 'UTC')::date < ?::date")
        params.append(cutoff_iso)
    else:
        where_clauses.append("date(audit_findings.resolved_at) < date(?)")
        params.append(cutoff_iso)


def _build_findings_where_sql(filters=None, auditor_user_id=None, supervisor_scope_names=None):
    filters = filters or {}
    where_clauses = []
    params = []

    append_audit_visibility_filters(where_clauses, params)

    if auditor_user_id is not None:
        where_clauses.append("audits.auditor_user_id = ?")
        params.append(auditor_user_id)

    append_supervisor_scope_filters(where_clauses, params, supervisor_scope_names=supervisor_scope_names)

    from_date = (filters.get("from_date") or "").strip()
    to_date = (filters.get("to_date") or "").strip()
    finding_status = (filters.get("finding_status") or "").strip()
    priority = (filters.get("priority") or "").strip()
    validation_status = (filters.get("validation_status") or "").strip()
    audit_id = (filters.get("audit_id") or "").strip()
    mobile_code = (filters.get("mobile_code") or "").strip()
    location = (filters.get("location") or "").strip()
    auditor = (filters.get("auditor") or "").strip()
    owner = (filters.get("owner") or "").strip()
    technician_supervisor = (filters.get("technician_supervisor") or "").strip()
    section_key = (filters.get("section_key") or "").strip()
    q = (filters.get("q") or "").strip()
    effectiveness = (filters.get("effectiveness") or "").strip().lower()
    quick_filter = (filters.get("quick_filter") or "").strip().lower()

    if from_date:
        where_clauses.append("audits.audit_date >= ?")
        params.append(from_date)

    if to_date:
        where_clauses.append("audits.audit_date <= ?")
        params.append(to_date)

    if finding_status:
        where_clauses.append("audit_findings.finding_status = ?")
        params.append(finding_status)

    if priority:
        where_clauses.append("audit_findings.priority = ?")
        params.append(priority)

    if validation_status:
        if validation_status == "__none__":
            where_clauses.append("COALESCE(audit_findings.validation_status, '') = ''")
        else:
            where_clauses.append("audit_findings.validation_status = ?")
            params.append(validation_status)

    if audit_id:
        where_clauses.append("CAST(audit_findings.audit_id AS TEXT) = ?")
        params.append(audit_id)

    if mobile_code:
        where_clauses.append("COALESCE(mobile_units.mobile_code, '') = ?")
        params.append(mobile_code)

    if location:
        where_clauses.append("COALESCE(audits.location, '') = ?")
        params.append(location)

    if auditor:
        where_clauses.append("COALESCE(auditor_users.username, audits.auditor_name, '') = ?")
        params.append(auditor)

    if owner:
        where_clauses.append("COALESCE(owners.username, '') = ?")
        params.append(owner)

    if technician_supervisor:
        where_clauses.append("COALESCE(audits.technician_supervisor_snapshot, technicians.supervisor_name, '') = ?")
        params.append(technician_supervisor)

    if section_key:
        where_clauses.append("COALESCE(audit_items.section_key, '') = ?")
        params.append(section_key)

    if q:
        like_value = f"%{q}%"
        if is_postgres():
            where_clauses.append(
                "("
                "CAST(audit_findings.audit_id AS TEXT) ILIKE ? OR "
                "CAST(audit_findings.id AS TEXT) ILIKE ? OR "
                "COALESCE(mobile_units.mobile_code, '') ILIKE ? OR "
                "COALESCE(audits.location, '') ILIKE ? OR "
                "COALESCE(auditor_users.username, audits.auditor_name, '') ILIKE ? OR "
                "COALESCE(owners.username, '') ILIKE ? OR "
                "COALESCE(audits.technician_supervisor_snapshot, technicians.supervisor_name, '') ILIKE ? OR "
                "COALESCE(technicians.name, audits.technician_display_name, '') ILIKE ? OR "
                "COALESCE(audit_items.section_title, '') ILIKE ? OR "
                "COALESCE(audit_items.item_label, '') ILIKE ? OR "
                "COALESCE(audit_findings.supervisor_name, '') ILIKE ?"
                ")"
            )
            params.extend([like_value] * 11)
        else:
            where_clauses.append(
                "("
                "LOWER(CAST(audit_findings.audit_id AS TEXT)) LIKE ? OR "
                "LOWER(CAST(audit_findings.id AS TEXT)) LIKE ? OR "
                "LOWER(COALESCE(mobile_units.mobile_code, '')) LIKE ? OR "
                "LOWER(COALESCE(audits.location, '')) LIKE ? OR "
                "LOWER(COALESCE(auditor_users.username, audits.auditor_name, '')) LIKE ? OR "
                "LOWER(COALESCE(owners.username, '')) LIKE ? OR "
                "LOWER(COALESCE(audits.technician_supervisor_snapshot, technicians.supervisor_name, '')) LIKE ? OR "
                "LOWER(COALESCE(technicians.name, audits.technician_display_name, '')) LIKE ? OR "
                "LOWER(COALESCE(audit_items.section_title, '')) LIKE ? OR "
                "LOWER(COALESCE(audit_items.item_label, '')) LIKE ? OR "
                "LOWER(COALESCE(audit_findings.supervisor_name, '')) LIKE ?"
                ")"
            )
            lowered = like_value.lower()
            params.extend([lowered] * 11)

    if effectiveness in {"pendiente", "por_vencer", "vencida"}:
        where_clauses.append("COALESCE(audit_findings.validation_status, '') = 'validado'")
        where_clauses.append("COALESCE(audit_findings.effectiveness_status, '') = 'pendiente'")
        where_clauses.append("COALESCE(audit_findings.effectiveness_due_date, '') != ''")

        alert_days = _effectiveness_alert_window_days()
        today_iso = _today_in_app_tz().isoformat()
        end_iso = _date_range_end_in_app_tz(alert_days).isoformat()
        if effectiveness == "vencida":
            if is_postgres():
                where_clauses.append("substring(audit_findings.effectiveness_due_date, 1, 10) ~ '^\\d{4}-\\d{2}-\\d{2}$'")
                where_clauses.append("to_date(substring(audit_findings.effectiveness_due_date, 1, 10), 'YYYY-MM-DD') < ?::date")
                params.append(today_iso)
            else:
                where_clauses.append("date(substr(audit_findings.effectiveness_due_date, 1, 10)) < date(?)")
                params.append(today_iso)
        elif effectiveness == "por_vencer":
            if is_postgres():
                where_clauses.append("substring(audit_findings.effectiveness_due_date, 1, 10) ~ '^\\d{4}-\\d{2}-\\d{2}$'")
                where_clauses.append("to_date(substring(audit_findings.effectiveness_due_date, 1, 10), 'YYYY-MM-DD') >= ?::date")
                where_clauses.append("to_date(substring(audit_findings.effectiveness_due_date, 1, 10), 'YYYY-MM-DD') <= ?::date")
                params.extend([today_iso, end_iso])
            else:
                where_clauses.append("date(substr(audit_findings.effectiveness_due_date, 1, 10)) >= date(?)")
                where_clauses.append("date(substr(audit_findings.effectiveness_due_date, 1, 10)) <= date(?)")
                params.extend([today_iso, end_iso])

    if quick_filter == "active":
        where_clauses.append("audit_findings.finding_status IN ('nuevo', 'respondido', 'resuelto', 'reabierto')")
    elif quick_filter == "high_priority":
        where_clauses.append("audit_findings.priority = 'alta'")
    elif quick_filter == "reopened":
        where_clauses.append("audit_findings.finding_status = 'reabierto'")
    elif quick_filter == "pending_validation":
        _append_pending_validation_where(where_clauses, params)
    elif quick_filter == "new":
        where_clauses.append("audit_findings.finding_status = 'nuevo'")
    elif quick_filter == "in_progress":
        where_clauses.append("audit_findings.finding_status = 'respondido'")
    elif quick_filter == "overdue_validation":
        _append_pending_validation_where(where_clauses, params, overdue_only=True)
    elif quick_filter == "overdue_effectiveness":
        filters = dict(filters)
        filters["quick_filter"] = ""
        filters["effectiveness"] = "vencida"
        return _build_findings_where_sql(
            filters,
            auditor_user_id=auditor_user_id,
            supervisor_scope_names=supervisor_scope_names,
        )
    elif quick_filter in {"stale_treatment", "escalated_treatment"}:
        cutoff_iso = _treatment_update_cutoff_in_app_tz(
            _treatment_update_alert_window_days() if quick_filter == "stale_treatment" else _treatment_update_escalation_days()
        ).isoformat()
        where_clauses.append("audit_findings.finding_status = 'respondido'")
        if is_postgres():
            where_clauses.append("(audit_findings.updated_at AT TIME ZONE 'UTC')::date <= ?::date")
        else:
            where_clauses.append("date(audit_findings.updated_at) <= date(?)")
        params.append(cutoff_iso)

    where_sql = ""
    if where_clauses:
        where_sql = "WHERE " + " AND ".join(where_clauses)
    return where_sql, tuple(params)


def fetch_finding_stats(filters=None, auditor_user_id=None, supervisor_scope_names=None):
    where_sql, params = _build_findings_where_sql(
        filters,
        auditor_user_id=auditor_user_id,
        supervisor_scope_names=supervisor_scope_names,
    )
    effectiveness_alert_days = _effectiveness_alert_window_days()
    pending_validation_days = _pending_validation_alert_window_days()
    stale_treatment_days = _treatment_update_alert_window_days()
    escalated_treatment_days = _treatment_update_escalation_days()
    today_iso = _today_in_app_tz().isoformat()
    end_iso = _date_range_end_in_app_tz(effectiveness_alert_days).isoformat()
    pending_validation_cutoff_iso = _pending_validation_cutoff_in_app_tz(pending_validation_days).isoformat()
    stale_treatment_cutoff_iso = _treatment_update_cutoff_in_app_tz(stale_treatment_days).isoformat()
    escalated_treatment_cutoff_iso = _treatment_update_cutoff_in_app_tz(escalated_treatment_days).isoformat()

    if is_postgres():
        stale_treatment_sql = (
            "SUM(CASE WHEN audit_findings.finding_status = 'respondido' "
            "AND (audit_findings.updated_at AT TIME ZONE 'UTC')::date <= ?::date "
            "THEN 1 ELSE 0 END) AS stale_treatment_count"
        )
        escalated_treatment_sql = (
            "SUM(CASE WHEN audit_findings.finding_status = 'respondido' "
            "AND (audit_findings.updated_at AT TIME ZONE 'UTC')::date <= ?::date "
            "THEN 1 ELSE 0 END) AS escalated_treatment_count"
        )
        overdue_effectiveness_sql = (
            "SUM(CASE WHEN COALESCE(audit_findings.validation_status, '') = 'validado' "
            "AND COALESCE(audit_findings.effectiveness_status, '') = 'pendiente' "
            "AND substring(audit_findings.effectiveness_due_date, 1, 10) ~ '^\\d{4}-\\d{2}-\\d{2}$' "
            "AND to_date(substring(audit_findings.effectiveness_due_date, 1, 10), 'YYYY-MM-DD') < ?::date "
            "THEN 1 ELSE 0 END) AS overdue_effectiveness_count"
        )
        due_soon_effectiveness_sql = (
            "SUM(CASE WHEN COALESCE(audit_findings.validation_status, '') = 'validado' "
            "AND COALESCE(audit_findings.effectiveness_status, '') = 'pendiente' "
            "AND substring(audit_findings.effectiveness_due_date, 1, 10) ~ '^\\d{4}-\\d{2}-\\d{2}$' "
            "AND to_date(substring(audit_findings.effectiveness_due_date, 1, 10), 'YYYY-MM-DD') >= ?::date "
            "AND to_date(substring(audit_findings.effectiveness_due_date, 1, 10), 'YYYY-MM-DD') <= ?::date "
            "THEN 1 ELSE 0 END) AS due_soon_effectiveness_count"
        )
        overdue_validation_sql = (
            "SUM(CASE WHEN audit_findings.finding_status = 'resuelto' "
            "AND COALESCE(audit_findings.validation_status, '') != 'validado' "
            "AND audit_findings.resolved_at IS NOT NULL "
            "AND (audit_findings.resolved_at AT TIME ZONE 'UTC')::date < ?::date "
            "THEN 1 ELSE 0 END) AS overdue_validation_count"
        )
    else:
        stale_treatment_sql = (
            "SUM(CASE WHEN audit_findings.finding_status = 'respondido' "
            "AND date(audit_findings.updated_at) <= date(?) "
            "THEN 1 ELSE 0 END) AS stale_treatment_count"
        )
        escalated_treatment_sql = (
            "SUM(CASE WHEN audit_findings.finding_status = 'respondido' "
            "AND date(audit_findings.updated_at) <= date(?) "
            "THEN 1 ELSE 0 END) AS escalated_treatment_count"
        )
        overdue_effectiveness_sql = (
            "SUM(CASE WHEN COALESCE(audit_findings.validation_status, '') = 'validado' "
            "AND COALESCE(audit_findings.effectiveness_status, '') = 'pendiente' "
            "AND COALESCE(audit_findings.effectiveness_due_date, '') != '' "
            "AND date(substr(audit_findings.effectiveness_due_date, 1, 10)) < date(?) "
            "THEN 1 ELSE 0 END) AS overdue_effectiveness_count"
        )
        due_soon_effectiveness_sql = (
            "SUM(CASE WHEN COALESCE(audit_findings.validation_status, '') = 'validado' "
            "AND COALESCE(audit_findings.effectiveness_status, '') = 'pendiente' "
            "AND COALESCE(audit_findings.effectiveness_due_date, '') != '' "
            "AND date(substr(audit_findings.effectiveness_due_date, 1, 10)) >= date(?) "
            "AND date(substr(audit_findings.effectiveness_due_date, 1, 10)) <= date(?) "
            "THEN 1 ELSE 0 END) AS due_soon_effectiveness_count"
        )
        overdue_validation_sql = (
            "SUM(CASE WHEN audit_findings.finding_status = 'resuelto' "
            "AND COALESCE(audit_findings.validation_status, '') != 'validado' "
            "AND date(audit_findings.resolved_at) < date(?) "
            "THEN 1 ELSE 0 END) AS overdue_validation_count"
        )

    row = get_db().execute(
        f"""
        SELECT
            COUNT(*) AS total_findings,
            SUM(CASE WHEN audit_findings.finding_status IN ('nuevo', 'respondido', 'resuelto', 'reabierto') THEN 1 ELSE 0 END) AS active_findings,
            SUM(CASE WHEN audit_findings.finding_status = 'nuevo' THEN 1 ELSE 0 END) AS new_count,
            SUM(CASE WHEN audit_findings.finding_status = 'respondido' THEN 1 ELSE 0 END) AS in_progress_count,
            {stale_treatment_sql},
            {escalated_treatment_sql},
            SUM(CASE WHEN audit_findings.priority = 'alta' THEN 1 ELSE 0 END) AS high_priority_count,
            SUM(CASE WHEN audit_findings.finding_status = 'reabierto' THEN 1 ELSE 0 END) AS reopened_count,
            SUM(CASE WHEN audit_findings.finding_status = 'resuelto' AND COALESCE(audit_findings.validation_status, '') != 'validado' THEN 1 ELSE 0 END) AS pending_validation_count,
            {overdue_validation_sql},
            {overdue_effectiveness_sql},
            {due_soon_effectiveness_sql},
            SUM(
                CASE
                    WHEN COALESCE(audit_findings.validation_status, '') = 'validado' OR audit_findings.finding_status = 'validado'
                    THEN 1
                    ELSE 0
                END
            ) AS validated_count
        FROM audit_findings
        INNER JOIN audits ON audits.id = audit_findings.audit_id
        INNER JOIN audit_items ON audit_items.id = audit_findings.audit_item_id
        LEFT JOIN mobile_units ON mobile_units.id = audits.mobile_unit_id
        LEFT JOIN technicians ON technicians.id = audits.technician_id
        LEFT JOIN users AS auditor_users ON auditor_users.id = audits.auditor_user_id
        LEFT JOIN users AS owners ON owners.id = audit_findings.owner_user_id
        {where_sql}
        """,
        (
            stale_treatment_cutoff_iso,
            escalated_treatment_cutoff_iso,
            pending_validation_cutoff_iso,
            today_iso,
            today_iso,
            end_iso,
            *params,
        ),
    ).fetchone()
    total_findings = row["total_findings"] or 0
    validated_count = row["validated_count"] or 0
    validation_rate = 0 if total_findings == 0 else round((validated_count / total_findings) * 100)
    return {
        "total_findings": total_findings,
        "active_findings": row["active_findings"] or 0,
        "new_count": row["new_count"] or 0,
        "in_progress_count": row["in_progress_count"] or 0,
        "stale_treatment_count": row["stale_treatment_count"] or 0,
        "escalated_treatment_count": row["escalated_treatment_count"] or 0,
        "high_priority_count": row["high_priority_count"] or 0,
        "reopened_count": row["reopened_count"] or 0,
        "pending_validation_count": row["pending_validation_count"] or 0,
        "overdue_validation_count": row["overdue_validation_count"] or 0,
        "overdue_effectiveness_count": row["overdue_effectiveness_count"] or 0,
        "due_soon_effectiveness_count": row["due_soon_effectiveness_count"] or 0,
        "pending_validation_alert_days": pending_validation_days,
        "treatment_alert_days": stale_treatment_days,
        "treatment_escalation_days": escalated_treatment_days,
        "validated_count": validated_count,
        "validation_rate": validation_rate,
    }


def fetch_finding_status_breakdown(filters=None, auditor_user_id=None, supervisor_scope_names=None):
    where_sql, params = _build_findings_where_sql(
        filters,
        auditor_user_id=auditor_user_id,
        supervisor_scope_names=supervisor_scope_names,
    )
    rows = get_db().execute(
        f"""
        SELECT
            audit_findings.finding_status,
            COUNT(*) AS findings_count
        FROM audit_findings
        INNER JOIN audits ON audits.id = audit_findings.audit_id
        INNER JOIN audit_items ON audit_items.id = audit_findings.audit_item_id
        LEFT JOIN mobile_units ON mobile_units.id = audits.mobile_unit_id
        LEFT JOIN technicians ON technicians.id = audits.technician_id
        LEFT JOIN users AS auditor_users ON auditor_users.id = audits.auditor_user_id
        LEFT JOIN users AS owners ON owners.id = audit_findings.owner_user_id
        {where_sql}
        GROUP BY audit_findings.finding_status
        """,
        params,
    ).fetchall()
    return [dict(row) for row in rows]


def fetch_findings(filters=None, auditor_user_id=None, supervisor_scope_names=None, limit=50, offset=0):
    filters = filters or {}
    created_at_expr = "audit_findings.created_at"
    updated_at_expr = "audit_findings.updated_at"
    where_sql, params = _build_findings_where_sql(
        filters,
        auditor_user_id=auditor_user_id,
        supervisor_scope_names=supervisor_scope_names,
    )

    sort_key = (filters.get("sort") or "").strip()
    sort_dir = (filters.get("dir") or "").strip().lower()
    direction_sql = "ASC" if sort_dir == "asc" else "DESC"

    effectiveness_base = (
        "substring(audit_findings.effectiveness_due_date, 1, 10)"
        if is_postgres()
        else "substr(audit_findings.effectiveness_due_date, 1, 10)"
    )
    effectiveness_fill = "'9999-12-31'" if direction_sql == "ASC" else "''"
    effectiveness_expr = f"COALESCE(NULLIF({effectiveness_base}, ''), {effectiveness_fill})"

    sort_map = {
        "audit_date": "audits.audit_date",
        "mobile_code": "COALESCE(mobile_units.mobile_code, '')",
        "technician_name": "COALESCE(technicians.name, audits.technician_display_name, '')",
        "section_title": "COALESCE(audit_items.section_title, '')",
        "item_label": "COALESCE(audit_items.item_label, '')",
        "non_compliance_reason": "COALESCE(audit_items.non_compliance_reason, '')",
        "supervisor_name": "COALESCE(audit_findings.supervisor_name, '')",
        "priority": "CASE COALESCE(audit_findings.priority, '') WHEN 'alta' THEN 0 WHEN 'media' THEN 1 ELSE 2 END",
        "finding_status": "COALESCE(audit_findings.finding_status, '')",
        "validation_status": "COALESCE(audit_findings.validation_status, '')",
        "effectiveness_due_date": effectiveness_expr,
    }

    sort_expr = sort_map.get(sort_key)
    if sort_expr:
        order_by_sql = f"{sort_expr} {direction_sql}, audits.audit_date DESC, audit_findings.updated_at DESC, audit_findings.id DESC"
    else:
        order_by_sql = "audits.audit_date DESC, audit_findings.updated_at DESC, audit_findings.id DESC"

    rows = get_db().execute(
        f"""
        SELECT
            audit_findings.id,
            audit_findings.audit_id,
            audit_findings.supervisor_name,
            audit_findings.item_status,
            audit_findings.finding_status,
            audit_findings.priority,
            audit_findings.validation_status,
            audit_findings.treatment_reason,
            audit_findings.treatment_note,
            audit_findings.treatment_next_step,
            audit_findings.treatment_commitment_date,
            audit_findings.evidence_path,
            audit_findings.effectiveness_due_date,
            audit_findings.effectiveness_status,
            {created_at_expr} AS created_at,
            {updated_at_expr} AS updated_at,
            audits.audit_date,
            COALESCE(auditor_users.username, audits.auditor_name) AS auditor_name,
            audits.result_status,
            audits.location,
            mobile_units.mobile_code,
            COALESCE(technicians.name, audits.technician_display_name) AS technician_name,
            audit_items.section_title,
            audit_items.item_label,
            audit_items.non_compliance_reason,
            owners.username AS owner_username
        FROM audit_findings
        INNER JOIN audits ON audits.id = audit_findings.audit_id
        INNER JOIN audit_items ON audit_items.id = audit_findings.audit_item_id
        LEFT JOIN mobile_units ON mobile_units.id = audits.mobile_unit_id
        LEFT JOIN technicians ON technicians.id = audits.technician_id
        LEFT JOIN users AS auditor_users ON auditor_users.id = audits.auditor_user_id
        LEFT JOIN users AS owners ON owners.id = audit_findings.owner_user_id
        {where_sql}
        ORDER BY {order_by_sql}
        LIMIT ?
        OFFSET ?
        """,
        tuple(list(params) + [limit, offset]),
    ).fetchall()
    normalized = [dict(row) for row in rows]
    _annotate_findings_effectiveness(normalized)
    return normalized


def count_findings(filters=None, auditor_user_id=None, supervisor_scope_names=None):
    where_sql, params = _build_findings_where_sql(
        filters,
        auditor_user_id=auditor_user_id,
        supervisor_scope_names=supervisor_scope_names,
    )
    row = get_db().execute(
        f"""
        SELECT COUNT(*) AS findings_total
        FROM audit_findings
        INNER JOIN audits ON audits.id = audit_findings.audit_id
        INNER JOIN audit_items ON audit_items.id = audit_findings.audit_item_id
        LEFT JOIN mobile_units ON mobile_units.id = audits.mobile_unit_id
        LEFT JOIN technicians ON technicians.id = audits.technician_id
        LEFT JOIN users AS auditor_users ON auditor_users.id = audits.auditor_user_id
        LEFT JOIN users AS owners ON owners.id = audit_findings.owner_user_id
        {where_sql}
        """,
        params,
    ).fetchone()
    return int((row["findings_total"] or 0) if row else 0)


def fetch_finding_detail(finding_id, auditor_user_id=None, supervisor_scope_names=None):
    created_at_expr = "audit_findings.created_at"
    updated_at_expr = "audit_findings.updated_at"
    responded_at_expr = "audit_findings.responded_at"
    validated_at_expr = "audit_findings.validated_at"
    resolved_at_expr = "audit_findings.resolved_at"
    effectiveness_verified_at_expr = "audit_findings.effectiveness_verified_at"
    where_sql, params = _build_findings_where_sql(
        {"finding_id": finding_id},
        auditor_user_id=auditor_user_id,
        supervisor_scope_names=supervisor_scope_names,
    )
    extra_where = "audit_findings.id = ?"
    query_params = [finding_id]
    if where_sql:
        where_sql = where_sql + " AND " + extra_where
        query_params = list(params) + [finding_id]
    else:
        where_sql = "WHERE " + extra_where

    row = get_db().execute(
        f"""
        SELECT
            audit_findings.id,
            audit_findings.audit_id,
            audit_findings.audit_item_id,
            audit_findings.technician_id,
            audit_findings.supervisor_name,
            audit_findings.owner_user_id,
            audit_findings.item_status,
            audit_findings.finding_status,
            audit_findings.priority,
            audit_findings.response_notes,
            audit_findings.treatment_reason,
            audit_findings.treatment_note,
            audit_findings.treatment_next_step,
            audit_findings.treatment_commitment_date,
            audit_findings.evidence_path,
            audit_findings.closure_criteria,
            audit_findings.effectiveness_due_date,
            audit_findings.effectiveness_status,
            audit_findings.effectiveness_notes,
            {effectiveness_verified_at_expr} AS effectiveness_verified_at,
            audit_findings.validation_status,
            audit_findings.validation_notes,
            {created_at_expr} AS created_at,
            {updated_at_expr} AS updated_at,
            {responded_at_expr} AS responded_at,
            {validated_at_expr} AS validated_at,
            {resolved_at_expr} AS resolved_at,
            audits.audit_date,
            audits.auditor_name,
            audits.auditor_user_id,
            audits.sa_number,
            audits.location,
            audits.installation_type,
            audits.result_status,
            audits.total_score,
            audits.technician_company_snapshot,
            audits.technician_supervisor_snapshot,
            audits.technician_center_snapshot,
            mobile_units.mobile_code,
            COALESCE(technicians.name, audits.technician_display_name) AS technician_name,
            COALESCE(technicians.employee_code, audits.technician_employee_code) AS technician_employee_code,
            audit_items.section_key,
            audit_items.section_title,
            audit_items.item_key,
            audit_items.item_label,
            audit_items.is_critical,
            audit_items.non_compliance_reason,
            audit_items.notes AS item_notes,
            audit_items.photo_path,
            owners.username AS owner_username,
            responders.username AS responded_by_username,
            validators.username AS validated_by_username,
            effectiveness_verifiers.username AS effectiveness_verified_by_username
        FROM audit_findings
        INNER JOIN audits ON audits.id = audit_findings.audit_id
        INNER JOIN audit_items ON audit_items.id = audit_findings.audit_item_id
        LEFT JOIN mobile_units ON mobile_units.id = audits.mobile_unit_id
        LEFT JOIN technicians ON technicians.id = audits.technician_id
        LEFT JOIN users AS owners ON owners.id = audit_findings.owner_user_id
        LEFT JOIN users AS responders ON responders.id = audit_findings.responded_by_user_id
        LEFT JOIN users AS validators ON validators.id = audit_findings.validated_by_user_id
        LEFT JOIN users AS effectiveness_verifiers ON effectiveness_verifiers.id = audit_findings.effectiveness_verified_by_user_id
        {where_sql}
        """,
        tuple(query_params),
    ).fetchone()
    result = dict(row) if row else None
    if result:
        _annotate_effectiveness_due(result)
        _annotate_treatment_tracking(result)
        _annotate_finding_state(result)
        result["completion_checklist"] = build_finding_completion_checklist(result)
        result["lifecycle_timeline"] = build_finding_timeline(result)
    return result


def fetch_effectiveness_alerts(auditor_user_id=None, supervisor_scope_names=None, limit=8):
    where_clauses = []
    params = []

    append_audit_visibility_filters(where_clauses, params)
    append_supervisor_scope_filters(where_clauses, params, supervisor_scope_names=supervisor_scope_names)

    if auditor_user_id is not None:
        where_clauses.append("audits.auditor_user_id = ?")
        params.append(auditor_user_id)

    where_clauses.append("COALESCE(audit_findings.validation_status, '') = 'validado'")
    where_clauses.append("COALESCE(audit_findings.effectiveness_status, '') = 'pendiente'")
    where_clauses.append("COALESCE(audit_findings.effectiveness_due_date, '') != ''")
    if is_postgres():
        where_clauses.append("substring(audit_findings.effectiveness_due_date, 1, 10) ~ '^\\d{4}-\\d{2}-\\d{2}$'")

    where_sql = ""
    if where_clauses:
        where_sql = "WHERE " + " AND ".join(where_clauses)

    alert_days = _effectiveness_alert_window_days()
    today_iso = _today_in_app_tz().isoformat()
    end_iso = _date_range_end_in_app_tz(alert_days).isoformat()

    if is_postgres():
        overdue_expr = "to_date(substring(audit_findings.effectiveness_due_date, 1, 10), 'YYYY-MM-DD') < ?::date"
        due_soon_expr = (
            "to_date(substring(audit_findings.effectiveness_due_date, 1, 10), 'YYYY-MM-DD') >= ?::date "
            "AND to_date(substring(audit_findings.effectiveness_due_date, 1, 10), 'YYYY-MM-DD') <= ?::date"
        )
        count_params = tuple(list(params) + [today_iso, today_iso, end_iso])
    else:
        overdue_expr = "date(substr(audit_findings.effectiveness_due_date, 1, 10)) < date(?)"
        due_soon_expr = (
            "date(substr(audit_findings.effectiveness_due_date, 1, 10)) >= date(?) "
            "AND date(substr(audit_findings.effectiveness_due_date, 1, 10)) <= date(?)"
        )
        count_params = tuple(list(params) + [today_iso, today_iso, end_iso])

    count_row = get_db().execute(
        f"""
        SELECT
            SUM(CASE WHEN {overdue_expr} THEN 1 ELSE 0 END) AS overdue_count,
            SUM(CASE WHEN {due_soon_expr} THEN 1 ELSE 0 END) AS due_soon_count
        FROM audit_findings
        INNER JOIN audits ON audits.id = audit_findings.audit_id
        {where_sql}
        """,
        count_params,
    ).fetchone()

    overdue_count = (count_row.get("overdue_count") if isinstance(count_row, dict) else count_row[0]) or 0
    due_soon_count = (count_row.get("due_soon_count") if isinstance(count_row, dict) else count_row[1]) or 0

    preview_where_sql = where_sql
    preview_params_prefix = list(params) + [today_iso, today_iso, end_iso]
    if preview_where_sql:
        preview_where_sql = preview_where_sql + f" AND ({overdue_expr} OR {due_soon_expr})"
    else:
        preview_where_sql = f"WHERE ({overdue_expr} OR {due_soon_expr})"

    preview_rows = get_db().execute(
        f"""
        SELECT
            audit_findings.id,
            audit_findings.audit_id,
            audits.audit_date,
            mobile_units.mobile_code,
            COALESCE(technicians.name, audits.technician_display_name) AS technician_name,
            audit_items.section_title,
            audit_items.item_label,
            audit_findings.effectiveness_due_date,
            audit_findings.effectiveness_status
        FROM audit_findings
        INNER JOIN audits ON audits.id = audit_findings.audit_id
        INNER JOIN audit_items ON audit_items.id = audit_findings.audit_item_id
        LEFT JOIN mobile_units ON mobile_units.id = audits.mobile_unit_id
        LEFT JOIN technicians ON technicians.id = audits.technician_id
        {preview_where_sql}
        ORDER BY audit_findings.effectiveness_due_date ASC, audit_findings.id ASC
        LIMIT ?
        """,
        tuple(preview_params_prefix + [int(limit or 0) or 8]),
    ).fetchall()

    preview = [dict(row) for row in preview_rows]
    _annotate_findings_effectiveness(preview)

    return {
        "alert_days": alert_days,
        "overdue_count": overdue_count,
        "due_soon_count": due_soon_count,
        "total": overdue_count + due_soon_count,
        "rows": preview,
    }


def _default_effectiveness_due_date_iso():
    days = int(current_app.config.get("FINDING_EFFECTIVENESS_CHECK_DAYS") or 30)
    return (_today_in_app_tz() + timedelta(days=days)).isoformat()


def _normalize_effectiveness_due_date(value):
    raw = (value or "").strip()
    if not raw:
        return None
    try:
        return datetime.strptime(raw, "%Y-%m-%d").date().isoformat()
    except ValueError as exc:
        raise ValueError("La fecha de verificación de eficacia no es válida (usa AAAA-MM-DD).") from exc


def _effectiveness_alert_window_days():
    try:
        return max(1, int(current_app.config.get("FINDING_EFFECTIVENESS_ALERT_DAYS") or 7))
    except (TypeError, ValueError):
        return 7


def _pending_validation_alert_window_days():
    try:
        return max(1, int(current_app.config.get("FINDING_PENDING_VALIDATION_ALERT_DAYS") or 3))
    except (TypeError, ValueError):
        return 3


def _treatment_update_alert_window_days():
    try:
        return max(1, int(current_app.config.get("FINDING_TREATMENT_UPDATE_ALERT_DAYS") or 3))
    except (TypeError, ValueError):
        return 3


def _treatment_update_escalation_days():
    try:
        configured = int(current_app.config.get("FINDING_TREATMENT_UPDATE_ESCALATION_DAYS") or 7)
    except (TypeError, ValueError):
        configured = 7
    return max(_treatment_update_alert_window_days(), configured)


def _treatment_update_cutoff_in_app_tz(days):
    return _today_in_app_tz() - timedelta(days=max(0, int(days or 0)))


def _parse_iso_date(value):
    raw = (value or "").strip()
    if not raw:
        return None
    try:
        return datetime.strptime(raw, "%Y-%m-%d").date()
    except ValueError:
        return None


def _annotate_effectiveness_due(row, today=None):
    if not isinstance(row, dict):
        return row

    today = today or _today_in_app_tz()
    alert_days = _effectiveness_alert_window_days()
    due_date = _parse_iso_date(row.get("effectiveness_due_date"))
    effectiveness_status = (row.get("effectiveness_status") or "").strip().lower()
    finding_status = (row.get("finding_status") or "").strip().lower()

    bucket = "none"
    days_to_due = None

    if effectiveness_status == "eficaz" or finding_status == "cerrado_definitivo":
        bucket = "ok"
    elif due_date:
        days_to_due = (due_date - today).days
        if days_to_due < 0:
            bucket = "overdue"
        elif days_to_due <= alert_days:
            bucket = "due_soon"
        else:
            bucket = "upcoming"

    row["effectiveness_due_bucket"] = bucket
    row["effectiveness_days_to_due"] = days_to_due
    return row


def _annotate_findings_effectiveness(rows):
    if not rows:
        return rows
    today = _today_in_app_tz()
    for row in rows:
        _annotate_effectiveness_due(row, today=today)
        _annotate_treatment_tracking(row, today=today)
        _annotate_finding_state(row)
    return rows


def _parse_db_datetime(value):
    raw = (value or "").strip() if isinstance(value, str) else value
    if not raw:
        return None
    if isinstance(raw, datetime):
        dt = raw
    else:
        text = str(raw).strip()
        try:
            dt = datetime.fromisoformat(text.replace("Z", "+00:00"))
        except ValueError:
            try:
                dt = datetime.strptime(text[:19], "%Y-%m-%d %H:%M:%S")
            except ValueError:
                return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(_app_timezone())


def treatment_reason_label(value):
    normalized = (value or "").strip().lower()
    if not normalized:
        return ""
    return TREATMENT_REASON_LABELS.get(normalized, normalized.replace("_", " ").capitalize())


def _normalize_treatment_reason(value):
    normalized = (value or "").strip().lower()
    if not normalized:
        return None
    if normalized not in TREATMENT_REASON_LABELS:
        raise ValueError("El motivo de tratamiento no es valido.")
    return normalized


def _normalize_treatment_commitment_date(value):
    raw = (value or "").strip()
    if not raw:
        return None
    try:
        return datetime.strptime(raw, "%Y-%m-%d").date().isoformat()
    except ValueError as exc:
        raise ValueError("La fecha compromiso no es valida (usa AAAA-MM-DD).") from exc


def _annotate_treatment_tracking(row, today=None):
    if not isinstance(row, dict):
        return row

    today = today or _today_in_app_tz()
    finding_status = (row.get("finding_status") or "").strip().lower()
    commitment_date = _parse_iso_date(row.get("treatment_commitment_date"))
    last_update_dt = _parse_db_datetime(row.get("updated_at") or row.get("responded_at") or row.get("created_at"))

    days_without_update = None
    if last_update_dt:
        days_without_update = max(0, (today - last_update_dt.date()).days)

    alert_days = _treatment_update_alert_window_days()
    escalation_days = _treatment_update_escalation_days()
    alert_level = "none"
    alert_label = ""
    if finding_status == "respondido" and days_without_update is not None:
        if days_without_update >= escalation_days:
            alert_level = "danger"
            alert_label = "Escalado"
        elif days_without_update >= alert_days:
            alert_level = "warning"
            alert_label = "Sin novedades"

    commitment_bucket = "none"
    commitment_days_to_due = None
    if commitment_date:
        commitment_days_to_due = (commitment_date - today).days
        if commitment_days_to_due < 0:
            commitment_bucket = "overdue"
        elif commitment_days_to_due == 0:
            commitment_bucket = "due_today"
        else:
            commitment_bucket = "upcoming"

    row["treatment_reason_label"] = treatment_reason_label(row.get("treatment_reason"))
    row["treatment_last_update_at"] = last_update_dt.isoformat() if last_update_dt else None
    row["treatment_days_without_update"] = days_without_update
    row["treatment_alert_level"] = alert_level
    row["treatment_alert_label"] = alert_label
    row["treatment_commitment_bucket"] = commitment_bucket
    row["treatment_commitment_days_to_due"] = commitment_days_to_due
    return row


def _annotate_finding_state(row):
    if not isinstance(row, dict):
        return row

    finding_status = (row.get("finding_status") or "").strip().lower()
    validation_status = (row.get("validation_status") or "").strip().lower()
    effectiveness_status = (row.get("effectiveness_status") or "").strip().lower()
    due_bucket = (row.get("effectiveness_due_bucket") or "").strip().lower()

    consolidated_key = "nuevo"
    consolidated_label = "Nuevo"
    consolidated_tone = "neutral"
    next_action = "Responder hallazgo"
    summary = "Pendiente de gestión inicial del supervisor."

    if effectiveness_status == "eficaz" or finding_status == "cerrado_definitivo":
        consolidated_key = "cerrado_definitivo"
        consolidated_label = "Cerrado definitivo"
        consolidated_tone = "ok"
        next_action = "Sin acción pendiente"
        summary = "Hallazgo validado y verificado como eficaz."
    elif finding_status == "reabierto" and effectiveness_status == "no_eficaz":
        consolidated_key = "reabierto_no_eficaz"
        consolidated_label = "Reabierto por no eficacia"
        consolidated_tone = "danger"
        next_action = "Corregir y volver a cerrar"
        summary = "La eficacia fue rechazada y el hallazgo volvió al supervisor."
    elif finding_status == "reabierto" or validation_status == "rechazado":
        consolidated_key = "reabierto"
        consolidated_label = "Reabierto"
        consolidated_tone = "danger"
        next_action = "Corregir y volver a cerrar"
        summary = "El cierre fue rechazado y requiere una nueva gestión."
    elif validation_status == "validado":
        consolidated_key = "validado_pendiente_eficacia"
        consolidated_label = "Validado pendiente eficacia"
        consolidated_tone = "warning"
        if due_bucket == "overdue":
            consolidated_tone = "danger"
            summary = "Hallazgo validado con verificación de eficacia vencida."
        elif due_bucket == "due_soon":
            summary = "Hallazgo validado con verificación de eficacia próxima a vencer."
        else:
            summary = "Hallazgo validado a la espera de verificación de eficacia."
        next_action = "Registrar verificación de eficacia"
    elif finding_status == "resuelto":
        consolidated_key = "cer_pve"
        consolidated_label = "CER-PVE"
        consolidated_tone = "warning"
        next_action = "Validar cierre"
        summary = "El supervisor cerró el hallazgo y queda revisión gerencial."
    elif finding_status == "respondido":
        consolidated_key = "en_tratamiento"
        consolidated_label = "En tratamiento"
        consolidated_tone = "neutral"
        next_action = "Completar cierre"
        if row.get("treatment_alert_level") == "danger":
            consolidated_tone = "danger"
            summary = "El hallazgo sigue en tratamiento y supero el umbral de escalamiento sin novedades."
        elif row.get("treatment_alert_level") == "warning":
            consolidated_tone = "warning"
            summary = "El hallazgo sigue en tratamiento y ya requiere una nueva novedad para mantener trazabilidad."
        else:
            summary = "Existe respuesta del supervisor, pero el cierre aún no está completo."
        if row.get("treatment_reason_label"):
            summary = f"{summary} Motivo actual: {row['treatment_reason_label']}."

    row["consolidated_status_key"] = consolidated_key
    row["consolidated_status_label"] = consolidated_label
    row["consolidated_status_tone"] = consolidated_tone
    row["consolidated_next_action"] = next_action
    row["consolidated_status_summary"] = summary
    return row


def build_finding_completion_checklist(row):
    finding_status = (row.get("finding_status") or "").strip().lower()
    response_ready = bool((row.get("response_notes") or "").strip())
    treatment_reason_ready = bool((row.get("treatment_reason") or "").strip())
    treatment_note_ready = bool((row.get("treatment_note") or "").strip())
    treatment_next_step_ready = bool((row.get("treatment_next_step") or "").strip())
    treatment_commitment_ready = bool((row.get("treatment_commitment_date") or "").strip())
    evidence_ready = bool(row.get("evidence_path"))
    criteria_ready = bool((row.get("closure_criteria") or "").strip())
    due_date_ready = bool((row.get("effectiveness_due_date") or "").strip())
    validation_status = (row.get("validation_status") or "").strip().lower()
    effectiveness_status = (row.get("effectiveness_status") or "").strip().lower()

    checklist = [
        {
            "label": "Respuesta del supervisor",
            "state": "complete" if response_ready else "pending",
            "detail": "Registrada." if response_ready else "Falta documentar la gestión realizada.",
        },
        {
            "label": "Evidencia fotográfica",
            "state": "complete" if evidence_ready else "pending",
            "detail": "Cargada." if evidence_ready else "Falta adjuntar evidencia para cierre.",
        },
        {
            "label": "Criterio de cierre",
            "state": "complete" if criteria_ready else "pending",
            "detail": "Registrado." if criteria_ready else "Falta explicar cómo se corrigió el hallazgo.",
        },
        {
            "label": "Fecha de eficacia",
            "state": "complete" if due_date_ready else "pending",
            "detail": (row.get("effectiveness_due_date") or "").strip() or "Falta programar la verificación de eficacia.",
        },
    ]

    if finding_status == "respondido":
        checklist[1:1] = [
            {
                "label": "Motivo actual",
                "state": "complete" if treatment_reason_ready else "pending",
                "detail": row.get("treatment_reason_label") or "Falta registrar por que sigue en tratamiento.",
            },
            {
                "label": "Ultima novedad",
                "state": "complete" if treatment_note_ready else "pending",
                "detail": "Registrada." if treatment_note_ready else "Falta dejar una novedad de seguimiento.",
            },
            {
                "label": "Proximo paso",
                "state": "complete" if treatment_next_step_ready else "pending",
                "detail": (row.get("treatment_next_step") or "").strip() or "Falta definir la siguiente accion comprometida.",
            },
            {
                "label": "Fecha compromiso",
                "state": "complete" if treatment_commitment_ready else "pending",
                "detail": (row.get("treatment_commitment_date") or "").strip() or "Falta informar cuando deberia haber un nuevo avance.",
            },
        ]

    if validation_status == "validado":
        checklist.append(
            {
                "label": "Validación gerencial",
                "state": "complete",
                "detail": "Cierre validado por gerencia.",
            }
        )
    elif validation_status == "rechazado":
        checklist.append(
            {
                "label": "Validación gerencial",
                "state": "issue",
                "detail": "El cierre fue rechazado y el hallazgo quedó reabierto.",
            }
        )
    else:
        checklist.append(
            {
                "label": "Validación gerencial",
                "state": "pending",
                "detail": "Aún no pasa por revisión gerencial.",
            }
        )

    if effectiveness_status == "eficaz":
        checklist.append(
            {
                "label": "Verificación de eficacia",
                "state": "complete",
                "detail": "La acción correctiva fue eficaz.",
            }
        )
    elif effectiveness_status == "no_eficaz":
        checklist.append(
            {
                "label": "Verificación de eficacia",
                "state": "issue",
                "detail": "La acción correctiva no fue eficaz y el hallazgo se reabrió.",
            }
        )
    elif validation_status == "validado":
        checklist.append(
            {
                "label": "Verificación de eficacia",
                "state": "pending",
                "detail": "Está pendiente el control post-cierre.",
            }
        )
    else:
        checklist.append(
            {
                "label": "Verificación de eficacia",
                "state": "pending",
                "detail": "Se habilita una vez validado el cierre.",
            }
        )

    completed_count = sum(1 for item in checklist if item["state"] == "complete")
    pending_count = len(checklist) - completed_count
    return {
        "items": checklist,
        "completed_count": completed_count,
        "pending_count": pending_count,
        "total_count": len(checklist),
    }


def build_finding_timeline(row):
    validation_status = (row.get("validation_status") or "").strip().lower()
    effectiveness_status = (row.get("effectiveness_status") or "").strip().lower()
    finding_status = (row.get("finding_status") or "").strip().lower()

    timeline = [
        {
            "label": "Creado",
            "date": row.get("created_at"),
            "state": "complete",
            "detail": "Hallazgo generado desde la auditoría.",
        },
        {
            "label": "Respondido",
            "date": row.get("responded_at"),
            "state": "complete" if row.get("responded_at") else ("current" if finding_status in {"respondido", "resuelto", "reabierto", "cerrado_definitivo"} else "pending"),
            "detail": "Gestión documentada por el supervisor.",
        },
        {
            "label": "CER-PVE",
            "date": row.get("resolved_at"),
            "state": "complete" if row.get("resolved_at") and finding_status in {"resuelto", "cerrado_definitivo"} else ("issue" if finding_status == "reabierto" else ("current" if finding_status == "respondido" else "pending")),
            "detail": "Cierre operativo con evidencia y criterio.",
        },
        {
            "label": "Validación",
            "date": row.get("validated_at"),
            "state": "complete" if validation_status == "validado" else ("issue" if validation_status == "rechazado" else ("current" if finding_status == "resuelto" else "pending")),
            "detail": "Revisión final del cierre por gerencia.",
        },
        {
            "label": "Eficacia",
            "date": row.get("effectiveness_verified_at"),
            "state": "complete" if effectiveness_status == "eficaz" else ("issue" if effectiveness_status == "no_eficaz" else ("current" if validation_status == "validado" else "pending")),
            "detail": "Verificación posterior para confirmar efectividad.",
        },
    ]
    return timeline


def update_finding_response(
    finding_id,
    finding_status,
    response_notes,
    treatment_reason,
    treatment_note,
    treatment_next_step,
    treatment_commitment_date,
    evidence_path,
    closure_criteria,
    effectiveness_due_date,
    responded_by_user_id,
):
    safe_status = (finding_status or "").strip().lower()
    if safe_status not in {"respondido", "resuelto"}:
        raise ValueError("El estado de respuesta no es válido.")

    notes_value = (response_notes or "").strip() or None
    if not notes_value:
        raise ValueError("Debes ingresar una respuesta para el hallazgo.")

    existing = get_db().execute(
        """
        SELECT
            finding_status,
            validation_status,
            validation_notes,
            response_notes,
            treatment_reason,
            treatment_note,
            treatment_next_step,
            treatment_commitment_date,
            evidence_path,
            closure_criteria,
            effectiveness_due_date,
            effectiveness_status,
            effectiveness_notes
        FROM audit_findings
        WHERE id = ?
        """,
        (finding_id,),
    ).fetchone()
    if not existing:
        return False

    if isinstance(existing, dict):
        previous_finding_status = (existing.get("finding_status") or "").strip().lower()
        previous_validation_status = (existing.get("validation_status") or "").strip().lower()
        previous_validation_notes = existing.get("validation_notes")
        previous_response_notes = existing.get("response_notes")
        previous_treatment_reason = existing.get("treatment_reason")
        previous_treatment_note = existing.get("treatment_note")
        previous_treatment_next_step = existing.get("treatment_next_step")
        previous_treatment_commitment_date = existing.get("treatment_commitment_date")
        previous_evidence = existing.get("evidence_path")
        previous_criteria = existing.get("closure_criteria")
        previous_due_date = existing.get("effectiveness_due_date")
        previous_effectiveness_status = existing.get("effectiveness_status")
    else:
        previous_finding_status = (existing[0] or "").strip().lower()
        previous_validation_status = (existing[1] or "").strip().lower()
        previous_validation_notes = existing[2]
        previous_response_notes = existing[3]
        previous_treatment_reason = existing[4]
        previous_treatment_note = existing[5]
        previous_treatment_next_step = existing[6]
        previous_treatment_commitment_date = existing[7]
        previous_evidence = existing[8]
        previous_criteria = existing[9]
        previous_due_date = existing[10]
        previous_effectiveness_status = existing[11]

    if previous_validation_status == "validado" or previous_finding_status == "validado":
        raise ValueError("No puedes editar un hallazgo ya validado.")

    reset_cycle = previous_finding_status == "reabierto" or previous_validation_status == "rechazado" or previous_effectiveness_status == "no_eficaz"
    evidence_value = evidence_path if evidence_path is not None else previous_evidence
    criteria_value = (closure_criteria or "").strip() or previous_criteria or None
    due_date_value = _normalize_effectiveness_due_date(effectiveness_due_date)
    treatment_reason_raw = (treatment_reason or "").strip()
    treatment_note_raw = (treatment_note or "").strip()
    treatment_next_step_raw = (treatment_next_step or "").strip()
    treatment_commitment_raw = (treatment_commitment_date or "").strip()
    treatment_reason_value = _normalize_treatment_reason(treatment_reason_raw) if treatment_reason_raw else previous_treatment_reason
    treatment_note_value = treatment_note_raw or previous_treatment_note or None
    treatment_next_step_value = treatment_next_step_raw or previous_treatment_next_step or None
    treatment_commitment_value = (
        _normalize_treatment_commitment_date(treatment_commitment_raw)
        if treatment_commitment_raw
        else previous_treatment_commitment_date
    )
    if not due_date_value and not reset_cycle:
        due_date_value = previous_due_date or None
    effectiveness_status_value = None if reset_cycle else ((previous_effectiveness_status or "").strip() or None)
    validation_status_value = None if reset_cycle else (previous_validation_status or None)
    validation_notes_value = None if reset_cycle else previous_validation_notes

    if safe_status == "respondido" and previous_finding_status != "respondido" and not treatment_note_raw:
        treatment_note_value = None
    elif safe_status != "respondido" and previous_finding_status != "respondido":
        if not treatment_reason_raw:
            treatment_reason_value = None
        if not treatment_note_raw:
            treatment_note_value = None
        if not treatment_next_step_raw:
            treatment_next_step_value = None
        if not treatment_commitment_raw:
            treatment_commitment_value = None

    if safe_status == "respondido":
        if not treatment_reason_value:
            raise ValueError("Debes indicar el motivo actual del tratamiento.")
        if not treatment_next_step_value:
            raise ValueError("Debes indicar el proximo paso comprometido.")
        if not treatment_commitment_value:
            raise ValueError("Debes indicar la fecha compromiso del tratamiento.")

    if safe_status == "resuelto":
        if not evidence_value:
            raise ValueError("Debes adjuntar evidencia fotográfica para marcar el hallazgo como resuelto.")
        if not criteria_value:
            raise ValueError("Debes ingresar el criterio de cierre para marcar el hallazgo como resuelto.")
        if not due_date_value:
            due_date_value = _default_effectiveness_due_date_iso()
        if not effectiveness_status_value:
            effectiveness_status_value = "pendiente"

    changes = []
    if previous_finding_status != safe_status:
        changes.append(f"estado: {previous_finding_status or '-'} -> {safe_status}")
    if (previous_response_notes or "") != (notes_value or ""):
        changes.append("respuesta actualizada")
    if (previous_treatment_reason or "") != (treatment_reason_value or ""):
        changes.append("motivo de tratamiento actualizado")
    if (previous_treatment_note or "") != (treatment_note_value or ""):
        changes.append("novedad actualizada")
    if (previous_treatment_next_step or "") != (treatment_next_step_value or ""):
        changes.append("proximo paso actualizado")
    if (previous_treatment_commitment_date or "") != (treatment_commitment_value or ""):
        changes.append("fecha compromiso actualizada")
    if (previous_criteria or "") != (criteria_value or ""):
        changes.append("criterio de cierre actualizado")
    if (previous_due_date or "") != (due_date_value or ""):
        changes.append("fecha de eficacia actualizada")
    if (previous_evidence or "") != (evidence_value or ""):
        changes.append("evidencia actualizada")

    get_db().execute(
        """
        UPDATE audit_findings
        SET
            finding_status = ?,
            response_notes = ?,
            treatment_reason = ?,
            treatment_note = ?,
            treatment_next_step = ?,
            treatment_commitment_date = ?,
            evidence_path = ?,
            closure_criteria = ?,
            effectiveness_due_date = ?,
            effectiveness_status = ?,
            effectiveness_notes = CASE WHEN ? THEN NULL ELSE effectiveness_notes END,
            validation_status = ?,
            validation_notes = ?,
            validated_by_user_id = CASE WHEN ? THEN NULL ELSE validated_by_user_id END,
            validated_at = CASE WHEN ? THEN NULL ELSE validated_at END,
            effectiveness_verified_by_user_id = CASE WHEN ? THEN NULL ELSE effectiveness_verified_by_user_id END,
            effectiveness_verified_at = CASE WHEN ? THEN NULL ELSE effectiveness_verified_at END,
            responded_by_user_id = ?,
            responded_at = CURRENT_TIMESTAMP,
            resolved_at = CASE WHEN ? = 'resuelto' THEN CURRENT_TIMESTAMP ELSE NULL END,
            updated_at = CURRENT_TIMESTAMP
        WHERE id = ?
        """,
        (
            safe_status,
            notes_value,
            treatment_reason_value,
            treatment_note_value,
            treatment_next_step_value,
            treatment_commitment_value,
            evidence_value,
            criteria_value,
            due_date_value,
            effectiveness_status_value,
            reset_cycle,
            validation_status_value,
            validation_notes_value,
            reset_cycle,
            reset_cycle,
            reset_cycle,
            reset_cycle,
            responded_by_user_id,
            safe_status,
            finding_id,
        ),
    )
    if changes:
        create_finding_event(
            finding_id,
            actor_user_id=responded_by_user_id,
            event_type="respuesta",
            detail="; ".join(changes),
        )
    get_db().commit()
    return True


def add_finding_treatment_update(
    finding_id,
    treatment_reason,
    treatment_note,
    treatment_next_step,
    treatment_commitment_date,
    actor_user_id,
):
    reason_value = _normalize_treatment_reason(treatment_reason)
    note_value = (treatment_note or "").strip() or None
    next_step_value = (treatment_next_step or "").strip() or None
    commitment_value = _normalize_treatment_commitment_date(treatment_commitment_date)

    if not reason_value:
        raise ValueError("Debes indicar el motivo actual del tratamiento.")
    if not note_value:
        raise ValueError("Debes ingresar la novedad actual del tratamiento.")
    if not next_step_value:
        raise ValueError("Debes indicar el proximo paso comprometido.")
    if not commitment_value:
        raise ValueError("Debes indicar la fecha compromiso del tratamiento.")

    existing = get_db().execute(
        """
        SELECT finding_status, validation_status
        FROM audit_findings
        WHERE id = ?
        """,
        (finding_id,),
    ).fetchone()
    if not existing:
        return False

    if isinstance(existing, dict):
        current_status = (existing.get("finding_status") or "").strip().lower()
        current_validation_status = (existing.get("validation_status") or "").strip().lower()
    else:
        current_status = (existing[0] or "").strip().lower()
        current_validation_status = (existing[1] or "").strip().lower()

    if current_validation_status == "validado":
        raise ValueError("No puedes cargar novedades en un hallazgo ya validado.")
    if current_status != "respondido":
        raise ValueError("Solo puedes cargar novedades cuando el hallazgo esta en tratamiento.")

    get_db().execute(
        """
        UPDATE audit_findings
        SET
            treatment_reason = ?,
            treatment_note = ?,
            treatment_next_step = ?,
            treatment_commitment_date = ?,
            updated_at = CURRENT_TIMESTAMP
        WHERE id = ?
        """,
        (reason_value, note_value, next_step_value, commitment_value, finding_id),
    )
    create_finding_event(
        finding_id,
        actor_user_id=actor_user_id,
        event_type="novedad_tratamiento",
        detail=(
            f"Motivo: {treatment_reason_label(reason_value)}; "
            f"Novedad: {note_value}; "
            f"Proximo paso: {next_step_value}; "
            f"Fecha compromiso: {commitment_value}"
        ),
    )
    get_db().commit()
    return True


def validate_finding(finding_id, validated_by_user_id, approved, validation_notes=None):
    existing = get_db().execute(
        """
        SELECT
            finding_status,
            validation_status,
            evidence_path,
            closure_criteria,
            effectiveness_due_date,
            effectiveness_status
        FROM audit_findings
        WHERE id = ?
        """,
        (finding_id,),
    ).fetchone()
    if not existing:
        return False

    if isinstance(existing, dict):
        current_status = (existing.get("finding_status") or "").strip().lower()
        current_validation_status = (existing.get("validation_status") or "").strip().lower()
        evidence_path = existing.get("evidence_path")
        closure_criteria = (existing.get("closure_criteria") or "").strip()
        effectiveness_due_date = (existing.get("effectiveness_due_date") or "").strip()
        effectiveness_status = (existing.get("effectiveness_status") or "").strip()
    else:
        current_status = (existing[0] or "").strip().lower()
        current_validation_status = (existing[1] or "").strip().lower()
        evidence_path = existing[2]
        closure_criteria = (existing[3] or "").strip()
        effectiveness_due_date = (existing[4] or "").strip()
        effectiveness_status = (existing[5] or "").strip()

    due_date_value = effectiveness_due_date or None
    effectiveness_status_value = effectiveness_status or None

    if approved:
        if current_status not in {"resuelto", "validado"}:
            raise ValueError("El hallazgo debe estar en estado resuelto antes de validar el cierre.")
        if not evidence_path:
            raise ValueError("Falta la evidencia fotográfica. Completa la respuesta del supervisor antes de validar.")
        if not closure_criteria:
            raise ValueError("Falta el criterio de cierre. Completa la respuesta del supervisor antes de validar.")
        if not due_date_value:
            due_date_value = _default_effectiveness_due_date_iso()
        if not effectiveness_status_value:
            effectiveness_status_value = "pendiente"

    status = "validado" if approved else "rechazado"
    notes_value = (validation_notes or "").strip() or None

    if approved:
        get_db().execute(
            """
            UPDATE audit_findings
            SET
                validation_status = ?,
                validation_notes = ?,
                validated_by_user_id = ?,
                validated_at = CURRENT_TIMESTAMP,
                effectiveness_due_date = COALESCE(effectiveness_due_date, ?),
                effectiveness_status = COALESCE(NULLIF(effectiveness_status, ''), ?),
                updated_at = CURRENT_TIMESTAMP
            WHERE id = ?
            """,
            (
                status,
                notes_value,
                validated_by_user_id,
                due_date_value,
                effectiveness_status_value,
                finding_id,
            ),
        )
    else:
        get_db().execute(
            """
            UPDATE audit_findings
            SET
                validation_status = ?,
                validation_notes = ?,
                validated_by_user_id = NULL,
                validated_at = NULL,
                finding_status = ?,
                effectiveness_due_date = NULL,
                effectiveness_status = NULL,
                effectiveness_notes = NULL,
                effectiveness_verified_by_user_id = NULL,
                effectiveness_verified_at = NULL,
                updated_at = CURRENT_TIMESTAMP
            WHERE id = ?
            """,
            (
                status,
                notes_value,
                "reabierto",
                finding_id,
            ),
        )
    create_finding_event(
        finding_id,
        actor_user_id=validated_by_user_id,
        event_type="validacion",
        detail=("validado" if approved else "reabierto") + (f"; notas: {notes_value}" if notes_value else ""),
    )
    get_db().commit()
    return True


def update_finding_effectiveness(
    finding_id,
    effectiveness_status,
    effectiveness_notes,
    verified_by_user_id,
    allow_override=False,
):
    safe_status = (effectiveness_status or "").strip().lower()
    if safe_status not in {"pendiente", "eficaz", "no_eficaz"}:
        raise ValueError("El resultado de eficacia no es válido.")

    notes_value = (effectiveness_notes or "").strip() or None

    existing = get_db().execute(
        "SELECT finding_status, validation_status, effectiveness_status FROM audit_findings WHERE id = ?",
        (finding_id,),
    ).fetchone()
    if not existing:
        return False

    if isinstance(existing, dict):
        current_finding_status = (existing.get("finding_status") or "").strip().lower()
        current_validation_status = (existing.get("validation_status") or "").strip().lower()
        previous_status = (existing.get("effectiveness_status") or "").strip().lower()
    else:
        current_finding_status = (existing[0] or "").strip().lower()
        current_validation_status = (existing[1] or "").strip().lower()
        previous_status = (existing[2] or "").strip().lower()

    is_validated = current_validation_status == "validado" or current_finding_status == "validado"
    if safe_status in {"eficaz", "no_eficaz"} and not is_validated:
        raise ValueError("Solo puedes registrar eficacia una vez que el hallazgo esté validado.")

    if previous_status in {"eficaz", "no_eficaz"} and safe_status != previous_status and not allow_override:
        raise ValueError("La eficacia ya fue registrada y no se puede modificar.")

    if safe_status == "pendiente":
        get_db().execute(
            """
            UPDATE audit_findings
            SET
                effectiveness_status = ?,
                effectiveness_notes = ?,
                finding_status = CASE WHEN finding_status = 'cerrado_definitivo' THEN 'resuelto' ELSE finding_status END,
                effectiveness_verified_by_user_id = NULL,
                effectiveness_verified_at = NULL,
                updated_at = CURRENT_TIMESTAMP
            WHERE id = ?
            """,
            ("pendiente", notes_value, finding_id),
        )
    else:
        if safe_status == "eficaz":
            get_db().execute(
                """
                UPDATE audit_findings
                SET
                    effectiveness_status = ?,
                    effectiveness_notes = ?,
                    finding_status = 'cerrado_definitivo',
                    effectiveness_verified_by_user_id = ?,
                    effectiveness_verified_at = CURRENT_TIMESTAMP,
                    updated_at = CURRENT_TIMESTAMP
                WHERE id = ?
                """,
                (safe_status, notes_value, verified_by_user_id, finding_id),
            )
        else:
            get_db().execute(
                """
                UPDATE audit_findings
                SET
                    effectiveness_status = ?,
                    effectiveness_notes = ?,
                    finding_status = 'reabierto',
                    validation_status = 'rechazado',
                    validated_by_user_id = NULL,
                    validated_at = NULL,
                    effectiveness_due_date = NULL,
                    effectiveness_verified_by_user_id = ?,
                    effectiveness_verified_at = CURRENT_TIMESTAMP,
                    updated_at = CURRENT_TIMESTAMP
                WHERE id = ?
                """,
                (safe_status, notes_value, verified_by_user_id, finding_id),
            )

    if previous_status != safe_status:
        create_finding_event(
            finding_id,
            actor_user_id=verified_by_user_id,
            event_type="eficacia",
            detail=f"{previous_status or '-'} -> {safe_status}",
        )
    get_db().commit()
    return True


def _finding_priority_for_item(item):
    status = str(item.get("status") or "").strip().lower()
    if item.get("is_critical") or status == "nc_mayor":
        return "alta"
    if status == "nc_menor":
        return "media"
    return "media"


def create_audit_findings(audit_id, audit_data, inserted_items, connection=None):
    connection = connection or get_db()
    supervisor_name = normalize_supervisor_scope_name(audit_data.get("technician_supervisor_snapshot"))
    owner_user_id = find_owner_user_id_by_supervisor_name(supervisor_name)
    owner_username = None
    if owner_user_id:
        owner_row = connection.execute("SELECT username FROM users WHERE id = ?", (owner_user_id,)).fetchone()
        if owner_row:
            owner_username = owner_row["username"] if isinstance(owner_row, dict) else owner_row[0]

    finding_rows = []
    for item in inserted_items:
        status = str(item.get("status") or "").strip().lower()
        if status not in {"no_cumple", "nc_menor", "nc_mayor"}:
            continue
        finding_rows.append(
            (
                audit_id,
                item["id"],
                audit_data.get("technician_id"),
                supervisor_name or None,
                owner_user_id,
                item["status"],
                _finding_priority_for_item(item),
            )
        )

    if not finding_rows:
        return 0

    inserted_count = 0
    for finding_row in finding_rows:
        if is_postgres():
            inserted = connection.execute(
                """
                INSERT INTO audit_findings (
                    audit_id,
                    audit_item_id,
                    technician_id,
                    supervisor_name,
                    owner_user_id,
                    item_status,
                    priority
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                RETURNING id
                """,
                finding_row,
            ).fetchone()
            finding_id = inserted["id"] if isinstance(inserted, dict) else inserted[0]
        else:
            cursor = connection.execute(
                """
                INSERT INTO audit_findings (
                    audit_id,
                    audit_item_id,
                    technician_id,
                    supervisor_name,
                    owner_user_id,
                    item_status,
                    priority
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                finding_row,
            )
            finding_id = cursor.lastrowid

        create_finding_event(
            finding_id,
            actor_user_id=None,
            event_type="creacion",
            detail="Hallazgo creado automáticamente desde la auditoría.",
            connection=connection,
        )
        if owner_username:
            create_finding_event(
                finding_id,
                actor_user_id=None,
                event_type="asignacion",
                detail=f"Asignado a {owner_username}.",
                connection=connection,
            )
        inserted_count += 1

    return inserted_count


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
            technician_company_snapshot,
            technician_supervisor_snapshot,
            technician_center_snapshot,
            location,
            address,
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
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
        audit_data.get("technician_company_snapshot"),
        audit_data.get("technician_supervisor_snapshot"),
        audit_data.get("technician_center_snapshot"),
        audit_data["location"],
        audit_data.get("address"),
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

    inserted_items = []
    for item in items:
        item_params = (
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
        if is_postgres():
            item_cursor = connection.execute(
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
                RETURNING id
                """,
                item_params,
            )
            item_row = item_cursor.fetchone()
            item_id = (item_row["id"] if isinstance(item_row, dict) else item_row[0]) if item_row else None
        else:
            item_cursor = connection.execute(
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
                item_params,
            )
            item_id = item_cursor.lastrowid
        inserted_items.append({**item, "id": item_id})
    create_audit_findings(audit_id, audit_data, inserted_items, connection=connection)

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


def append_qc_visibility_filters(where_clauses, params, include_pruebas=False, table_alias="qc_sessions"):
    if not _normalize_bool(include_pruebas):
        where_clauses.append(f"COALESCE({table_alias}.record_scope, ?) = ?")
        params.extend([AUDIT_SCOPE_OFFICIAL, AUDIT_SCOPE_OFFICIAL])

        official_from_date = get_audit_official_from_date()
        if official_from_date:
            where_clauses.append(f"{table_alias}.qc_date >= ?")
            params.append(official_from_date)


def build_qc_sessions_where_sql(filters=None, auditor_user_id=None, supervisor_scope_names=None):
    filters = filters or {}
    where_clauses = []
    params = []

    append_qc_visibility_filters(where_clauses, params, include_pruebas=filters.get("include_pruebas"), table_alias="qc_sessions")
    append_supervisor_scope_filters(where_clauses, params, supervisor_scope_names=supervisor_scope_names, audit_table_alias="qc_sessions")

    if auditor_user_id is not None:
        where_clauses.append("qc_sessions.auditor_user_id = ?")
        params.append(auditor_user_id)

    from_date = (filters.get("from_date") or "").strip()
    to_date = (filters.get("to_date") or "").strip()
    status = (filters.get("status") or "").strip()
    technician_id = filters.get("technician_id")
    q = (filters.get("q") or "").strip()

    if from_date:
        where_clauses.append("qc_sessions.qc_date >= ?")
        params.append(from_date)
    if to_date:
        where_clauses.append("qc_sessions.qc_date <= ?")
        params.append(to_date)
    if status:
        where_clauses.append("qc_sessions.result_status = ?")
        params.append(status)
    if technician_id:
        where_clauses.append("qc_sessions.technician_id = ?")
        params.append(technician_id)

    if q:
        like_value = f"%{q}%"
        if is_postgres():
            where_clauses.append(
                "("
                "CAST(qc_sessions.id AS TEXT) ILIKE ? OR "
                "COALESCE(qc_sessions.sa_number, '') ILIKE ? OR "
                "COALESCE(technicians.name, qc_sessions.technician_display_name, '') ILIKE ? OR "
                "COALESCE(qc_sessions.location, '') ILIKE ?"
                ")"
            )
            params.extend([like_value] * 4)
        else:
            where_clauses.append(
                "("
                "CAST(qc_sessions.id AS TEXT) LIKE ? OR "
                "LOWER(COALESCE(qc_sessions.sa_number, '')) LIKE ? OR "
                "LOWER(COALESCE(technicians.name, qc_sessions.technician_display_name, '')) LIKE ? OR "
                "LOWER(COALESCE(qc_sessions.location, '')) LIKE ?"
                ")"
            )
            lowered = like_value.lower()
            params.extend([lowered] * 4)

    where_sql = ""
    if where_clauses:
        where_sql = "WHERE " + " AND ".join(where_clauses)
    return where_sql, tuple(params)


def fetch_qc_sessions(filters=None, auditor_user_id=None, supervisor_scope_names=None, limit=300):
    where_sql, params = build_qc_sessions_where_sql(
        filters,
        auditor_user_id=auditor_user_id,
        supervisor_scope_names=supervisor_scope_names,
    )
    filters = filters or {}
    sort_key = (filters.get("sort") or "").strip()
    sort_dir = (filters.get("dir") or "").strip().lower()
    if sort_dir not in {"asc", "desc"}:
        sort_dir = "desc"

    sa_number_sort_expr = "COALESCE(qc_sessions.sa_number, '')"
    if is_postgres():
        sa_number_sort_expr = (
            "CASE "
            "WHEN qc_sessions.sa_number ~ '^[0-9]+$' THEN qc_sessions.sa_number::BIGINT "
            "ELSE NULL "
            "END"
        )
    else:
        sa_number_sort_expr = (
            "CASE "
            "WHEN qc_sessions.sa_number IS NOT NULL "
            "AND qc_sessions.sa_number != '' "
            "AND qc_sessions.sa_number NOT GLOB '*[^0-9]*' "
            "THEN CAST(qc_sessions.sa_number AS INTEGER) "
            "ELSE NULL "
            "END"
        )

    sort_columns = {
        "qc_date": "qc_sessions.qc_date",
        "auditor_name": "COALESCE(qc_sessions.auditor_name, '')",
        "sa_number": sa_number_sort_expr,
        "technician_name": "COALESCE(technicians.name, qc_sessions.technician_display_name, '')",
        "location": "COALESCE(qc_sessions.location, '')",
        "result_status": "qc_sessions.result_status",
        "total_score": "qc_sessions.total_score",
    }
    sort_expr = sort_columns.get(sort_key)
    if sort_expr:
        order_sql = f"ORDER BY {sort_expr} {sort_dir.upper()}, qc_sessions.created_at DESC"
    else:
        order_sql = "ORDER BY qc_sessions.created_at DESC"
    created_at_expr = "qc_sessions.created_at"
    rows = get_db().execute(
        f"""
        SELECT
            qc_sessions.id,
            qc_sessions.qc_date,
            qc_sessions.auditor_name,
            qc_sessions.auditor_user_id,
            qc_sessions.sa_number,
            qc_sessions.location,
            qc_sessions.installation_type,
            qc_sessions.total_score,
            qc_sessions.result_status,
            qc_sessions.record_scope,
            qc_sessions.audit_id,
            {created_at_expr} AS created_at,
            COALESCE(technicians.name, qc_sessions.technician_display_name) AS technician_name,
            COALESCE(technicians.employee_code, qc_sessions.technician_employee_code) AS technician_employee_code
        FROM qc_sessions
        LEFT JOIN technicians ON technicians.id = qc_sessions.technician_id
        {where_sql}
        {order_sql}
        LIMIT ?
        """,
        tuple(list(params) + [limit]),
    ).fetchall()
    return [dict(row) for row in rows]


def fetch_qc_sessions_for_audit(audit_id, auditor_user_id=None, supervisor_scope_names=None, limit=50):
    where_clauses = ["qc_sessions.audit_id = ?"]
    params = [audit_id]

    append_supervisor_scope_filters(
        where_clauses,
        params,
        supervisor_scope_names=supervisor_scope_names,
        audit_table_alias="qc_sessions",
    )

    if auditor_user_id is not None:
        where_clauses.append("qc_sessions.auditor_user_id = ?")
        params.append(auditor_user_id)

    where_sql = " WHERE " + " AND ".join(where_clauses)
    created_at_expr = "qc_sessions.created_at"
    rows = get_db().execute(
        f"""
        SELECT
            qc_sessions.id,
            qc_sessions.qc_date,
            qc_sessions.total_score,
            qc_sessions.result_status,
            qc_sessions.audit_id,
            {created_at_expr} AS created_at
        FROM qc_sessions
        {where_sql}
        ORDER BY qc_sessions.created_at DESC
        LIMIT ?
        """,
        tuple(list(params) + [limit]),
    ).fetchall()
    return [dict(row) for row in rows]


def fetch_qc_session_detail(qc_session_id, supervisor_scope_names=None):
    created_at_expr = "qc_sessions.created_at"
    where_clauses = ["qc_sessions.id = ?"]
    params = [qc_session_id]
    append_supervisor_scope_filters(where_clauses, params, supervisor_scope_names=supervisor_scope_names, audit_table_alias="qc_sessions")
    row = get_db().execute(
        f"""
        SELECT
            qc_sessions.id,
            qc_sessions.qc_date,
            qc_sessions.auditor_name,
            qc_sessions.auditor_user_id,
            qc_sessions.sa_number,
            qc_sessions.technician_display_name,
            qc_sessions.technician_employee_code,
            qc_sessions.technician_company_snapshot,
            qc_sessions.technician_supervisor_snapshot,
            qc_sessions.technician_center_snapshot,
            qc_sessions.technician_id,
            qc_sessions.audit_id,
            qc_sessions.location,
            qc_sessions.address,
            qc_sessions.installation_type,
            qc_sessions.total_score,
            qc_sessions.result_status,
            qc_sessions.record_scope,
            qc_sessions.general_notes,
            qc_sessions.photo_path,
            qc_sessions.qc_live_installation,
            qc_sessions.installation_duration_minutes,
            qc_sessions.cable_type,
            qc_sessions.cable_meters,
            {created_at_expr} AS created_at,
            COALESCE(technicians.name, qc_sessions.technician_display_name) AS technician_name,
            COALESCE(technicians.employee_code, qc_sessions.technician_employee_code) AS employee_code,
            COALESCE(qc_sessions.technician_company_snapshot, technicians.company_name) AS technician_company,
            COALESCE(qc_sessions.technician_supervisor_snapshot, technicians.supervisor_name) AS technician_supervisor,
            COALESCE(qc_sessions.technician_center_snapshot, technicians.center_name) AS technician_center
        FROM qc_sessions
        LEFT JOIN technicians ON technicians.id = qc_sessions.technician_id
        WHERE {' AND '.join(where_clauses)}
        """,
        tuple(params),
    ).fetchone()
    return dict(row) if row else None


def fetch_qc_items(qc_session_id):
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
        FROM qc_items
        WHERE qc_session_id = ?
        ORDER BY id ASC
        """,
        (qc_session_id,),
    ).fetchall()
    return [dict(row) for row in rows]


def create_qc_session(qc_data, items):
    connection = get_db()
    insert_sql = """
        INSERT INTO qc_sessions (
            qc_date,
            auditor_name,
            auditor_user_id,
            sa_number,
            technician_display_name,
            technician_employee_code,
            technician_company_snapshot,
            technician_supervisor_snapshot,
            technician_center_snapshot,
            technician_id,
            audit_id,
            location,
            address,
            installation_type,
            total_score,
            result_status,
            record_scope,
            general_notes,
            photo_path,
            qc_live_installation,
            installation_duration_minutes,
            cable_type,
            cable_meters
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """
    insert_params = (
        qc_data["qc_date"],
        qc_data["auditor_name"],
        qc_data.get("auditor_user_id"),
        qc_data.get("sa_number"),
        qc_data.get("technician_display_name"),
        qc_data.get("technician_employee_code"),
        qc_data.get("technician_company_snapshot"),
        qc_data.get("technician_supervisor_snapshot"),
        qc_data.get("technician_center_snapshot"),
        qc_data["technician_id"],
        qc_data.get("audit_id"),
        qc_data["location"],
        qc_data.get("address"),
        qc_data["installation_type"],
        qc_data["total_score"],
        qc_data["result_status"],
        normalize_audit_record_scope(qc_data.get("record_scope")),
        qc_data.get("general_notes"),
        qc_data.get("photo_path"),
        1 if qc_data.get("qc_live_installation") else 0,
        qc_data.get("installation_duration_minutes"),
        qc_data.get("cable_type"),
        qc_data.get("cable_meters"),
    )

    if is_postgres():
        cursor = connection.execute(insert_sql + " RETURNING id", insert_params)
        new_id_row = cursor.fetchone()
        qc_session_id = (new_id_row["id"] if isinstance(new_id_row, dict) else new_id_row[0]) if new_id_row else None
    else:
        cursor = connection.execute(insert_sql, insert_params)
        qc_session_id = cursor.lastrowid

    for item in items:
        item_params = (
            qc_session_id,
            item["section_key"],
            item["section_title"],
            item["item_key"],
            item["item_label"],
            item["status"],
            1 if item.get("is_critical") else 0,
            item.get("non_compliance_reason"),
            item.get("notes"),
            item.get("photo_path"),
        )
        if is_postgres():
            connection.execute(
                """
                INSERT INTO qc_items (
                    qc_session_id,
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
                item_params,
            )
        else:
            connection.execute(
                """
                INSERT INTO qc_items (
                    qc_session_id,
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
                item_params,
            )
    connection.commit()
    return qc_session_id


def append_service_visibility_filters(where_clauses, params, include_pruebas=False, table_alias="service_sessions"):
    if not _normalize_bool(include_pruebas):
        where_clauses.append(f"COALESCE({table_alias}.record_scope, ?) = ?")
        params.extend([AUDIT_SCOPE_OFFICIAL, AUDIT_SCOPE_OFFICIAL])

        official_from_date = get_audit_official_from_date()
        if official_from_date:
            where_clauses.append(f"{table_alias}.service_date >= ?")
            params.append(official_from_date)


def build_service_sessions_where_sql(filters=None, auditor_user_id=None, supervisor_scope_names=None):
    filters = filters or {}
    where_clauses = []
    params = []

    append_service_visibility_filters(
        where_clauses,
        params,
        include_pruebas=filters.get("include_pruebas"),
        table_alias="service_sessions",
    )
    append_supervisor_scope_filters(
        where_clauses,
        params,
        supervisor_scope_names=supervisor_scope_names,
        audit_table_alias="service_sessions",
    )

    if auditor_user_id is not None:
        where_clauses.append("service_sessions.auditor_user_id = ?")
        params.append(auditor_user_id)

    from_date = (filters.get("from_date") or "").strip()
    to_date = (filters.get("to_date") or "").strip()
    status = (filters.get("status") or "").strip()
    technician_id = filters.get("technician_id")
    q = (filters.get("q") or "").strip()

    if from_date:
        where_clauses.append("service_sessions.service_date >= ?")
        params.append(from_date)
    if to_date:
        where_clauses.append("service_sessions.service_date <= ?")
        params.append(to_date)
    if status:
        where_clauses.append("service_sessions.result_status = ?")
        params.append(status)
    if technician_id:
        where_clauses.append("service_sessions.technician_id = ?")
        params.append(technician_id)

    if q:
        like_value = f"%{q}%"
        if is_postgres():
            where_clauses.append(
                "("
                "CAST(service_sessions.id AS TEXT) ILIKE ? OR "
                "COALESCE(service_sessions.sa_number, '') ILIKE ? OR "
                "COALESCE(technicians.name, service_sessions.technician_display_name, '') ILIKE ? OR "
                "COALESCE(service_sessions.location, '') ILIKE ?"
                ")"
            )
            params.extend([like_value] * 4)
        else:
            where_clauses.append(
                "("
                "CAST(service_sessions.id AS TEXT) LIKE ? OR "
                "LOWER(COALESCE(service_sessions.sa_number, '')) LIKE ? OR "
                "LOWER(COALESCE(technicians.name, service_sessions.technician_display_name, '')) LIKE ? OR "
                "LOWER(COALESCE(service_sessions.location, '')) LIKE ?"
                ")"
            )
            lowered = like_value.lower()
            params.extend([lowered] * 4)

    where_sql = ""
    if where_clauses:
        where_sql = "WHERE " + " AND ".join(where_clauses)
    return where_sql, tuple(params)


def fetch_service_sessions(filters=None, auditor_user_id=None, supervisor_scope_names=None, limit=300):
    where_sql, params = build_service_sessions_where_sql(
        filters,
        auditor_user_id=auditor_user_id,
        supervisor_scope_names=supervisor_scope_names,
    )
    filters = filters or {}
    sort_key = (filters.get("sort") or "").strip()
    sort_dir = (filters.get("dir") or "").strip().lower()
    if sort_dir not in {"asc", "desc"}:
        sort_dir = "desc"

    sa_number_sort_expr = "COALESCE(service_sessions.sa_number, '')"
    if is_postgres():
        sa_number_sort_expr = (
            "CASE "
            "WHEN service_sessions.sa_number ~ '^[0-9]+$' THEN service_sessions.sa_number::BIGINT "
            "ELSE NULL "
            "END"
        )
    else:
        sa_number_sort_expr = (
            "CASE "
            "WHEN service_sessions.sa_number IS NOT NULL "
            "AND service_sessions.sa_number != '' "
            "AND service_sessions.sa_number NOT GLOB '*[^0-9]*' "
            "THEN CAST(service_sessions.sa_number AS INTEGER) "
            "ELSE NULL "
            "END"
        )

    sort_columns = {
        "service_date": "service_sessions.service_date",
        "auditor_name": "COALESCE(service_sessions.auditor_name, '')",
        "sa_number": sa_number_sort_expr,
        "technician_name": "COALESCE(technicians.name, service_sessions.technician_display_name, '')",
        "location": "COALESCE(service_sessions.location, '')",
        "result_status": "service_sessions.result_status",
        "total_score": "service_sessions.total_score",
        "optical_delta_dbm": "service_sessions.optical_delta_dbm",
    }
    sort_expr = sort_columns.get(sort_key)
    if sort_expr:
        order_sql = f"ORDER BY {sort_expr} {sort_dir.upper()}, service_sessions.created_at DESC"
    else:
        order_sql = "ORDER BY service_sessions.created_at DESC"

    created_at_expr = "service_sessions.created_at"
    rows = get_db().execute(
        f"""
        SELECT
            service_sessions.id,
            service_sessions.service_date,
            service_sessions.auditor_name,
            service_sessions.auditor_user_id,
            service_sessions.sa_number,
            service_sessions.location,
            service_sessions.total_score,
            service_sessions.result_status,
            service_sessions.record_scope,
            service_sessions.optical_delta_dbm,
            {created_at_expr} AS created_at,
            COALESCE(technicians.name, service_sessions.technician_display_name) AS technician_name,
            COALESCE(technicians.employee_code, service_sessions.technician_employee_code) AS technician_employee_code
        FROM service_sessions
        LEFT JOIN technicians ON technicians.id = service_sessions.technician_id
        {where_sql}
        {order_sql}
        LIMIT ?
        """,
        tuple(list(params) + [limit]),
    ).fetchall()
    return [dict(row) for row in rows]


def fetch_service_session_detail(service_session_id, supervisor_scope_names=None):
    created_at_expr = "service_sessions.created_at"
    where_clauses = ["service_sessions.id = ?"]
    params = [service_session_id]
    append_supervisor_scope_filters(
        where_clauses,
        params,
        supervisor_scope_names=supervisor_scope_names,
        audit_table_alias="service_sessions",
    )
    row = get_db().execute(
        f"""
        SELECT
            service_sessions.id,
            service_sessions.service_date,
            service_sessions.auditor_name,
            service_sessions.auditor_user_id,
            service_sessions.sa_number,
            service_sessions.technician_display_name,
            service_sessions.technician_employee_code,
            service_sessions.technician_company_snapshot,
            service_sessions.technician_supervisor_snapshot,
            service_sessions.technician_center_snapshot,
            service_sessions.technician_id,
            service_sessions.location,
            service_sessions.address,
            service_sessions.optical_expected_dbm,
            service_sessions.optical_measured_dbm,
            service_sessions.optical_delta_dbm,
            service_sessions.total_score,
            service_sessions.result_status,
            service_sessions.record_scope,
            service_sessions.general_notes,
            service_sessions.photo_path,
            {created_at_expr} AS created_at,
            COALESCE(technicians.name, service_sessions.technician_display_name) AS technician_name,
            COALESCE(technicians.employee_code, service_sessions.technician_employee_code) AS employee_code,
            COALESCE(service_sessions.technician_company_snapshot, technicians.company_name) AS technician_company,
            COALESCE(service_sessions.technician_supervisor_snapshot, technicians.supervisor_name) AS technician_supervisor,
            COALESCE(service_sessions.technician_center_snapshot, technicians.center_name) AS technician_center
        FROM service_sessions
        LEFT JOIN technicians ON technicians.id = service_sessions.technician_id
        WHERE {' AND '.join(where_clauses)}
        """,
        tuple(params),
    ).fetchone()
    return dict(row) if row else None


def fetch_service_items(service_session_id):
    rows = get_db().execute(
        """
        SELECT
            id,
            item_key,
            item_label,
            status,
            is_critical,
            notes,
            photo_path
        FROM service_items
        WHERE service_session_id = ?
        ORDER BY id ASC
        """,
        (service_session_id,),
    ).fetchall()
    return [dict(row) for row in rows]


def fetch_service_speedtests(service_session_id):
    rows = get_db().execute(
        """
        SELECT
            id,
            space_key,
            space_label,
            download_mbps,
            upload_mbps,
            ping_ms
        FROM service_speedtests
        WHERE service_session_id = ?
        ORDER BY id ASC
        """,
        (service_session_id,),
    ).fetchall()
    return [dict(row) for row in rows]


def create_service_session(service_data, items, speedtests):
    connection = get_db()
    insert_sql = """
        INSERT INTO service_sessions (
            service_date,
            auditor_name,
            auditor_user_id,
            sa_number,
            technician_display_name,
            technician_employee_code,
            technician_company_snapshot,
            technician_supervisor_snapshot,
            technician_center_snapshot,
            technician_id,
            location,
            address,
            optical_expected_dbm,
            optical_measured_dbm,
            optical_delta_dbm,
            total_score,
            result_status,
            record_scope,
            general_notes,
            photo_path
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """
    insert_params = (
        service_data["service_date"],
        service_data["auditor_name"],
        service_data.get("auditor_user_id"),
        service_data.get("sa_number"),
        service_data.get("technician_display_name"),
        service_data.get("technician_employee_code"),
        service_data.get("technician_company_snapshot"),
        service_data.get("technician_supervisor_snapshot"),
        service_data.get("technician_center_snapshot"),
        service_data["technician_id"],
        service_data["location"],
        service_data.get("address"),
        service_data.get("optical_expected_dbm"),
        service_data.get("optical_measured_dbm"),
        service_data.get("optical_delta_dbm"),
        service_data["total_score"],
        service_data["result_status"],
        normalize_audit_record_scope(service_data.get("record_scope")),
        service_data.get("general_notes"),
        service_data.get("photo_path"),
    )

    if is_postgres():
        cursor = connection.execute(insert_sql + " RETURNING id", insert_params)
        new_id_row = cursor.fetchone()
        service_session_id = (new_id_row["id"] if isinstance(new_id_row, dict) else new_id_row[0]) if new_id_row else None
    else:
        cursor = connection.execute(insert_sql, insert_params)
        service_session_id = cursor.lastrowid

    for item in items:
        item_params = (
            service_session_id,
            item["item_key"],
            item["item_label"],
            item["status"],
            1 if item.get("is_critical") else 0,
            item.get("notes"),
            item.get("photo_path"),
        )
        connection.execute(
            """
            INSERT INTO service_items (
                service_session_id,
                item_key,
                item_label,
                status,
                is_critical,
                notes,
                photo_path
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            item_params,
        )

    for entry in speedtests:
        speedtest_params = (
            service_session_id,
            entry.get("space_key") or "",
            entry.get("space_label") or "",
            entry.get("download_mbps"),
            entry.get("upload_mbps"),
            entry.get("ping_ms"),
        )
        connection.execute(
            """
            INSERT INTO service_speedtests (
                service_session_id,
                space_key,
                space_label,
                download_mbps,
                upload_mbps,
                ping_ms
            ) VALUES (?, ?, ?, ?, ?, ?)
            """,
            speedtest_params,
        )

    connection.commit()
    return service_session_id


def fetch_qc_reports_management_summary(filters=None, auditor_user_id=None, supervisor_scope_names=None):
    where_sql, params = build_qc_sessions_where_sql(
        filters,
        auditor_user_id=auditor_user_id,
        supervisor_scope_names=supervisor_scope_names,
    )
    row = get_db().execute(
        f"""
        SELECT
            COUNT(*) AS total_qc,
            SUM(CASE WHEN qc_sessions.result_status IN ('Aprobada', 'Aprobada con observaciones') THEN 1 ELSE 0 END) AS approved_count,
            SUM(CASE WHEN qc_sessions.result_status = 'Rechazada' THEN 1 ELSE 0 END) AS rejected_count,
            AVG(qc_sessions.total_score) AS average_score
        FROM qc_sessions
        LEFT JOIN technicians ON technicians.id = qc_sessions.technician_id
        {where_sql}
        """,
        params,
    ).fetchone()

    total_qc = row["total_qc"] or 0
    approved_count = row["approved_count"] or 0
    rejected_count = row["rejected_count"] or 0
    average_score = 0 if total_qc == 0 else round((row["average_score"] or 0), 2)
    approval_rate = 0 if total_qc == 0 else round((approved_count / total_qc) * 100)

    return {
        "total_qc": total_qc,
        "approved_count": approved_count,
        "rejected_count": rejected_count,
        "approval_rate": approval_rate,
        "average_score": average_score,
    }


def fetch_qc_reports_status_breakdown(filters=None, auditor_user_id=None, supervisor_scope_names=None):
    where_sql, params = build_qc_sessions_where_sql(
        filters,
        auditor_user_id=auditor_user_id,
        supervisor_scope_names=supervisor_scope_names,
    )
    rows = get_db().execute(
        f"""
        SELECT
            qc_sessions.result_status,
            COUNT(*) AS qc_count,
            AVG(qc_sessions.total_score) AS average_score
        FROM qc_sessions
        LEFT JOIN technicians ON technicians.id = qc_sessions.technician_id
        {where_sql}
        GROUP BY qc_sessions.result_status
        ORDER BY qc_count DESC, qc_sessions.result_status ASC
        """,
        params,
    ).fetchall()

    breakdown = []
    for row in rows:
        breakdown.append(
            {
                "result_status": row["result_status"],
                "qc_count": row["qc_count"] or 0,
                "average_score": round((row["average_score"] or 0), 2),
            }
        )
    return breakdown


def fetch_qc_reports_time_series(filters=None, auditor_user_id=None, supervisor_scope_names=None, limit=120):
    where_sql, params = build_qc_sessions_where_sql(
        filters,
        auditor_user_id=auditor_user_id,
        supervisor_scope_names=supervisor_scope_names,
    )
    period_expr = "SUBSTRING(qc_sessions.qc_date FROM 1 FOR 7)" if is_postgres() else "substr(qc_sessions.qc_date, 1, 7)"
    rows = get_db().execute(
        f"""
        SELECT
            {period_expr} AS period,
            COUNT(*) AS qc_count,
            AVG(qc_sessions.total_score) AS average_score,
            SUM(CASE WHEN qc_sessions.result_status = 'Rechazada' THEN 1 ELSE 0 END) AS rejected_count
        FROM qc_sessions
        LEFT JOIN technicians ON technicians.id = qc_sessions.technician_id
        {where_sql}
        GROUP BY period
        ORDER BY period ASC
        LIMIT ?
        """,
        tuple(list(params) + [limit]),
    ).fetchall()

    series = []
    for row in rows:
        series.append(
            {
                "period": row["period"] or "-",
                "qc_count": row["qc_count"] or 0,
                "average_score": round((row["average_score"] or 0), 2),
                "rejected_count": row["rejected_count"] or 0,
            }
        )
    return series


def fetch_qc_reports_technician_ranking(filters=None, auditor_user_id=None, supervisor_scope_names=None, min_qc=3, limit=200):
    where_sql, params = build_qc_sessions_where_sql(
        filters,
        auditor_user_id=auditor_user_id,
        supervisor_scope_names=supervisor_scope_names,
    )
    rows = get_db().execute(
        f"""
        SELECT
            qc_sessions.technician_id,
            COALESCE(technicians.name, qc_sessions.technician_display_name) AS technician_name,
            COALESCE(technicians.employee_code, qc_sessions.technician_employee_code) AS technician_employee_code,
            COUNT(*) AS total_qc,
            AVG(qc_sessions.total_score) AS average_score,
            SUM(CASE WHEN qc_sessions.result_status = 'Rechazada' THEN 1 ELSE 0 END) AS rejected_count,
            MAX(qc_sessions.qc_date) AS last_qc_date
        FROM qc_sessions
        LEFT JOIN technicians ON technicians.id = qc_sessions.technician_id
        {where_sql}
        GROUP BY qc_sessions.technician_id, technician_name, technician_employee_code
        HAVING COUNT(*) >= ?
        ORDER BY average_score DESC, total_qc DESC, technician_name ASC
        LIMIT ?
        """,
        tuple(list(params) + [int(min_qc), int(limit)]),
    ).fetchall()

    ranking = []
    for row in rows:
        ranking.append(
            {
                "technician_id": row["technician_id"],
                "technician_name": row["technician_name"] or "-",
                "technician_employee_code": row["technician_employee_code"] or "-",
                "total_qc": row["total_qc"] or 0,
                "average_score": round((row["average_score"] or 0), 2),
                "rejected_count": row["rejected_count"] or 0,
                "last_qc_date": row["last_qc_date"] or "-",
            }
        )
    return ranking


def fetch_qc_reports_technician_ranking_by_nc_major(filters=None, auditor_user_id=None, supervisor_scope_names=None, min_qc=3, limit=200):
    where_sql, params = build_qc_sessions_where_sql(
        filters,
        auditor_user_id=auditor_user_id,
        supervisor_scope_names=supervisor_scope_names,
    )
    rows = get_db().execute(
        f"""
        SELECT
            qc_sessions.technician_id,
            COALESCE(technicians.name, qc_sessions.technician_display_name) AS technician_name,
            COALESCE(technicians.employee_code, qc_sessions.technician_employee_code) AS technician_employee_code,
            COUNT(DISTINCT qc_sessions.id) AS total_qc,
            SUM(CASE WHEN qc_items.status = 'nc_mayor' THEN 1 ELSE 0 END) AS nc_mayor_count,
            SUM(CASE WHEN qc_items.status = 'nc_menor' THEN 1 ELSE 0 END) AS nc_menor_count,
            SUM(CASE WHEN qc_items.status IN ('conforme', 'nc_menor', 'nc_mayor') THEN 1 ELSE 0 END) AS evaluated_items_count,
            AVG(qc_sessions.total_score) AS average_score,
            MAX(qc_sessions.qc_date) AS last_qc_date
        FROM qc_sessions
        LEFT JOIN technicians ON technicians.id = qc_sessions.technician_id
        LEFT JOIN qc_items ON qc_items.qc_session_id = qc_sessions.id
        {where_sql}
        GROUP BY qc_sessions.technician_id, technician_name, technician_employee_code
        HAVING COUNT(DISTINCT qc_sessions.id) >= ?
        ORDER BY nc_mayor_count DESC, nc_menor_count DESC, average_score ASC, total_qc DESC, technician_name ASC
        LIMIT ?
        """,
        tuple(list(params) + [int(min_qc), int(limit)]),
    ).fetchall()

    ranking = []
    for row in rows:
        evaluated = row["evaluated_items_count"] or 0
        nc_mayor = row["nc_mayor_count"] or 0
        nc_menor = row["nc_menor_count"] or 0
        ranking.append(
            {
                "technician_id": row["technician_id"],
                "technician_name": row["technician_name"] or "-",
                "technician_employee_code": row["technician_employee_code"] or "-",
                "total_qc": row["total_qc"] or 0,
                "average_score": round((row["average_score"] or 0), 2),
                "nc_mayor_count": nc_mayor,
                "nc_menor_count": nc_menor,
                "evaluated_items_count": evaluated,
                "nc_mayor_rate": 0 if evaluated == 0 else round((nc_mayor / evaluated) * 100, 1),
                "last_qc_date": row["last_qc_date"] or "-",
            }
        )
    return ranking


def fetch_qc_technician_extra_summary(filters=None, auditor_user_id=None, supervisor_scope_names=None):
    where_sql, params = build_qc_sessions_where_sql(
        filters,
        auditor_user_id=auditor_user_id,
        supervisor_scope_names=supervisor_scope_names,
    )
    row = get_db().execute(
        f"""
        SELECT
            SUM(CASE WHEN qc_sessions.audit_id IS NOT NULL THEN 1 ELSE 0 END) AS linked_audit_count,
            SUM(CASE WHEN qc_sessions.qc_live_installation = 1 THEN 1 ELSE 0 END) AS live_qc_count,
            AVG(CASE WHEN qc_sessions.qc_live_installation = 1 THEN qc_sessions.installation_duration_minutes ELSE NULL END) AS avg_install_minutes,
            AVG(CASE WHEN qc_sessions.qc_live_installation = 1 THEN qc_sessions.cable_meters ELSE NULL END) AS avg_cable_meters
        FROM qc_sessions
        LEFT JOIN technicians ON technicians.id = qc_sessions.technician_id
        {where_sql}
        """,
        params,
    ).fetchone()

    linked_audit_count = row["linked_audit_count"] or 0
    live_qc_count = row["live_qc_count"] or 0
    avg_install_minutes = None if live_qc_count == 0 else round((row["avg_install_minutes"] or 0), 1)
    avg_cable_meters = None if live_qc_count == 0 else round((row["avg_cable_meters"] or 0), 1)

    return {
        "linked_audit_count": linked_audit_count,
        "live_qc_count": live_qc_count,
        "avg_install_minutes": avg_install_minutes,
        "avg_cable_meters": avg_cable_meters,
    }


def fetch_qc_technician_nc_summary(filters=None, auditor_user_id=None, supervisor_scope_names=None):
    where_sql, params = build_qc_sessions_where_sql(
        filters,
        auditor_user_id=auditor_user_id,
        supervisor_scope_names=supervisor_scope_names,
    )
    row = get_db().execute(
        f"""
        SELECT
            SUM(CASE WHEN qc_items.status = 'nc_menor' THEN 1 ELSE 0 END) AS nc_menor_count,
            SUM(CASE WHEN qc_items.status = 'nc_mayor' THEN 1 ELSE 0 END) AS nc_mayor_count,
            SUM(CASE WHEN qc_items.status IN ('conforme', 'nc_menor', 'nc_mayor') THEN 1 ELSE 0 END) AS evaluated_items_count
        FROM qc_items
        JOIN qc_sessions ON qc_sessions.id = qc_items.qc_session_id
        LEFT JOIN technicians ON technicians.id = qc_sessions.technician_id
        {where_sql}
        """,
        params,
    ).fetchone()

    evaluated_items_count = row["evaluated_items_count"] or 0
    nc_menor_count = row["nc_menor_count"] or 0
    nc_mayor_count = row["nc_mayor_count"] or 0

    return {
        "evaluated_items_count": evaluated_items_count,
        "nc_menor_count": nc_menor_count,
        "nc_mayor_count": nc_mayor_count,
    }


def fetch_qc_technician_nc_breakdown(filters=None, auditor_user_id=None, supervisor_scope_names=None, limit=60):
    where_sql, params = build_qc_sessions_where_sql(
        filters,
        auditor_user_id=auditor_user_id,
        supervisor_scope_names=supervisor_scope_names,
    )
    rows = get_db().execute(
        f"""
        SELECT
            qc_items.item_key,
            qc_items.item_label,
            SUM(CASE WHEN qc_items.status = 'nc_menor' THEN 1 ELSE 0 END) AS nc_menor_count,
            SUM(CASE WHEN qc_items.status = 'nc_mayor' THEN 1 ELSE 0 END) AS nc_mayor_count,
            SUM(CASE WHEN qc_items.status IN ('conforme', 'nc_menor', 'nc_mayor') THEN 1 ELSE 0 END) AS evaluated_count
        FROM qc_items
        JOIN qc_sessions ON qc_sessions.id = qc_items.qc_session_id
        LEFT JOIN technicians ON technicians.id = qc_sessions.technician_id
        {where_sql}
        GROUP BY qc_items.item_key, qc_items.item_label
        ORDER BY nc_mayor_count DESC, nc_menor_count DESC, evaluated_count DESC, qc_items.item_label ASC
        LIMIT ?
        """,
        tuple(list(params) + [int(limit)]),
    ).fetchall()

    breakdown = []
    for row in rows:
        evaluated = row["evaluated_count"] or 0
        nc_menor = row["nc_menor_count"] or 0
        nc_mayor = row["nc_mayor_count"] or 0
        total_nc = nc_menor + nc_mayor
        breakdown.append(
            {
                "item_key": row["item_key"] or "-",
                "item_label": row["item_label"] or "-",
                "evaluated_count": evaluated,
                "nc_menor_count": nc_menor,
                "nc_mayor_count": nc_mayor,
                "nc_total_count": total_nc,
                "nc_mayor_rate": 0 if evaluated == 0 else round((nc_mayor / evaluated) * 100, 1),
                "nc_total_rate": 0 if evaluated == 0 else round((total_nc / evaluated) * 100, 1),
            }
        )
    return breakdown


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


def import_material_stock(rows, *, import_batch_id=None):
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

    if import_batch_id and mobile_id_map:
        mobile_ids = list(mobile_id_map.values())
        placeholders = ", ".join(["?"] * len(mobile_ids))
        previous_rows = connection.execute(
            f"""
            SELECT material_id, mobile_unit_id, quantity
            FROM material_stock
            WHERE mobile_unit_id IN ({placeholders})
            """,
            mobile_ids,
        ).fetchall()
        if previous_rows:
            connection.executemany(
                """
                INSERT INTO material_stock_import_backups (batch_id, mobile_unit_id, material_id, quantity)
                VALUES (?, ?, ?, ?)
                """,
                [
                    (
                        import_batch_id,
                        row["mobile_unit_id"],
                        row["material_id"],
                        row["quantity"],
                    )
                    for row in previous_rows
                ],
            )

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


def import_equipment_inventory(rows, *, import_batch_id=None):
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

    if import_batch_id and warehouse_codes:
        codes = sorted(warehouse_codes)
        placeholders = ", ".join(["?"] * len(codes))
        previous_rows = connection.execute(
            f"""
            SELECT
                storage_location_id,
                mobile_unit_id,
                center_name,
                warehouse_code,
                warehouse_name,
                material_code,
                material_name,
                serial_number
            FROM equipment_inventory
            WHERE warehouse_code IN ({placeholders})
            """,
            codes,
        ).fetchall()
        if previous_rows:
            connection.executemany(
                """
                INSERT INTO equipment_inventory_import_backups (
                    batch_id,
                    storage_location_id,
                    mobile_unit_id,
                    center_name,
                    warehouse_code,
                    warehouse_name,
                    material_code,
                    material_name,
                    serial_number
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                [
                    (
                        import_batch_id,
                        row["storage_location_id"],
                        row["mobile_unit_id"],
                        row["center_name"],
                        row["warehouse_code"],
                        row["warehouse_name"],
                        row["material_code"],
                        row["material_name"],
                        row["serial_number"],
                    )
                    for row in previous_rows
                ],
            )

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


def create_import_batch(
    import_type,
    import_label,
    *,
    filename=None,
    file_sha256=None,
    uploaded_by_user=None,
    row_count=0,
    can_rollback=0,
    scope=None,
):
    safe_type = (import_type or "").strip()
    safe_label = (import_label or "").strip()
    if not safe_type or not safe_label:
        raise ValueError("Tipo de importación inválido.")

    uploaded_by_user_id = None
    uploaded_by_username = None
    uploaded_by_role = None
    if uploaded_by_user:
        uploaded_by_user_id = uploaded_by_user.get("id")
        uploaded_by_username = uploaded_by_user.get("username")
        uploaded_by_role = uploaded_by_user.get("role")

    scope_json = json.dumps(scope or {}, ensure_ascii=False) if scope is not None else None

    connection = get_db()
    if is_postgres():
        row = connection.execute(
            """
            INSERT INTO import_batches (
                status,
                import_type,
                import_label,
                filename,
                file_sha256,
                uploaded_by_user_id,
                uploaded_by_username,
                uploaded_by_role,
                row_count,
                can_rollback,
                scope_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            RETURNING id
            """,
            (
                "running",
                safe_type,
                safe_label,
                filename,
                file_sha256,
                uploaded_by_user_id,
                uploaded_by_username,
                uploaded_by_role,
                int(row_count or 0),
                1 if can_rollback else 0,
                scope_json,
            ),
        ).fetchone()
        batch_id = row["id"] if isinstance(row, dict) else row[0]
    else:
        cursor = connection.execute(
            """
            INSERT INTO import_batches (
                status,
                import_type,
                import_label,
                filename,
                file_sha256,
                uploaded_by_user_id,
                uploaded_by_username,
                uploaded_by_role,
                row_count,
                can_rollback,
                scope_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                "running",
                safe_type,
                safe_label,
                filename,
                file_sha256,
                uploaded_by_user_id,
                uploaded_by_username,
                uploaded_by_role,
                int(row_count or 0),
                1 if can_rollback else 0,
                scope_json,
            ),
        )
        batch_id = cursor.lastrowid

    connection.commit()
    return batch_id


def finalize_import_batch(
    batch_id,
    *,
    status="completed",
    created_count=0,
    updated_count=0,
    skipped_rows=None,
    error_message=None,
):
    connection = get_db()
    skipped_json = None
    if skipped_rows is not None:
        skipped_json = json.dumps(list(skipped_rows or []), ensure_ascii=False)

    connection.execute(
        """
        UPDATE import_batches
        SET status = ?,
            created_count = ?,
            updated_count = ?,
            skipped_rows_json = COALESCE(?, skipped_rows_json),
            error_message = ?
        WHERE id = ?
        """,
        (
            (status or "completed").strip(),
            int(created_count or 0),
            int(updated_count or 0),
            skipped_json,
            (error_message or None),
            int(batch_id),
        ),
    )
    connection.commit()


def fetch_import_batches(limit=50):
    connection = get_db()
    rows = connection.execute(
        """
        SELECT *
        FROM import_batches
        ORDER BY id DESC
        LIMIT ?
        """,
        (int(limit or 50),),
    ).fetchall()
    return [dict(row) for row in rows]


def fetch_import_batch_by_id(batch_id):
    row = get_db().execute(
        "SELECT * FROM import_batches WHERE id = ?",
        (int(batch_id),),
    ).fetchone()
    return dict(row) if row else None


def rollback_import_batch(batch_id, actor_user_id):
    connection = get_db()
    batch = fetch_import_batch_by_id(batch_id)
    if not batch:
        raise ValueError("Importación no encontrada.")
    if not batch.get("can_rollback"):
        raise ValueError("Esta importación no admite reversión.")
    if batch.get("rolled_back_at"):
        raise ValueError("Esta importación ya fue revertida.")
    if (batch.get("status") or "").strip().lower() != "completed":
        raise ValueError("Solo se pueden revertir importaciones completadas.")

    scope = {}
    raw_scope = batch.get("scope_json")
    if raw_scope:
        try:
            parsed = json.loads(raw_scope)
            scope = parsed if isinstance(parsed, dict) else {}
        except Exception:
            scope = {}

    now_value = datetime.utcnow().replace(microsecond=0).isoformat()
    import_type = (batch.get("import_type") or "").strip()

    if import_type == "material_stock":
        mobile_unit_ids = scope.get("mobile_unit_ids") or []
        mobile_codes = scope.get("mobile_codes") or []
        if not mobile_unit_ids and mobile_codes:
            resolved_ids = []
            for raw_code in mobile_codes:
                normalized_code = normalize_mobile_code(raw_code)
                if not normalized_code:
                    continue
                row = connection.execute(
                    "SELECT id FROM mobile_units WHERE mobile_code = ?",
                    (normalized_code,),
                ).fetchone()
                if row:
                    resolved_ids.append(row["id"] if isinstance(row, dict) else row[0])
            mobile_unit_ids = resolved_ids
        if not mobile_unit_ids:
            rows = connection.execute(
                """
                SELECT DISTINCT mobile_unit_id
                FROM material_stock_import_backups
                WHERE batch_id = ?
                """,
                (int(batch_id),),
            ).fetchall()
            mobile_unit_ids = [row["mobile_unit_id"] for row in rows]

        if mobile_unit_ids:
            placeholders = ", ".join(["?"] * len(mobile_unit_ids))
            connection.execute(
                f"DELETE FROM material_stock WHERE mobile_unit_id IN ({placeholders})",
                list(mobile_unit_ids),
            )

        backup_rows = connection.execute(
            """
            SELECT material_id, mobile_unit_id, quantity
            FROM material_stock_import_backups
            WHERE batch_id = ?
            """,
            (int(batch_id),),
        ).fetchall()
        if backup_rows:
            connection.executemany(
                """
                INSERT INTO material_stock (material_id, mobile_unit_id, quantity)
                VALUES (?, ?, ?)
                ON CONFLICT(material_id, mobile_unit_id)
                DO UPDATE SET quantity = excluded.quantity
                """,
                [
                    (
                        row["material_id"],
                        row["mobile_unit_id"],
                        row["quantity"],
                    )
                    for row in backup_rows
                ],
            )

    elif import_type == "equipment_inventory":
        warehouse_codes = scope.get("warehouse_codes") or []
        if warehouse_codes:
            placeholders = ", ".join(["?"] * len(warehouse_codes))
            connection.execute(
                f"DELETE FROM equipment_inventory WHERE warehouse_code IN ({placeholders})",
                list(warehouse_codes),
            )

        backup_rows = connection.execute(
            """
            SELECT
                storage_location_id,
                mobile_unit_id,
                center_name,
                warehouse_code,
                warehouse_name,
                material_code,
                material_name,
                serial_number
            FROM equipment_inventory_import_backups
            WHERE batch_id = ?
            """,
            (int(batch_id),),
        ).fetchall()
        if backup_rows:
            serials = [row["serial_number"] for row in backup_rows if row.get("serial_number")]
            if serials:
                placeholders = ", ".join(["?"] * len(serials))
                connection.execute(
                    f"DELETE FROM equipment_inventory WHERE serial_number IN ({placeholders})",
                    serials,
                )
            connection.executemany(
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
                ON CONFLICT(serial_number)
                DO UPDATE SET
                    storage_location_id = excluded.storage_location_id,
                    mobile_unit_id = excluded.mobile_unit_id,
                    center_name = excluded.center_name,
                    warehouse_code = excluded.warehouse_code,
                    warehouse_name = excluded.warehouse_name,
                    material_code = excluded.material_code,
                    material_name = excluded.material_name
                """,
                [
                    (
                        row["storage_location_id"],
                        row["mobile_unit_id"],
                        row["center_name"],
                        row["warehouse_code"],
                        row["warehouse_name"],
                        row["material_code"],
                        row["material_name"],
                        row["serial_number"],
                    )
                    for row in backup_rows
                ],
            )
    else:
        raise ValueError("Tipo de importación no soportado para reversión.")

    connection.execute(
        """
        UPDATE import_batches
        SET status = ?,
            rolled_back_at = ?,
            rolled_back_by_user_id = ?
        WHERE id = ?
        """,
        ("rolled_back", now_value, int(actor_user_id), int(batch_id)),
    )
    connection.commit()


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


def fetch_distinct_supervisors():
    rows = get_db().execute(
        """
        SELECT DISTINCT COALESCE(supervisor_name, '') AS supervisor_name
        FROM technicians
        WHERE COALESCE(supervisor_name, '') != ''
        ORDER BY supervisor_name ASC
        """
    ).fetchall()
    return [row["supervisor_name"] for row in rows]


def fetch_distinct_centers():
    rows = get_db().execute(
        """
        SELECT DISTINCT COALESCE(center_name, '') AS center_name
        FROM technicians
        WHERE COALESCE(center_name, '') != ''
        ORDER BY center_name ASC
        """
    ).fetchall()
    return [row["center_name"] for row in rows]


def fetch_distinct_regions():
    rows = get_db().execute(
        """
        SELECT DISTINCT COALESCE(region, '') AS region
        FROM technicians
        WHERE COALESCE(region, '') != ''
        ORDER BY region ASC
        """
    ).fetchall()
    return [row["region"] for row in rows]


def fetch_distinct_companies():
    rows = get_db().execute(
        """
        SELECT DISTINCT COALESCE(company_name, '') AS company_name
        FROM technicians
        WHERE COALESCE(company_name, '') != ''
        ORDER BY company_name ASC
        """
    ).fetchall()
    return [row["company_name"] for row in rows]


def _build_technician_list_where_and_params(
    filters,
    supervisor_scope_names=None,
):
    filters = filters or {}
    where_clauses = ["1=1"]
    params = []

    q = (filters.get("q") or "").strip()
    region = (filters.get("region") or "").strip()
    supervisor = (filters.get("supervisor") or "").strip()
    center = (filters.get("center") or "").strip()
    company = (filters.get("company") or "").strip()
    is_active_raw = filters.get("is_active")

    if is_active_raw is not None and str(is_active_raw) != "":
        try:
            active_val = int(is_active_raw)
            where_clauses.append("technicians.is_active = ?")
            params.append(active_val)
        except (TypeError, ValueError):
            pass

    if q:
        like_value = f"%{q}%"
        if is_postgres():
            where_clauses.append(
                "(technicians.name ILIKE ? OR technicians.employee_code ILIKE ? OR technicians.phone ILIKE ? OR technicians.commune ILIKE ? OR technicians.team ILIKE ?)"
            )
        else:
            where_clauses.append(
                "(LOWER(technicians.name) LIKE ? OR LOWER(technicians.employee_code) LIKE ? OR LOWER(COALESCE(technicians.phone, '')) LIKE ? OR LOWER(COALESCE(technicians.commune, '')) LIKE ? OR LOWER(COALESCE(technicians.team, '')) LIKE ?)"
            )
        params.append(like_value)
        params.append(like_value)
        params.append(like_value)
        params.append(like_value)
        params.append(like_value)

    if region:
        if is_postgres():
            where_clauses.append("technicians.region ILIKE ?")
            params.append(region)
        else:
            where_clauses.append("LOWER(technicians.region) = ?")
            params.append(region.lower())

    if supervisor:
        if is_postgres():
            where_clauses.append("technicians.supervisor_name ILIKE ?")
            params.append(supervisor)
        else:
            where_clauses.append("LOWER(COALESCE(technicians.supervisor_name, '')) = ?")
            params.append(supervisor.lower())

    if center:
        if is_postgres():
            where_clauses.append("technicians.center_name ILIKE ?")
            params.append(center)
        else:
            where_clauses.append("LOWER(COALESCE(technicians.center_name, '')) = ?")
            params.append(center.lower())

    if company:
        if is_postgres():
            where_clauses.append("technicians.company_name ILIKE ?")
            params.append(company)
        else:
            where_clauses.append("LOWER(COALESCE(technicians.company_name, '')) = ?")
            params.append(company.lower())

    if supervisor_scope_names:
        normalized = normalize_supervisor_scope_names(supervisor_scope_names)
        if normalized:
            placeholders = ", ".join(["?"] * len(normalized))
            if is_postgres():
                where_clauses.append(
                    f"UPPER(TRIM(COALESCE(technicians.supervisor_name, ''))) IN ({placeholders})"
                )
            else:
                where_clauses.append(
                    f"UPPER(TRIM(COALESCE(technicians.supervisor_name, ''))) IN ({placeholders})"
                )
            params.extend([s.upper().strip() for s in normalized])

    where_sql = "WHERE " + " AND ".join(where_clauses)
    return where_sql, list(params)


_TECHNICIAN_SORT_WHITELIST = {
    "name": "technicians.name",
    "employee_code": "technicians.employee_code",
    "region": "technicians.region",
    "supervisor_name": "technicians.supervisor_name",
    "center_name": "technicians.center_name",
    "company_name": "technicians.company_name",
    "audits_count": "audits_count",
    "audit_approval_rate": "audit_approval_rate",
    "audit_avg_score": "audit_avg_score",
    "audit_critical_count": "audit_critical_count",
    "qc_count": "qc_count",
    "qc_approval_rate": "qc_approval_rate",
    "qc_avg_score": "qc_avg_score",
    "service_count": "service_count",
    "avg_nps": "avg_nps",
    "last_activity": "last_activity_expr",
    "is_active": "technicians.is_active",
}


def _build_technician_sort_order(sort_by, sort_dir):
    normalized_by = str(sort_by or "").strip().lower() or "name"
    normalized_dir = str(sort_dir or "").strip().lower()
    asc = normalized_dir != "desc"
    col_sql = _TECHNICIAN_SORT_WHITELIST.get(normalized_by, "technicians.name")
    dir_sql = "ASC" if asc else "DESC"
    tiebreaker = "technicians.is_active DESC, technicians.name ASC"
    return f"ORDER BY {col_sql} {dir_sql}, {tiebreaker}"


def fetch_technician_list_summary(
    filters=None,
    auditor_user_id=None,
    supervisor_scope_names=None,
    sort_by=None,
    sort_dir=None,
    limit=500,
    offset=0,
):
    filters = filters or {}
    where_sql, params = _build_technician_list_where_and_params(
        filters, supervisor_scope_names=supervisor_scope_names
    )

    from_date = (filters.get("from_date") or "").strip()
    to_date = (filters.get("to_date") or "").strip()

    audit_date_from = ""
    audit_date_to = ""
    qc_date_from = ""
    qc_date_to = ""
    service_date_from = ""
    service_date_to = ""
    tnps_date_from = ""
    tnps_date_to = ""
    if from_date:
        audit_date_from = "AND audits.audit_date >= ?"
        qc_date_from = "AND qc_sessions.qc_date >= ?"
        service_date_from = "AND service_sessions.service_date >= ?"
        tnps_date_from = "AND tnps_responses.response_date >= ?"
        params.extend([from_date, from_date, from_date, from_date])
    if to_date:
        audit_date_to = "AND audits.audit_date <= ?"
        qc_date_to = "AND qc_sessions.qc_date <= ?"
        service_date_to = "AND service_sessions.service_date <= ?"
        tnps_date_to = "AND tnps_responses.response_date <= ?"
        params.extend([to_date, to_date, to_date, to_date])

    order_sql = _build_technician_sort_order(sort_by, sort_dir)

    rows = get_db().execute(
        f"""
        SELECT
            technicians.id,
            technicians.name,
            technicians.employee_code,
            technicians.region,
            technicians.team,
            technicians.company_name,
            technicians.union_name,
            technicians.supervisor_name,
            technicians.center_name,
            technicians.is_active,
            COALESCE(audit_stats.audits_count, 0) AS audits_count,
            COALESCE(audit_stats.average_score, 0) AS audit_avg_score,
            COALESCE(audit_stats.approval_rate, 0) AS audit_approval_rate,
            COALESCE(audit_stats.critical_count, 0) AS audit_critical_count,
            COALESCE(qc_stats.qc_count, 0) AS qc_count,
            COALESCE(qc_stats.average_score, 0) AS qc_avg_score,
            COALESCE(qc_stats.approval_rate, 0) AS qc_approval_rate,
            COALESCE(service_stats.service_count, 0) AS service_count,
            COALESCE(service_stats.average_score, 0) AS service_avg_score,
            COALESCE(tnps_stats.avg_nps, 0) AS avg_nps,
            COALESCE(tnps_stats.nps_count, 0) AS nps_count,
            COALESCE(audit_stats.last_audit_date, '') AS last_audit_date,
            COALESCE(qc_stats.last_qc_date, '') AS last_qc_date,
            COALESCE(service_stats.last_service_date, '') AS last_service_date,
            GREATEST(
                COALESCE(audit_stats.last_audit_date, ''),
                COALESCE(qc_stats.last_qc_date, ''),
                COALESCE(service_stats.last_service_date, '')
            ) AS last_activity_expr
        FROM technicians
        LEFT JOIN (
            SELECT
                audits.technician_id AS tid,
                COUNT(*) AS audits_count,
                AVG(audits.total_score) AS average_score,
                CASE WHEN COUNT(*) = 0 THEN 0 ELSE
                    """ + _round_sql_expr("100.0 * SUM(CASE WHEN audits.result_status IN ('Aprobada', 'Aprobada con observaciones') THEN 1 ELSE 0 END) / COUNT(*)", 1) + """
                END AS approval_rate,
                SUM(CASE WHEN audits.result_status = 'Critica' THEN 1 ELSE 0 END) AS critical_count,
                MAX(audits.audit_date) AS last_audit_date
            FROM audits
            WHERE audits.technician_id IS NOT NULL
            {audit_date_from}
            {audit_date_to}
            GROUP BY audits.technician_id
        ) audit_stats ON audit_stats.tid = technicians.id
        LEFT JOIN (
            SELECT
                qc_sessions.technician_id AS tid,
                COUNT(*) AS qc_count,
                AVG(qc_sessions.total_score) AS average_score,
                CASE WHEN COUNT(*) = 0 THEN 0 ELSE
                    """ + _round_sql_expr("100.0 * SUM(CASE WHEN qc_sessions.result_status IN ('Aprobada', 'Aprobada con observaciones') THEN 1 ELSE 0 END) / COUNT(*)", 1) + """
                END AS approval_rate,
                MAX(qc_sessions.qc_date) AS last_qc_date
            FROM qc_sessions
            WHERE 1=1
            {qc_date_from}
            {qc_date_to}
            GROUP BY qc_sessions.technician_id
        ) qc_stats ON qc_stats.tid = technicians.id
        LEFT JOIN (
            SELECT
                service_sessions.technician_id AS tid,
                COUNT(*) AS service_count,
                AVG(service_sessions.total_score) AS average_score,
                MAX(service_sessions.service_date) AS last_service_date
            FROM service_sessions
            WHERE 1=1
            {service_date_from}
            {service_date_to}
            GROUP BY service_sessions.technician_id
        ) service_stats ON service_stats.tid = technicians.id
        LEFT JOIN (
            SELECT
                tnps_responses.technician_id AS tid,
                AVG(tnps_responses.score) AS avg_nps,
                COUNT(*) AS nps_count
            FROM tnps_responses
            WHERE tnps_responses.technician_id IS NOT NULL
            {tnps_date_from}
            {tnps_date_to}
            GROUP BY tnps_responses.technician_id
        ) tnps_stats ON tnps_stats.tid = technicians.id
        {where_sql}
        {order_sql}
        LIMIT ? OFFSET ?
        """,
        tuple(params + [int(limit), max(0, int(offset or 0))]),
    ).fetchall()

    result = []
    for row in rows:
        r = dict(row)

        ec = (r.get("employee_code") or "")
        ec_clean = str(ec).strip()
        if ec_clean:
            try:
                ec_num = float(ec_clean)
                if ec_num.is_integer():
                    ec_clean = str(int(ec_num))
                else:
                    ec_clean = str(ec_num)
            except (TypeError, ValueError):
                pass
        r["employee_code"] = ec_clean

        r["audits_count"] = int(r.get("audits_count") or 0)
        r["qc_count"] = int(r.get("qc_count") or 0)
        r["service_count"] = int(r.get("service_count") or 0)
        r["nps_count"] = int(r.get("nps_count") or 0)
        r["audit_critical_count"] = int(r.get("audit_critical_count") or 0)

        def _fmt_num(v, decimals=1):
            try:
                f = float(v or 0)
            except (TypeError, ValueError):
                f = 0.0
            r_rounded = round(f, decimals)
            if r_rounded == int(r_rounded):
                return int(r_rounded)
            return r_rounded

        r["audit_avg_score"] = _fmt_num(r.get("audit_avg_score"), 1)
        r["qc_avg_score"] = _fmt_num(r.get("qc_avg_score"), 1)
        r["service_avg_score"] = _fmt_num(r.get("service_avg_score"), 1)
        r["avg_nps"] = _fmt_num(r.get("avg_nps"), 1)
        r["audit_approval_rate"] = _fmt_num(r.get("audit_approval_rate"), 1)
        r["qc_approval_rate"] = _fmt_num(r.get("qc_approval_rate"), 1)
        result.append(r)
    return result


def count_technicians_list(
    filters=None,
    auditor_user_id=None,
    supervisor_scope_names=None,
):
    filters = filters or {}
    where_sql, params = _build_technician_list_where_and_params(
        filters, supervisor_scope_names=supervisor_scope_names
    )
    row = get_db().execute(
        f"""
        SELECT COUNT(*) AS c
        FROM technicians
        {where_sql}
        """,
        tuple(params),
    ).fetchone()
    try:
        return int(dict(row or {}).get("c") or 0)
    except (TypeError, ValueError):
        return 0


def fetch_technician_by_id(technician_id):
    try:
        tid = int(technician_id)
    except (TypeError, ValueError):
        return None
    row = get_db().execute(
        """
        SELECT id, name, employee_code, region, phone, commune, team,
               company_name, union_name, supervisor_name, center_name,
               is_active
        FROM technicians
        WHERE id = ?
        """,
        (tid,),
    ).fetchone()
    return dict(row) if row else None


def _fmt_num(v, digits=1):
    try:
        if v is None:
            return 0
        fv = float(v)
    except (TypeError, ValueError):
        return 0
    rounded = round(fv, digits)
    if rounded == int(rounded):
        return int(rounded)
    return rounded


def _build_range_params(filters):
    params = []
    audit_from = audit_to = qc_from = qc_to = service_from = service_to = tnps_from = tnps_to = ""
    from_date = (filters or {}).get("from_date") or ""
    to_date = (filters or {}).get("to_date") or ""
    if from_date:
        audit_from = "AND audits.audit_date >= ?"
        qc_from = "AND qc_sessions.qc_date >= ?"
        service_from = "AND service_sessions.service_date >= ?"
        tnps_from = "AND tnps_responses.response_date >= ?"
        params.extend([from_date, from_date, from_date, from_date])
    if to_date:
        audit_to = "AND audits.audit_date <= ?"
        qc_to = "AND qc_sessions.qc_date <= ?"
        service_to = "AND service_sessions.service_date <= ?"
        tnps_to = "AND tnps_responses.response_date <= ?"
        params.extend([to_date, to_date, to_date, to_date])
    return (audit_from, audit_to, qc_from, qc_to, service_from, service_to, tnps_from, tnps_to), params


def fetch_technician_profile_summary(technician_id, filters=None, auditor_user_id=None):
    try:
        tid = int(technician_id)
    except (TypeError, ValueError):
        return None
    (audit_from, audit_to, qc_from, qc_to, service_from, service_to, tnps_from, tnps_to), range_params = _build_range_params(filters)
    from_date = (filters or {}).get("from_date") or ""
    to_date = (filters or {}).get("to_date") or ""
    n_params = 0
    if from_date:
        n_params += 1
    if to_date:
        n_params += 1
    audit_rp = range_params[:n_params]
    qc_rp = range_params[n_params:2 * n_params]
    service_rp = range_params[2 * n_params:3 * n_params]
    tnps_rp = range_params[3 * n_params:4 * n_params]

    audit_sql = """
        SELECT
            COUNT(*) AS audits_count,
            """ + _round_sql_expr("AVG(audits.total_score)", 1) + """ AS audit_avg_score,
            SUM(CASE WHEN audits.result_status IN ('Aprobada', 'Aprobada con observaciones') THEN 1 ELSE 0 END) AS audit_approved,
            SUM(CASE WHEN audits.result_status = 'Critica' THEN 1 ELSE 0 END) AS audit_critical,
            MAX(audits.audit_date) AS last_audit_date,
            MIN(audits.audit_date) AS first_audit_date
        FROM audits
        WHERE audits.technician_id = ?
        {audit_from}
        {audit_to}
    """.format(audit_from=audit_from, audit_to=audit_to)
    qc_sql = """
        SELECT
            COUNT(*) AS qc_count,
            """ + _round_sql_expr("AVG(qc_sessions.total_score)", 1) + """ AS qc_avg_score,
            SUM(CASE WHEN qc_sessions.result_status IN ('Aprobada', 'Aprobada con observaciones') THEN 1 ELSE 0 END) AS qc_approved,
            MAX(qc_sessions.qc_date) AS last_qc_date,
            MIN(qc_sessions.qc_date) AS first_qc_date
        FROM qc_sessions
        WHERE qc_sessions.technician_id = ?
        {qc_from}
        {qc_to}
    """.format(qc_from=qc_from, qc_to=qc_to)
    service_sql = """
        SELECT
            COUNT(*) AS service_count,
            """ + _round_sql_expr("AVG(service_sessions.total_score)", 1) + """ AS service_avg_score,
            MAX(service_sessions.service_date) AS last_service_date,
            MIN(service_sessions.service_date) AS first_service_date
        FROM service_sessions
        WHERE service_sessions.technician_id = ?
        {service_from}
        {service_to}
    """.format(service_from=service_from, service_to=service_to)
    tnps_sql = """
        SELECT
            COUNT(*) AS nps_count,
            """ + _round_sql_expr("AVG(tnps_responses.score)", 1) + """ AS avg_nps,
            MIN(tnps_responses.response_date) AS first_tnps_date
        FROM tnps_responses
        WHERE tnps_responses.technician_id = ?
        {tnps_from}
        {tnps_to}
    """.format(tnps_from=tnps_from, tnps_to=tnps_to)
    audit_critical_items_sql = f"""
        SELECT
            audit_items.item_label AS label,
            COUNT(*) AS cnt
        FROM audits
        JOIN audit_items ON audit_items.audit_id = audits.id
        WHERE audits.technician_id = ?
          AND audit_items.status = 'no_cumple'
        {audit_from}
        {audit_to}
        GROUP BY audit_items.item_label
        ORDER BY cnt DESC, audit_items.item_label ASC
        LIMIT 5
    """
    qc_nc_major_items_sql = f"""
        SELECT
            qc_items.item_label AS label,
            COUNT(*) AS cnt
        FROM qc_sessions
        JOIN qc_items ON qc_items.qc_session_id = qc_sessions.id
        WHERE qc_sessions.technician_id = ?
          AND qc_items.status = 'nc_mayor'
        {qc_from}
        {qc_to}
        GROUP BY qc_items.item_label
        ORDER BY cnt DESC, qc_items.item_label ASC
        LIMIT 5
    """

    db = get_db()
    audit_row = db.execute(audit_sql, tuple([tid] + list(audit_rp))).fetchone()
    qc_row = db.execute(qc_sql, tuple([tid] + list(qc_rp))).fetchone()
    service_row = db.execute(service_sql, tuple([tid] + list(service_rp))).fetchone()
    tnps_row = db.execute(tnps_sql, tuple([tid] + list(tnps_rp))).fetchone()
    audit_items_rows = db.execute(audit_critical_items_sql, tuple([tid] + list(audit_rp))).fetchall()
    qc_items_rows = db.execute(qc_nc_major_items_sql, tuple([tid] + list(qc_rp))).fetchall()

    a = dict(audit_row or {})
    q = dict(qc_row or {})
    s = dict(service_row or {})
    t = dict(tnps_row or {})

    audits_count = int(a.get("audits_count") or 0)
    qc_count = int(q.get("qc_count") or 0)
    service_count = int(s.get("service_count") or 0)
    audit_approved = int(a.get("audit_approved") or 0)
    qc_approved = int(q.get("qc_approved") or 0)
    audit_critical = int(a.get("audit_critical") or 0)
    nps_count = int(t.get("nps_count") or 0)

    activity_dates = [
        a.get("last_audit_date") or "",
        q.get("last_qc_date") or "",
        s.get("last_service_date") or "",
    ]
    first_candidates = [
        d for d in [
            a.get("first_audit_date") or "",
            q.get("first_qc_date") or "",
            s.get("first_service_date") or "",
            t.get("first_tnps_date") or "",
        ] if d
    ]
    first_activity = min(first_candidates) if first_candidates else ""
    last_activity = ""
    last_non_empty = [x for x in activity_dates if x]
    if last_non_empty:
        last_activity = max(last_non_empty)

    return {
        "audits_count": audits_count,
        "audit_avg_score": _fmt_num(a.get("audit_avg_score"), 1),
        "audit_approval_rate": _fmt_num((100.0 * audit_approved / audits_count) if audits_count else 0, 1),
        "audit_critical_count": audit_critical,
        "audit_rejected_count": max(0, audits_count - audit_approved - audit_critical),
        "last_audit_date": a.get("last_audit_date") or "",
        "qc_count": qc_count,
        "qc_avg_score": _fmt_num(q.get("qc_avg_score"), 1),
        "qc_approval_rate": _fmt_num((100.0 * qc_approved / qc_count) if qc_count else 0, 1),
        "last_qc_date": q.get("last_qc_date") or "",
        "service_count": service_count,
        "service_avg_score": _fmt_num(s.get("service_avg_score"), 1),
        "last_service_date": s.get("last_service_date") or "",
        "nps_count": nps_count,
        "avg_nps": _fmt_num(t.get("avg_nps"), 1),
        "first_activity": first_activity,
        "last_activity": last_activity,
        "top_audit_no_cumple_items": [
            {"label": r["label"], "count": int(r["cnt"] or 0)}
            for r in audit_items_rows
        ],
        "top_qc_nc_mayor_items": [
            {"label": r["label"], "count": int(r["cnt"] or 0)}
            for r in qc_items_rows
        ],
    }


def fetch_technician_profile_benchmarks(technician_id, filters=None, auditor_user_id=None):
    tech = fetch_technician_by_id(technician_id)
    if not tech:
        return None
    supervisor = (tech.get("supervisor_name") or "").strip()
    center = (tech.get("center_name") or "").strip()
    region = (tech.get("region") or "").strip()
    company = (tech.get("company_name") or "").strip()

    peer_where = "1=1"
    peer_params = []
    scope_hint = "Empresa"
    if supervisor:
        peer_where = "UPPER(TRIM(COALESCE(technicians.supervisor_name, ''))) = UPPER(?)"
        peer_params = [supervisor]
        scope_hint = "Supervisor"
    elif center:
        peer_where = "UPPER(TRIM(COALESCE(technicians.center_name, ''))) = UPPER(?)"
        peer_params = [center]
        scope_hint = "Centro"
    elif region:
        peer_where = "UPPER(TRIM(COALESCE(technicians.region, ''))) = UPPER(?)"
        peer_params = [region]
        scope_hint = "Región"
    elif company:
        peer_where = "UPPER(TRIM(COALESCE(technicians.company_name, ''))) = UPPER(?)"
        peer_params = [company]
        scope_hint = "Empresa"

    (audit_from, audit_to, qc_from, qc_to, service_from, service_to, tnps_from, tnps_to), range_params = _build_range_params(filters)
    from_date = (filters or {}).get("from_date") or ""
    to_date = (filters or {}).get("to_date") or ""
    n_params = 0
    if from_date:
        n_params += 1
    if to_date:
        n_params += 1
    audit_rp = range_params[:n_params]
    qc_rp = range_params[n_params:2 * n_params]
    service_rp = range_params[2 * n_params:3 * n_params]
    tnps_rp = range_params[3 * n_params:4 * n_params]

    db = get_db()
    peers_ids_sql = f"""
        SELECT DISTINCT technicians.id
        FROM technicians
        WHERE {peer_where}
          AND technicians.is_active = 1
    """
    peer_rows = db.execute(peers_ids_sql, tuple(peer_params)).fetchall()
    peer_ids = [r["id"] for r in peer_rows]
    if int(tech["id"]) not in peer_ids:
        peer_ids.append(int(tech["id"]))
    peers_count = len(peer_ids)

    def _avg_over_peers(base_agg_sql, peer_ids, extra_params):
        if not peer_ids:
            return None
        placeholders = ",".join(["?"] * len(peer_ids))
        sql = base_agg_sql.format(peer_ids_where=f"IN ({placeholders})")
        params = list(peer_ids) + list(extra_params)
        row = db.execute(sql, tuple(params)).fetchone()
        return dict(row or {}) if row else {}

    audit_agg_sql = """
        SELECT
            COUNT(DISTINCT audits.id) AS total_count,
            COUNT(DISTINCT audits.technician_id) AS tech_count,
            """ + _round_sql_expr("AVG(audits.total_score)", 1) + """ AS avg_score,
            1.0 * SUM(CASE WHEN audits.result_status IN ('Aprobada', 'Aprobada con observaciones') THEN 1 ELSE 0 END) / NULLIF(COUNT(*), 0) AS approval_rate
        FROM audits
        WHERE audits.technician_id {peer_ids_where}
        {audit_from}
        {audit_to}
    """.format(audit_from=audit_from, audit_to=audit_to, peer_ids_where="{peer_ids_where}")
    qc_agg_sql = """
        SELECT
            COUNT(DISTINCT qc_sessions.id) AS total_count,
            COUNT(DISTINCT qc_sessions.technician_id) AS tech_count,
            """ + _round_sql_expr("AVG(qc_sessions.total_score)", 1) + """ AS avg_score,
            1.0 * SUM(CASE WHEN qc_sessions.result_status IN ('Aprobada', 'Aprobada con observaciones') THEN 1 ELSE 0 END) / NULLIF(COUNT(*), 0) AS approval_rate
        FROM qc_sessions
        WHERE qc_sessions.technician_id {peer_ids_where}
        {qc_from}
        {qc_to}
    """.format(qc_from=qc_from, qc_to=qc_to, peer_ids_where="{peer_ids_where}")
    service_agg_sql = """
        SELECT
            COUNT(DISTINCT service_sessions.id) AS total_count,
            COUNT(DISTINCT service_sessions.technician_id) AS tech_count,
            """ + _round_sql_expr("AVG(service_sessions.total_score)", 1) + """ AS avg_score
        FROM service_sessions
        WHERE service_sessions.technician_id {peer_ids_where}
        {service_from}
        {service_to}
    """.format(service_from=service_from, service_to=service_to, peer_ids_where="{peer_ids_where}")
    tnps_agg_sql = """
        SELECT
            COUNT(*) AS total_count,
            """ + _round_sql_expr("AVG(tnps_responses.score)", 1) + """ AS avg_score
        FROM tnps_responses
        WHERE tnps_responses.technician_id {peer_ids_where}
        {tnps_from}
        {tnps_to}
    """.format(tnps_from=tnps_from, tnps_to=tnps_to, peer_ids_where="{peer_ids_where}")

    a_bm = _avg_over_peers(audit_agg_sql, peer_ids, audit_rp) or {}
    q_bm = _avg_over_peers(qc_agg_sql, peer_ids, qc_rp) or {}
    s_bm = _avg_over_peers(service_agg_sql, peer_ids, service_rp) or {}
    t_bm = _avg_over_peers(tnps_agg_sql, peer_ids, tnps_rp) or {}

    return {
        "scope_hint": scope_hint,
        "scope_value": supervisor or center or region or company or "-",
        "peers_count": peers_count,
        "audit_avg_score": _fmt_num(a_bm.get("avg_score"), 1),
        "audit_approval_rate": _fmt_num(100.0 * float(a_bm.get("approval_rate") or 0), 1),
        "qc_avg_score": _fmt_num(q_bm.get("avg_score"), 1),
        "qc_approval_rate": _fmt_num(100.0 * float(q_bm.get("approval_rate") or 0), 1),
        "service_avg_score": _fmt_num(s_bm.get("avg_score"), 1),
        "avg_nps": _fmt_num(t_bm.get("avg_score"), 1),
    }


def fetch_technician_recent_audits(technician_id, filters=None, limit=8):
    try:
        tid = int(technician_id)
    except (TypeError, ValueError):
        return []
    (audit_from, audit_to, _, _, _, _, _, _), range_params = _build_range_params(filters)
    from_date = (filters or {}).get("from_date") or ""
    to_date = (filters or {}).get("to_date") or ""
    n_params = 0
    if from_date:
        n_params += 1
    if to_date:
        n_params += 1
    audit_rp = range_params[:n_params]

    rows = get_db().execute(
        f"""
        SELECT
            audits.id,
            audits.audit_date,
            audits.result_status,
            audits.total_score,
            audits.technician_display_name,
            audits.auditor_name,
            audits.sa_number,
            audits.location,
            audits.installation_type
        FROM audits
        WHERE audits.technician_id = ?
        {audit_from}
        {audit_to}
        ORDER BY audits.audit_date DESC, audits.id DESC
        LIMIT ?
        """,
        tuple([tid] + list(audit_rp) + [int(limit)]),
    ).fetchall()
    return [dict(r) for r in rows]


def fetch_technician_recent_qc(technician_id, filters=None, limit=8):
    try:
        tid = int(technician_id)
    except (TypeError, ValueError):
        return []
    (_, _, qc_from, qc_to, _, _, _, _), range_params = _build_range_params(filters)
    from_date = (filters or {}).get("from_date") or ""
    to_date = (filters or {}).get("to_date") or ""
    n_params = 0
    if from_date:
        n_params += 1
    if to_date:
        n_params += 1
    qc_rp = range_params[n_params:2 * n_params]

    rows = get_db().execute(
        f"""
        SELECT
            qc_sessions.id,
            qc_sessions.qc_date,
            qc_sessions.result_status,
            qc_sessions.total_score,
            qc_sessions.installation_type,
            qc_sessions.technician_display_name,
            qc_sessions.auditor_name,
            qc_sessions.sa_number,
            qc_sessions.location
        FROM qc_sessions
        WHERE qc_sessions.technician_id = ?
        {qc_from}
        {qc_to}
        ORDER BY qc_sessions.qc_date DESC, qc_sessions.id DESC
        LIMIT ?
        """,
        tuple([tid] + list(qc_rp) + [int(limit)]),
    ).fetchall()
    return [dict(r) for r in rows]


def fetch_technician_recent_service(technician_id, filters=None, limit=8):
    try:
        tid = int(technician_id)
    except (TypeError, ValueError):
        return []
    (_, _, _, _, service_from, service_to, _, _), range_params = _build_range_params(filters)
    from_date = (filters or {}).get("from_date") or ""
    to_date = (filters or {}).get("to_date") or ""
    n_params = 0
    if from_date:
        n_params += 1
    if to_date:
        n_params += 1
    service_rp = range_params[2 * n_params:3 * n_params]

    rows = get_db().execute(
        f"""
        SELECT
            service_sessions.id,
            service_sessions.service_date,
            service_sessions.result_status,
            service_sessions.total_score,
            service_sessions.technician_display_name,
            service_sessions.auditor_name,
            service_sessions.sa_number,
            service_sessions.location,
            service_sessions.optical_delta_dbm,
            service_sessions.record_scope
        FROM service_sessions
        WHERE service_sessions.technician_id = ?
        {service_from}
        {service_to}
        ORDER BY service_sessions.service_date DESC, service_sessions.id DESC
        LIMIT ?
        """,
        tuple([tid] + list(service_rp) + [int(limit)]),
    ).fetchall()
    return [dict(r) for r in rows]


def _period_key_expr(date_col, granularity="month"):
    normalized = (granularity or "month").strip().lower()
    if normalized == "week":
        if is_postgres():
            return (
                "to_char(date_trunc('week', CASE WHEN " + date_col + " IS NULL OR TRIM(" + date_col + ") = '' THEN NULL ELSE " + date_col + "::date END), 'IYYY-\"W\"IW')"
            )
        return "strftime('%Y-W%W', CASE WHEN COALESCE(" + date_col + ", '') = '' THEN NULL ELSE " + date_col + " END)"
    if is_postgres():
        return (
            "to_char(date_trunc('month', CASE WHEN " + date_col + " IS NULL OR TRIM(" + date_col + ") = '' THEN NULL ELSE " + date_col + "::date END), 'YYYY-MM')"
        )
    return "strftime('%Y-%m', CASE WHEN COALESCE(" + date_col + ", '') = '' THEN NULL ELSE " + date_col + " END)"


def _round_sql_expr(value_expr, ndigits=1):
    try:
        n = int(ndigits)
    except (TypeError, ValueError):
        n = 1
    n_str = str(n)
    if is_postgres():
        return "ROUND((" + value_expr + ")::numeric, " + n_str + ")"
    return "ROUND(" + value_expr + ", " + n_str + ")"


def fetch_technician_monthly_series(technician_id, filters=None, granularity="month", limit=18):
    try:
        tid = int(technician_id)
    except (TypeError, ValueError):
        return []
    (audit_from, audit_to, qc_from, qc_to, service_from, service_to, tnps_from, tnps_to), range_params = _build_range_params(filters)
    from_date = (filters or {}).get("from_date") or ""
    to_date = (filters or {}).get("to_date") or ""
    n_params = 0
    if from_date:
        n_params += 1
    if to_date:
        n_params += 1
    audit_rp = range_params[:n_params]
    qc_rp = range_params[n_params:2 * n_params]
    service_rp = range_params[2 * n_params:3 * n_params]
    tnps_rp = range_params[3 * n_params:4 * n_params]

    audit_period = _period_key_expr("audits.audit_date", granularity)
    qc_period = _period_key_expr("qc_sessions.qc_date", granularity)
    service_period = _period_key_expr("service_sessions.service_date", granularity)
    tnps_period = _period_key_expr("tnps_responses.response_date", granularity)

    audit_sql = """
        SELECT
            {audit_period} AS period_key,
            COUNT(*) AS audits_count,
            """ + _round_sql_expr("AVG(audits.total_score)", 1) + """ AS audit_avg_score,
            1.0 * SUM(CASE WHEN audits.result_status IN ('Aprobada', 'Aprobada con observaciones') THEN 1 ELSE 0 END) / NULLIF(COUNT(*), 0) AS audit_approval_rate,
            SUM(CASE WHEN audits.result_status = 'Critica' THEN 1 ELSE 0 END) AS audit_critical_count
        FROM audits
        WHERE audits.technician_id = ?
        {audit_from}
        {audit_to}
        GROUP BY period_key
    """.format(audit_period=audit_period, audit_from=audit_from, audit_to=audit_to)
    qc_sql = """
        SELECT
            {qc_period} AS period_key,
            COUNT(*) AS qc_count,
            """ + _round_sql_expr("AVG(qc_sessions.total_score)", 1) + """ AS qc_avg_score,
            1.0 * SUM(CASE WHEN qc_sessions.result_status IN ('Aprobada', 'Aprobada con observaciones') THEN 1 ELSE 0 END) / NULLIF(COUNT(*), 0) AS qc_approval_rate
        FROM qc_sessions
        WHERE qc_sessions.technician_id = ?
        {qc_from}
        {qc_to}
        GROUP BY period_key
    """.format(qc_period=qc_period, qc_from=qc_from, qc_to=qc_to)
    service_sql = """
        SELECT
            {service_period} AS period_key,
            COUNT(*) AS service_count,
            """ + _round_sql_expr("AVG(service_sessions.total_score)", 1) + """ AS service_avg_score
        FROM service_sessions
        WHERE service_sessions.technician_id = ?
        {service_from}
        {service_to}
        GROUP BY period_key
    """.format(service_period=service_period, service_from=service_from, service_to=service_to)
    tnps_sql = """
        SELECT
            {tnps_period} AS period_key,
            COUNT(*) AS nps_count,
            """ + _round_sql_expr("AVG(tnps_responses.score)", 1) + """ AS avg_nps
        FROM tnps_responses
        WHERE tnps_responses.technician_id = ?
        {tnps_from}
        {tnps_to}
        GROUP BY period_key
    """.format(tnps_period=tnps_period, tnps_from=tnps_from, tnps_to=tnps_to)

    db = get_db()
    a_rows = db.execute(audit_sql, tuple([tid] + list(audit_rp))).fetchall()
    q_rows = db.execute(qc_sql, tuple([tid] + list(qc_rp))).fetchall()
    s_rows = db.execute(service_sql, tuple([tid] + list(service_rp))).fetchall()
    t_rows = db.execute(tnps_sql, tuple([tid] + list(tnps_rp))).fetchall()

    merged = {}
    def _merge_rows(rows, source):
        for r in rows:
            d = dict(r)
            pk = d.pop("period_key")
            if pk not in merged:
                merged[pk] = {
                    "period_key": pk,
                    "audits_count": 0, "audit_avg_score": None, "audit_approval_rate": None, "audit_critical_count": 0,
                    "qc_count": 0, "qc_avg_score": None, "qc_approval_rate": None,
                    "service_count": 0, "service_avg_score": None,
                    "nps_count": 0, "avg_nps": None,
                }
            for k, v in d.items():
                if v is None or v == "":
                    continue
                merged[pk][k] = _fmt_num(v, 1) if k in (
                    "audit_avg_score", "qc_avg_score", "service_avg_score", "avg_nps"
                ) else (
                    _fmt_num(100.0 * float(v), 1) if k in ("audit_approval_rate", "qc_approval_rate") else int(v)
                )

    _merge_rows(a_rows, "audit")
    _merge_rows(q_rows, "qc")
    _merge_rows(s_rows, "service")
    _merge_rows(t_rows, "tnps")

    series = sorted(merged.values(), key=lambda x: x["period_key"])
    if limit and len(series) > limit:
        series = series[-limit:]
    return series


def _shift_dates(from_date, to_date, days):
    try:
        from datetime import datetime, timedelta
        fmt = "%Y-%m-%d"
        if not from_date or not to_date:
            return "", ""
        start = datetime.strptime(str(from_date), fmt)
        end = datetime.strptime(str(to_date), fmt)
        shift = timedelta(days=days)
        return (start - shift).strftime(fmt), (end - shift).strftime(fmt)
    except Exception:
        return "", ""


def fetch_technician_period_over_period(technician_id, filters=None):
    from_date = (filters or {}).get("from_date") or ""
    to_date = (filters or {}).get("to_date") or ""
    all_time = bool((filters or {}).get("all_time"))

    current_filters = dict(filters or {})
    if all_time or not from_date or not to_date:
        prev_filters = {"from_date": "", "to_date": "", "all_time": 0}
        current_summary = fetch_technician_profile_summary(technician_id, filters={"from_date": "", "to_date": ""})
        previous_summary = None
    else:
        try:
            from datetime import datetime
            fmt = "%Y-%m-%d"
            start = datetime.strptime(str(from_date), fmt)
            end = datetime.strptime(str(to_date), fmt)
            span_days = max(1, (end - start).days + 1)
            prev_from, prev_to = _shift_dates(from_date, to_date, span_days)
            prev_filters = {"from_date": prev_from, "to_date": prev_to}
            current_summary = fetch_technician_profile_summary(technician_id, filters=current_filters)
            previous_summary = fetch_technician_profile_summary(technician_id, filters=prev_filters)
        except Exception:
            current_summary = fetch_technician_profile_summary(technician_id, filters=current_filters)
            previous_summary = None

    if not current_summary:
        current_summary = {}
    if not previous_summary:
        previous_summary = {}

    kpis = [
        ("audits_count", "Auditorías", "cnt", None),
        ("audit_avg_score", "Score Audit prom.", "score", None),
        ("audit_approval_rate", "% Aprob. Audit", "pct", None),
        ("audit_critical_count", "Críticas Audit", "cnt_down_better"),
        ("qc_count", "QC", "cnt", None),
        ("qc_avg_score", "Score QC prom.", "score", None),
        ("qc_approval_rate", "% Aprob. QC", "pct", None),
        ("service_count", "Service", "cnt", None),
        ("service_avg_score", "Score Service prom.", "score", None),
        ("nps_count", "Respuestas NPS", "cnt", None),
        ("avg_nps", "NPS prom.", "nps", None),
    ]

    rows = []
    for key, label, kind, *_rest in kpis:
        cur_raw = current_summary.get(key)
        prev_raw = previous_summary.get(key)
        try:
            cur = float(cur_raw) if cur_raw not in (None, "", []) else None
        except (TypeError, ValueError):
            cur = None
        try:
            prev = float(prev_raw) if prev_raw not in (None, "", []) else None
        except (TypeError, ValueError):
            prev = None
        delta_val = None
        delta_pct = None
        if cur is not None and prev is not None and prev != 0:
            delta_val = cur - prev
            delta_pct = (delta_val / prev) * 100.0
        rows.append({
            "key": key,
            "label": label,
            "kind": kind,
            "current": _fmt_num(cur, 1) if cur is not None else "-",
            "previous": _fmt_num(prev, 1) if prev is not None else "-",
            "delta_val": ("{0:+.1f}".format(delta_val) if delta_val is not None else "-"),
            "delta_pct": ("{0:+.1f}%".format(delta_pct) if delta_pct is not None else "-"),
            "status": _delta_status(cur, prev, kind),
        })
    return {
        "current_filters": current_filters,
        "previous_filters": prev_filters if not (all_time or not from_date or not to_date) else {"label": "Sin comparar (Todo histórico)"},
        "rows": rows,
    }


def _delta_status(cur, prev, kind):
    if cur is None or prev is None:
        return "neutral"
    if kind == "cnt_down_better":
        if cur < prev:
            return "ok"
        if cur > prev:
            return "danger"
        return "neutral"
    if cur > prev:
        return "ok"
    if cur < prev:
        return "danger"
    return "neutral"


def _human_age_es(date_from_str, date_to_str):
    try:
        from datetime import datetime
        fmt = "%Y-%m-%d"
        if not date_from_str or not date_to_str:
            return ""
        d1 = datetime.strptime(str(date_from_str)[:10], fmt)
        d2 = datetime.strptime(str(date_to_str)[:10], fmt)
        if d2 < d1:
            d1, d2 = d2, d1
        years = d2.year - d1.year
        months = d2.month - d1.month
        days = (d2 - d2.replace(day=1)).days + 1 - ((d1 - d1.replace(day=1)).days + 1 - 1)
        if d2.day < d1.day:
            months -= 1
        if months < 0:
            years -= 1
            months += 12
        total_days = max(0, (d2 - d1).days)
        total_months = max(0, years * 12 + months)
        if total_days < 45:
            label = "{0} días".format(total_days)
        elif total_months < 24:
            label = "{0} mes{1}".format(total_months, "es" if total_months != 1 else "")
        else:
            if months == 0:
                label = "{0} año{1}".format(years, "s" if years != 1 else "")
            else:
                label = "{0} año{1} {2} mes{3}".format(
                    years, "s" if years != 1 else "",
                    months, "es" if months != 1 else "",
                )
        return {
            "label": label,
            "total_days": total_days,
            "total_months": total_months,
            "years": years,
            "months": months,
        }
    except Exception:
        return ""


def _days_between(from_str, to_str):
    try:
        from datetime import datetime
        fmt = "%Y-%m-%d"
        if not from_str or not to_str:
            return None
        d1 = datetime.strptime(str(from_str)[:10], fmt)
        d2 = datetime.strptime(str(to_str)[:10], fmt)
        return (d2 - d1).days
    except Exception:
        return None


def fetch_technician_historical_profile(technician_id, filters=None):
    try:
        tid = int(technician_id)
    except (TypeError, ValueError):
        return {}
    lifetime_summary = fetch_technician_profile_summary(tid, filters={"from_date": "", "to_date": ""}) or {}
    monthly = fetch_technician_monthly_series(tid, filters={"from_date": "", "to_date": ""}, granularity="month", limit=36) or []

    today_str = _fmt_today_iso()
    first_activity = lifetime_summary.get("first_activity") or ""
    last_activity = lifetime_summary.get("last_activity") or ""
    last_audit = lifetime_summary.get("last_audit_date") or ""
    last_qc = lifetime_summary.get("last_qc_date") or ""
    last_service = lifetime_summary.get("last_service_date") or ""

    age = _human_age_es(first_activity, today_str) if first_activity else ""
    age_label = age["label"] if isinstance(age, dict) else (age or "")
    total_months = (age["total_months"] if isinstance(age, dict) else 0) or 1

    a_cum = 0
    qc_cum = 0
    sv_cum = 0
    peak_audit = None
    peak_qc = None
    peak_service = None
    worst_approval_audit = None
    worst_approval_qc = None

    audits_total = int(lifetime_summary.get("audits_count") or 0)
    qc_total = int(lifetime_summary.get("qc_count") or 0)
    service_total = int(lifetime_summary.get("service_count") or 0)
    nps_total = int(lifetime_summary.get("nps_count") or 0)

    for m in monthly:
        a = int(m.get("audits_count") or 0)
        q = int(m.get("qc_count") or 0)
        s = int(m.get("service_count") or 0)
        a_cum += a
        qc_cum += q
        sv_cum += s
        if peak_audit is None or a > peak_audit.get("value", 0):
            peak_audit = {"period": m.get("period_key"), "value": a}
        if peak_qc is None or q > peak_qc.get("value", 0):
            peak_qc = {"period": m.get("period_key"), "value": q}
        if peak_service is None or s > peak_service.get("value", 0):
            peak_service = {"period": m.get("period_key"), "value": s}
        a_appr = m.get("audit_approval_rate")
        q_appr = m.get("qc_approval_rate")
        if a_appr is not None and a_appr != "" and a > 0:
            try:
                v = float(a_appr)
                if worst_approval_audit is None or v < worst_approval_audit.get("value", 999):
                    worst_approval_audit = {"period": m.get("period_key"), "value": v, "formatted": _fmt_num(v, 1)}
            except (TypeError, ValueError):
                pass
        if q_appr is not None and q_appr != "" and q > 0:
            try:
                v = float(q_appr)
                if worst_approval_qc is None or v < worst_approval_qc.get("value", 999):
                    worst_approval_qc = {"period": m.get("period_key"), "value": v, "formatted": _fmt_num(v, 1)}
            except (TypeError, ValueError):
                pass

    avg_per_month = {
        "audits": _fmt_num((1.0 * audits_total / total_months) if total_months else 0, 1),
        "qc": _fmt_num((1.0 * qc_total / total_months) if total_months else 0, 1),
        "service": _fmt_num((1.0 * service_total / total_months) if total_months else 0, 1),
        "nps": _fmt_num((1.0 * nps_total / total_months) if total_months else 0, 1),
    }

    days_since_last_activity = _days_between(last_activity, today_str) if last_activity else None
    days_since_last_audit = _days_between(last_audit, today_str) if last_audit else None
    days_since_last_qc = _days_between(last_qc, today_str) if last_qc else None
    days_since_last_service = _days_between(last_service, today_str) if last_service else None

    critical_total = int(lifetime_summary.get("audit_critical_count") or 0)
    audit_critical_rate = (
        _fmt_num(100.0 * critical_total / audits_total, 1) if audits_total else "0"
    )

    return {
        "lifetime_summary": lifetime_summary,
        "monthly_series": monthly,
        "age": {
            "first": first_activity,
            "last": last_activity,
            "label": age_label,
            "total_days": age["total_days"] if isinstance(age, dict) else 0,
            "total_months": total_months,
        },
        "volumes": {
            "audits_total": audits_total,
            "qc_total": qc_total,
            "service_total": service_total,
            "nps_total": nps_total,
            "avg_per_month": avg_per_month,
        },
        "quality": {
            "audit_avg_score": lifetime_summary.get("audit_avg_score"),
            "qc_avg_score": lifetime_summary.get("qc_avg_score"),
            "service_avg_score": lifetime_summary.get("service_avg_score"),
            "avg_nps": lifetime_summary.get("avg_nps"),
            "audit_approval_rate": lifetime_summary.get("audit_approval_rate"),
            "qc_approval_rate": lifetime_summary.get("qc_approval_rate"),
            "audit_critical_count": critical_total,
            "audit_critical_rate": audit_critical_rate,
            "audit_rejected_count": int(lifetime_summary.get("audit_rejected_count") or 0),
        },
        "peaks": {
            "audit": peak_audit,
            "qc": peak_qc,
            "service": peak_service,
            "worst_audit_approval": worst_approval_audit,
            "worst_qc_approval": worst_approval_qc,
        },
        "streaks": {
            "days_since_last_activity": days_since_last_activity,
            "days_since_last_audit": days_since_last_audit,
            "days_since_last_qc": days_since_last_qc,
            "days_since_last_service": days_since_last_service,
            "last_audit_date": last_audit,
            "last_qc_date": last_qc,
            "last_service_date": last_service,
        },
        "today": today_str,
    }


def _fmt_today_iso():
    try:
        from datetime import datetime
        return datetime.today().strftime("%Y-%m-%d")
    except Exception:
        return ""


