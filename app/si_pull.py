import base64
import json
import re
import threading
import time
import unicodedata
from datetime import datetime, timedelta, timezone
from decimal import Decimal

from flask import current_app

from app.models import (
    apply_si_stock_snapshot,
    get_db,
    is_postgres,
    mark_si_ot_no_realizadas_resueltas,
    upsert_si_ot_batch,
    upsert_si_ot_no_realizadas_batch,
)


class SIPullConfigError(RuntimeError):
    """Error de configuración para la conexión pull del Sistema Integral."""


class SIPullBusyError(RuntimeError):
    """El pull del Sistema Integral ya está corriendo en esta instancia."""


_RUN_LOCK = threading.Lock()
_SYNC_KEY = "si_ot_pull"


def _required_pull_settings():
    config = {
        "host": current_app.config.get("SI_MSSQL_HOST"),
        "port": current_app.config.get("SI_MSSQL_PORT"),
        "database": current_app.config.get("SI_MSSQL_DATABASE"),
        "user": current_app.config.get("SI_MSSQL_USER"),
        "password": current_app.config.get("SI_MSSQL_PASSWORD"),
        "connect_timeout": current_app.config.get("SI_PULL_CONNECT_TIMEOUT_SECONDS") or 30,
        "query_timeout": current_app.config.get("SI_PULL_QUERY_TIMEOUT_SECONDS") or 120,
    }
    missing = [key for key in ("host", "database", "user", "password") if not config.get(key)]
    if missing:
        raise SIPullConfigError(
            "Faltan variables de entorno para el pull del Sistema Integral: "
            + ", ".join(f"SI_MSSQL_{key.upper()}" for key in missing)
        )
    return config


def _resolve_window_minutes(raw_minutes):
    if raw_minutes is None or str(raw_minutes).strip() == "":
        return max(1, int(current_app.config.get("SI_PULL_WINDOW_MINUTES") or 15))
    try:
        return max(1, int(str(raw_minutes).strip()))
    except (TypeError, ValueError) as exc:
        raise ValueError("minutes debe ser un entero positivo") from exc


def _serialize_value(value):
    if isinstance(value, (bytes, bytearray)):
        return base64.b64encode(bytes(value)).decode("ascii")
    if isinstance(value, datetime):
        return value.strftime("%Y-%m-%d %H:%M:%S")
    if isinstance(value, Decimal):
        return float(value)
    return value


def _serialize_rows(rows):
    serialized = []
    for row in rows or []:
        serialized.append({key: _serialize_value(value) for key, value in dict(row).items()})
    return serialized


def _utc_now():
    return datetime.now(timezone.utc).replace(microsecond=0)


def _utc_now_text():
    return _utc_now().strftime("%Y-%m-%d %H:%M:%S")


def _parse_text_datetime(raw_value):
    if not raw_value:
        return None
    raw = str(raw_value).strip()
    if not raw:
        return None
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S%z", "%Y-%m-%dT%H:%M:%S"):
        try:
            parsed = datetime.strptime(raw, fmt)
            if parsed.tzinfo is not None:
                return parsed.astimezone(timezone.utc).replace(tzinfo=None)
            return parsed
        except ValueError:
            continue
    try:
        parsed = datetime.fromisoformat(raw)
        if parsed.tzinfo is not None:
            return parsed.astimezone(timezone.utc).replace(tzinfo=None)
        return parsed
    except ValueError:
        return None


def _placeholder():
    return "%s" if is_postgres() else "?"


def _ensure_sync_state_table():
    db = get_db()
    if is_postgres():
        db.execute(
            """
            CREATE TABLE IF NOT EXISTS si_sync_state (
                sync_key TEXT PRIMARY KEY,
                lock_acquired_at TEXT,
                last_started_at TEXT,
                last_finished_at TEXT,
                last_success_at TEXT,
                last_status TEXT,
                last_error TEXT,
                last_filter_since TEXT,
                last_summary TEXT,
                updated_at TEXT
            )
            """
        )
    else:
        db.execute(
            """
            CREATE TABLE IF NOT EXISTS si_sync_state (
                sync_key TEXT PRIMARY KEY,
                lock_acquired_at TEXT,
                last_started_at TEXT,
                last_finished_at TEXT,
                last_success_at TEXT,
                last_status TEXT,
                last_error TEXT,
                last_filter_since TEXT,
                last_summary TEXT,
                updated_at TEXT
            )
            """
        )
    db.commit()


def _fetch_sync_state(sync_key=None):
    _ensure_sync_state_table()
    db = get_db()
    ph = _placeholder()
    key = sync_key or _SYNC_KEY
    row = db.execute(
        f"SELECT * FROM si_sync_state WHERE sync_key = {ph}",
        (key,),
    ).fetchone()
    if not row:
        return None
    return dict(row) if isinstance(row, dict) else dict(zip(row.keys(), row))


def _upsert_sync_state(sync_key=None, **fields):
    _ensure_sync_state_table()
    db = get_db()
    key = sync_key or _SYNC_KEY
    current = _fetch_sync_state(key) or {"sync_key": key}
    current.update(fields)
    current["sync_key"] = key
    columns = [
        "sync_key",
        "lock_acquired_at",
        "last_started_at",
        "last_finished_at",
        "last_success_at",
        "last_status",
        "last_error",
        "last_filter_since",
        "last_summary",
        "updated_at",
    ]
    values = [current.get(col) for col in columns]
    ph = _placeholder()
    exists = db.execute(
        f"SELECT sync_key FROM si_sync_state WHERE sync_key = {ph}",
        (key,),
    ).fetchone()
    if exists:
        assignments = ", ".join(f"{col} = {ph}" for col in columns[1:])
        db.execute(
            f"UPDATE si_sync_state SET {assignments} WHERE sync_key = {ph}",
            tuple(values[1:] + [key]),
        )
    else:
        db.execute(
            f"INSERT INTO si_sync_state ({', '.join(columns)}) VALUES ({', '.join([ph] * len(columns))})",
            tuple(values),
        )
    db.commit()
    return current


def get_si_pull_state(sync_key=None, lock_timeout_config="SI_PULL_LOCK_TIMEOUT_SECONDS"):
    key = sync_key or _SYNC_KEY
    state = _fetch_sync_state(key)
    if not state:
        return {
            "sync_key": key,
            "last_status": "idle",
            "running": False,
        }
    lock_timeout = int(current_app.config.get(lock_timeout_config) or 900)
    locked_at = _parse_text_datetime(state.get("lock_acquired_at"))
    running = bool(locked_at and (datetime.utcnow() - locked_at) < timedelta(seconds=lock_timeout))
    normalized = dict(state)
    normalized["running"] = running
    return normalized


def _fetch_server_now(cursor):
    """Hora local del SQL Server, que es la que usa Fecha_Carga."""
    cursor.execute("SELECT GETDATE() AS server_now")
    row = cursor.fetchone() or {}
    value = row.get("server_now")
    if not isinstance(value, datetime):
        raise RuntimeError("El SQL Server del Sistema Integral no devolvió una hora válida")
    return value.replace(microsecond=0, tzinfo=None)


def _resolve_filter_since(raw_minutes, server_now):
    window_minutes = _resolve_window_minutes(raw_minutes)
    if raw_minutes is not None:
        since_dt = server_now - timedelta(minutes=window_minutes)
        return since_dt, window_minutes, "manual-window"

    state = _fetch_sync_state()
    last_success_at = _parse_text_datetime((state or {}).get("last_success_at"))
    if last_success_at:
        since_dt = last_success_at - timedelta(minutes=window_minutes)
        return since_dt, window_minutes, "resume-window"

    since_dt = server_now - timedelta(minutes=window_minutes)
    return since_dt, window_minutes, "fallback-window"


def _load_catalogs(cursor):
    catalog_queries = (
        ("materiales", "SELECT * FROM Materiales"),
        ("tecnicos", "SELECT t.n_tec, t.dni, t.coord, t.sup, t.Centro, d.nombre, d.apellido FROM Tecnicos t LEFT JOIN DatosPersonales d ON d.dni = t.dni"),
        ("centros", "SELECT * FROM Centros"),
        ("proveedores", "SELECT * FROM Proveedores"),
        ("actividades", "SELECT * FROM Actividades"),
        ("tipo_ot_estados", "SELECT * FROM Tipo_Ot_Estados"),
        ("empresas", "SELECT * FROM Empresas"),
        ("sindicatos", "SELECT * FROM Sindicatos"),
    )
    catalogos = {}
    for key, sql in catalog_queries:
        cursor.execute(sql)
        catalogos[key] = _serialize_rows(cursor.fetchall() or [])
    return catalogos


def _fetch_related_rows(cursor, table_sql, ids):
    if not ids:
        return {}
    placeholders = ", ".join(["%s"] * len(ids))
    cursor.execute(table_sql.format(placeholders=placeholders), tuple(ids))
    grouped = {}
    for row in cursor.fetchall() or []:
        data = {key: _serialize_value(value) for key, value in dict(row).items()}
        key = int(data["id_ot"])
        grouped.setdefault(key, []).append(data)
    return grouped


def _fetch_wfx_rows(cursor, n_ots):
    if not n_ots:
        return {}
    placeholders = ", ".join(["%s"] * len(n_ots))
    cursor.execute(
        f"""
        SELECT w.n_ot, w.estado, w.cod_res, w.tipo_trabajo, w.nodo,
               w.nombre, w.dni, w.tel, w.n_cli
        FROM OT_WFX_2 w
        INNER JOIN (
            SELECT n_ot, MAX(id) AS max_id
            FROM OT_WFX_2
            WHERE n_ot IN ({placeholders})
            GROUP BY n_ot
        ) x ON x.n_ot = w.n_ot AND x.max_id = w.id
        """,
        tuple(n_ots),
    )
    return {
        str(row["n_ot"]): {key: _serialize_value(value) for key, value in dict(row).items()}
        for row in (cursor.fetchall() or [])
    }


def _fetch_equipment_rows(cursor, n_ots):
    if not n_ots:
        return {}
    placeholders = ", ".join(["%s"] * len(n_ots))
    cursor.execute(
        f"""
        SELECT eu.id, eu.n_ot, eu.serial, 'Utilizado' AS operacion, sbe.material
        FROM EquiposUT eu
        LEFT JOIN Stock_Base_Eqp sbe ON sbe.serial = eu.serial
        WHERE eu.n_ot IN ({placeholders})
        UNION ALL
        SELECT -er.id AS id, er.n_ot, er.serial, 'Recuperado' AS operacion, sbe.material
        FROM EquiposRec er
        LEFT JOIN Stock_Base_Eqp sbe ON sbe.serial = er.serial
        WHERE er.n_ot IN ({placeholders})
        """,
        tuple(n_ots) + tuple(n_ots),
    )
    grouped = {}
    for row in cursor.fetchall() or []:
        data = {key: _serialize_value(value) for key, value in dict(row).items()}
        grouped.setdefault(str(data["n_ot"]), []).append(data)
    return grouped


def _prepare_batch(cursor, ot_batch):
    prepared = _serialize_rows(ot_batch)
    ids = [int(ot["id"]) for ot in prepared if ot.get("id") is not None]
    n_ots = [str(ot["n_ot"]) for ot in prepared if ot.get("n_ot")]
    actividades = _fetch_related_rows(
        cursor,
        "SELECT id, id_ot, cantidad, actividad_id FROM OtActividades WHERE id_ot IN ({placeholders})",
        ids,
    )
    materiales = _fetch_related_rows(
        cursor,
        "SELECT id, id_ot, material, cantidad FROM OtMateriales WHERE id_ot IN ({placeholders})",
        ids,
    )
    wfx_rows = _fetch_wfx_rows(cursor, n_ots)
    equipment_rows = _fetch_equipment_rows(cursor, n_ots)

    for ot in prepared:
        ot_id = int(ot["id"]) if ot.get("id") is not None else None
        ot["actividades"] = actividades.get(ot_id, []) if ot_id is not None else []
        ot["materiales"] = materiales.get(ot_id, []) if ot_id is not None else []
        ot["equipos"] = equipment_rows.get(str(ot.get("n_ot") or ""), [])
        wfx = wfx_rows.get(str(ot.get("n_ot") or ""))
        if wfx:
            ot["estado_real"] = wfx.get("estado")
            ot["cod_res"] = wfx.get("cod_res")
            ot["tipo_trabajo"] = wfx.get("tipo_trabajo")
            ot["nodo"] = wfx.get("nodo")
            ot["cliente_nombre"] = wfx.get("nombre")
            ot["cliente_dni"] = wfx.get("dni") or wfx.get("n_cli") or ot.get("n_cliente")
            ot["cliente_tel"] = wfx.get("tel")
            if ot.get("n_cliente") in (None, ""):
                ot["n_cliente"] = wfx.get("n_cli")
    return prepared


def _process_upsert_batch(prepared_batch, catalogos):
    result = upsert_si_ot_batch({"ots": prepared_batch, "catalogos": catalogos})
    errors = result.get("errors") or []
    if not result.get("ok") or errors:
        raise RuntimeError(f"Lote rechazado por upsert_si_ot_batch: {errors}")
    return result


# =========================================================================
# OT no realizadas
#
# En el SI el técnico registra el motivo editando el campo "dirección": borra
# la dirección y escribe el motivo (a veces como "MOTIVO // DIRECCION"). Por eso
# guardamos siempre el texto original (dir_original) y, además, una versión
# clasificada (direccion + motivo + categoria) que se puede reclasificar sin
# volver a consultar el SI.
# =========================================================================

_CATEGORIA_PENDIENTE = "pendiente"
_CATEGORIA_MOTIVO = "motivo"
_CATEGORIA_CARGA_ERRONEA = "carga_erronea"
_CATEGORIA_REALIZADO_SIN_CARGA = "realizado_sin_carga"

_NO_REALIZADAS_LOOKBACK_DAYS_DEFAULT = 90

_CARGA_ERRONEA_PATTERNS = tuple(
    re.compile(pattern)
    for pattern in (
        r"\bMAL CARGAD[AO]S?\b",
        r"\bMAL GENERAD[AO]S?\b",
        r"\bCARGA ERRONEA\b",
        r"\bERROR DE CARGA\b",
        r"\bNO CORRESPONDE\b",
        r"\bPRUEBA\b",
        r"\bTEST\b",
    )
)

_MOTIVO_PATTERNS = tuple(
    re.compile(pattern)
    for pattern in (
        r"\bANULAD[AO]S?\b",
        r"\bANULACION\b",
        r"\bCANCELAD[AO]S?\b",
        r"\bCANCELACION\b",
        r"\bAUSENTE\b",
        r"\bAUSENCIA\b",
        r"\bDOMICILIO CERRADO\b",
        r"\bCASA CERRADA\b",
        r"\bREAGEND\w*\b",
        r"\bREPROGRAMAD[AO]S?\b",
        r"\bREPROGRAMAR\b",
        r"\bPOSTERGAD[AO]S?\b",
        r"\bSUSPENDID[AO]S?\b",
        r"\bSUSPENSION\b",
        r"\bCLIMA\b",
        r"\bLLUVIA\b",
        r"\bMAL TIEMPO\b",
        r"\bSIN ACCESO\b",
        r"\bSIN RED\b",
        r"\bSIN SENAL\b",
        r"\bSIN FIBRA\b",
        r"\bSIN POSTE\b",
        r"\bSIN ELECTRICIDAD\b",
        r"\bSIN MATERIALES\b",
        r"\bFALTA MATERIAL(?:ES)?\b",
        r"\bSIN CABLE\b",
        r"\bNO SE REALIZ\w*\b",
        r"\bNO REALIZAD[AO]S?\b",
        r"\bNO SE PUDO\b",
        r"\bNO SE PUEDE\b",
        r"\bCANERIA OBSTRUIDA\b",
        r"\bOBSTRUID[AO]\b",
        r"\bINCONVENIENTE CDO\b",
        r"\bCDO SATURAD[OA]\b",
        r"\bCDO LLENO\b",
        r"\bPOSTE QUEBRAD[OA]\b",
        r"\bPOSTE INCLINAD[OA]\b",
        r"\bRECHAZAD[AO]S?\b",
        r"\bRECHAZO\b",
        r"\bNO ACEPTA\b",
        r"\bDUPLICAD[AO]S?\b",
        r"\bFUERA DE ZONA\b",
        r"\bDIRECCION ERRONEA\b",
        r"\bDOMICILIO ERRONEO\b",
        r"\bNO INSTALAD[AO]\b",
    )
)


def _normalize_text(value):
    """Mayúsculas sin acentos y con espacios colapsados, para comparar motivos."""
    if value is None:
        return ""
    text = unicodedata.normalize("NFKD", str(value))
    text = "".join(ch for ch in text if not unicodedata.combining(ch))
    return re.sub(r"\s+", " ", text).upper().strip()


def _match_pattern(text, patterns):
    for pattern in patterns:
        found = pattern.search(text)
        if found:
            return found.group(0)
    return None


def _classify_no_realizada(dir_original, estado):
    """Separa dirección y motivo a partir del texto libre del campo "dir"."""
    raw = (dir_original or "").strip()
    normalized = _normalize_text(raw)
    estado_norm = _normalize_text(estado)

    info = {
        "dir_original": raw or None,
        "direccion": raw or None,
        "motivo": None,
        "categoria": _CATEGORIA_PENDIENTE,
    }

    if normalized:
        matched = _match_pattern(normalized, _CARGA_ERRONEA_PATTERNS)
        if matched:
            info["motivo"] = matched
            info["direccion"] = None
            info["categoria"] = _CATEGORIA_CARGA_ERRONEA
            return info

        if "//" in raw:
            motivo_seg = None
            direccion_seg = None
            for segment in [seg.strip() for seg in raw.split("//") if seg.strip()]:
                if motivo_seg is None and _match_pattern(_normalize_text(segment), _MOTIVO_PATTERNS):
                    motivo_seg = segment
                elif direccion_seg is None:
                    direccion_seg = segment
            if motivo_seg:
                info["motivo"] = motivo_seg
                info["direccion"] = direccion_seg
                info["categoria"] = _CATEGORIA_MOTIVO
                return info

        matched = _match_pattern(normalized, _MOTIVO_PATTERNS)
        if matched:
            info["motivo"] = raw
            info["direccion"] = None
            info["categoria"] = _CATEGORIA_MOTIVO
            return info

    if estado_norm == "REALIZADO":
        info["categoria"] = _CATEGORIA_REALIZADO_SIN_CARGA
        return info

    if not normalized:
        info["direccion"] = None
    return info


def _resolve_no_realizadas_lookback_days():
    try:
        return max(1, int(current_app.config.get("SI_PULL_NO_REALIZADAS_LOOKBACK_DAYS") or _NO_REALIZADAS_LOOKBACK_DAYS_DEFAULT))
    except (TypeError, ValueError):
        return _NO_REALIZADAS_LOOKBACK_DAYS_DEFAULT


def _resolve_no_realizadas_watermark():
    """Último id de OT_WFX_2 ya procesado (0 fuerza la carga inicial por fecha)."""
    try:
        row = get_db().execute(
            "SELECT MAX(wfx_id) AS max_id FROM si_ot_no_realizadas"
        ).fetchone()
    except Exception:
        return 0
    if not row:
        return 0
    value = row["max_id"] if isinstance(row, dict) else row[0]
    try:
        return int(value or 0)
    except (TypeError, ValueError):
        return 0


def _fetch_no_realizadas_rows(cursor, watermark, lookback_days):
    """Última fila de OT_WFX_2 por n_ot que no tiene registro en OtRealizadas.

    Sin marca de agua se hace la carga inicial por fecha (últimos N días). Con
    marca de agua se traen solo las OT con movimientos nuevos (id > watermark),
    que es una lectura por rango sobre la PK clustered de OT_WFX_2.
    """
    if watermark:
        window_sql = "id > %s"
        window_params = (int(watermark),)
    else:
        window_sql = "fecha >= DATEADD(day, %s, CAST(GETDATE() AS date))"
        window_params = (-int(lookback_days),)

    cursor.execute(
        f"""
        SELECT w.n_ot, w.id AS wfx_id, w.estado, w.tipo_trabajo, w.cod_res, w.nodo,
               w.id_u, w.nombre, w.n_cli, w.dni, w.tel, w.dir, w.fecha, w.act,
               w.Centro, w.Empresa, w.Sindicato
        FROM OT_WFX_2 w
        INNER JOIN (
            SELECT n_ot, MAX(id) AS max_id
            FROM OT_WFX_2
            WHERE {window_sql}
            GROUP BY n_ot
        ) x ON x.n_ot = w.n_ot AND x.max_id = w.id
        LEFT JOIN OtRealizadas o ON o.n_ot = w.n_ot
        WHERE o.n_ot IS NULL
        """,
        window_params,
    )
    return cursor.fetchall() or []


def _prepare_no_realizada(row):
    data = {key: _serialize_value(value) for key, value in dict(row).items()}
    data["wfx_id"] = int(data["wfx_id"]) if data.get("wfx_id") is not None else None
    data["ultimo_movimiento"] = data.get("act")
    return {**data, **_classify_no_realizada(data.get("dir"), data.get("estado"))}


def _pull_no_realizadas(cursor):
    """Sincroniza las OT creadas en el SI que no figuran en OtRealizadas."""
    watermark = _resolve_no_realizadas_watermark()
    lookback_days = _resolve_no_realizadas_lookback_days()
    rows = _fetch_no_realizadas_rows(cursor, watermark, lookback_days)

    saved = 0
    if rows:
        result = upsert_si_ot_no_realizadas_batch([_prepare_no_realizada(row) for row in rows])
        errors = result.get("errors") or []
        if errors:
            raise RuntimeError(f"Lote rechazado por upsert_si_ot_no_realizadas_batch: {errors}")
        saved = int(result.get("no_realizadas") or 0)

    resueltas = mark_si_ot_no_realizadas_resueltas()
    return {
        "strategy": "incremental-id" if watermark else "initial-window",
        "watermark": watermark,
        "lookback_days": lookback_days,
        "candidates": len(rows),
        "saved": saved,
        "resueltas": resueltas,
    }


def si_pull_dry_run(raw_minutes=None):
    """Valida conexión a SQL Server y devuelve métricas básicas sin escribir datos."""
    settings = _required_pull_settings()
    window_minutes = _resolve_window_minutes(raw_minutes)

    try:
        import pymssql
    except ImportError as exc:
        raise RuntimeError("pymssql no está instalado en el entorno actual") from exc

    conn = pymssql.connect(
        server=settings["host"],
        port=int(settings["port"]),
        user=settings["user"],
        password=settings["password"],
        database=settings["database"],
        login_timeout=int(settings["connect_timeout"]),
        timeout=int(settings["query_timeout"]),
        charset="UTF-8",
        as_dict=True,
    )
    try:
        cursor = conn.cursor(as_dict=True)

        # La ventana se calcula con la hora del SQL Server: Fecha_Carga está en hora
        # local del servidor y Render corre en UTC, así que usar el reloj local del
        # proceso desplazaría el filtro (~3 horas) y no traería ninguna OT.
        server_now = _fetch_server_now(cursor)
        since_dt = server_now - timedelta(minutes=window_minutes)
        since_sql = since_dt.strftime("%Y%m%d %H:%M:%S")
        server_info = {"server_now": server_now}

        cursor.execute(
            """
            SELECT COUNT(*) AS total_ot, MAX(Fecha_Carga) AS ultima_fecha_carga
            FROM OtRealizadas
            WHERE Fecha_Carga > %s
            """,
            (since_sql,),
        )
        ot_stats = cursor.fetchone() or {}

        cursor.execute(
            """
            SELECT TOP 5 id, n_ot, Fecha_Carga
            FROM OtRealizadas
            WHERE Fecha_Carga > %s
            ORDER BY Fecha_Carga DESC
            """,
            (since_sql,),
        )
        ot_rows = cursor.fetchall() or []

        cursor.execute(
            """
            SELECT COUNT(*) AS total_actividades
            FROM OtActividades a
            INNER JOIN OtRealizadas o ON a.id_ot = o.id
            WHERE o.Fecha_Carga > %s
            """,
            (since_sql,),
        )
        act_stats = cursor.fetchone() or {}

        cursor.execute(
            """
            SELECT COUNT(*) AS total_materiales
            FROM OtMateriales m
            INNER JOIN OtRealizadas o ON m.id_ot = o.id
            WHERE o.Fecha_Carga > %s
            """,
            (since_sql,),
        )
        mat_stats = cursor.fetchone() or {}

        # OT que existen en la bitácora pero nunca se cargaron como realizadas.
        nr_watermark = _resolve_no_realizadas_watermark()
        nr_lookback = _resolve_no_realizadas_lookback_days()
        nr_rows = _fetch_no_realizadas_rows(cursor, nr_watermark, nr_lookback)
        nr_categorias = {}
        for row in nr_rows:
            categoria = _classify_no_realizada(row.get("dir"), row.get("estado"))["categoria"]
            nr_categorias[categoria] = nr_categorias.get(categoria, 0) + 1
    finally:
        conn.close()

    return {
        "mode": "dry-run",
        "window_minutes": window_minutes,
        "filter_since": since_dt.strftime("%Y-%m-%d %H:%M:%S"),
        "filter_since_sql": since_sql,
        "mssql": {
            "host": settings["host"],
            "port": int(settings["port"]),
            "database": settings["database"],
            "server_now": _serialize_value(server_info.get("server_now")),
        },
        "stats": {
            "ot_realizadas": int(ot_stats.get("total_ot") or 0),
            "ot_actividades": int(act_stats.get("total_actividades") or 0),
            "ot_materiales": int(mat_stats.get("total_materiales") or 0),
            "ultima_fecha_carga": _serialize_value(ot_stats.get("ultima_fecha_carga")),
        },
        "no_realizadas": {
            "watermark": nr_watermark,
            "lookback_days": nr_lookback,
            "strategy": "incremental-id" if nr_watermark else "initial-window",
            "total": len(nr_rows),
            "categorias": nr_categorias,
        },
        "sample_ots": _serialize_rows(ot_rows),
    }


def si_pull_run(raw_minutes=None, include_catalogs=False):
    """Ejecuta el pull incremental real y persiste las OT en la base local."""
    if not _RUN_LOCK.acquire(blocking=False):
        raise SIPullBusyError("Ya hay un pull del Sistema Integral corriendo en esta instancia")

    started_at = _utc_now_text()
    try:
        settings = _required_pull_settings()
        batch_size = max(1, int(current_app.config.get("SI_PULL_BATCH_SIZE") or 500))
        pause_seconds = max(0, int(current_app.config.get("SI_PULL_PAUSE_MS") or 0)) / 1000.0

        try:
            import pymssql
        except ImportError as exc:
            raise RuntimeError("pymssql no está instalado en el entorno actual") from exc

        conn = pymssql.connect(
            server=settings["host"],
            port=int(settings["port"]),
            user=settings["user"],
            password=settings["password"],
            database=settings["database"],
            login_timeout=int(settings["connect_timeout"]),
            timeout=int(settings["query_timeout"]),
            charset="UTF-8",
            as_dict=True,
        )
        try:
            cursor = conn.cursor(as_dict=True)

            # La ventana y la marca de agua se manejan con la hora del SQL Server, que es
            # el reloj de Fecha_Carga. El reloj del proceso (UTC en Render) no sirve acá.
            server_now = _fetch_server_now(cursor)
            since_dt, window_minutes, strategy = _resolve_filter_since(raw_minutes, server_now)
            since_sql = since_dt.strftime("%Y%m%d %H:%M:%S")
            watermark = server_now.strftime("%Y-%m-%d %H:%M:%S")

            _upsert_sync_state(
                lock_acquired_at=started_at,
                last_started_at=started_at,
                last_finished_at=None,
                last_status="running",
                last_error=None,
                last_filter_since=since_dt.strftime("%Y-%m-%d %H:%M:%S"),
                updated_at=started_at,
            )

            catalogos = {}
            if include_catalogs:
                catalogos = _load_catalogs(cursor)

            cursor.execute(
                """
                SELECT * FROM OtRealizadas
                WHERE Fecha_Carga > %s
                ORDER BY Fecha_Carga
                """,
                (since_sql,),
            )
            ot_rows = cursor.fetchall() or []

            total_ots = 0
            total_actividades = 0
            total_materiales = 0
            batch_count = 0
            sent_catalogs = False

            if include_catalogs and not ot_rows:
                result = _process_upsert_batch([], catalogos)
                total_actividades += int(result.get("actividades") or 0)
                total_materiales += int(result.get("materiales") or 0)
                sent_catalogs = True

            for offset in range(0, len(ot_rows), batch_size):
                raw_batch = ot_rows[offset: offset + batch_size]
                prepared_batch = _prepare_batch(cursor, raw_batch)
                batch_catalogos = catalogos if include_catalogs and not sent_catalogs else {}
                result = _process_upsert_batch(prepared_batch, batch_catalogos)
                total_ots += int(result.get("ots") or 0)
                total_actividades += int(result.get("actividades") or 0)
                total_materiales += int(result.get("materiales") or 0)
                batch_count += 1
                sent_catalogs = sent_catalogs or bool(batch_catalogos)
                if pause_seconds > 0 and offset + batch_size < len(ot_rows):
                    time.sleep(pause_seconds)

            # OT creadas en el SI que nunca llegaron a OtRealizadas.
            no_realizadas = _pull_no_realizadas(cursor)
        finally:
            conn.close()

        finished_at = _utc_now_text()
        summary = {
            "window_minutes": window_minutes,
            "strategy": strategy,
            "ots": total_ots,
            "actividades": total_actividades,
            "materiales": total_materiales,
            "batches": batch_count,
            "include_catalogs": bool(include_catalogs),
            "no_realizadas": no_realizadas,
        }
        _upsert_sync_state(
            lock_acquired_at=None,
            last_finished_at=finished_at,
            # La marca de agua queda en hora del SQL Server, no en hora del proceso.
            last_success_at=watermark,
            last_status="ok",
            last_error=None,
            last_filter_since=since_dt.strftime("%Y-%m-%d %H:%M:%S"),
            last_summary=json.dumps(summary, ensure_ascii=False),
            updated_at=finished_at,
        )
        return {
            "mode": "run",
            "window_minutes": window_minutes,
            "filter_since": since_dt.strftime("%Y-%m-%d %H:%M:%S"),
            "filter_since_sql": since_sql,
            "strategy": strategy,
            "include_catalogs": bool(include_catalogs),
            "stats": {
                "ot_realizadas": total_ots,
                "ot_actividades": total_actividades,
                "ot_materiales": total_materiales,
                "batches": batch_count,
                "no_realizadas": no_realizadas.get("saved") or 0,
            },
            "no_realizadas": no_realizadas,
            "state": get_si_pull_state(),
        }
    except Exception as exc:
        finished_at = _utc_now_text()
        _upsert_sync_state(
            lock_acquired_at=None,
            last_finished_at=finished_at,
            last_status="error",
            last_error=str(exc),
            updated_at=finished_at,
        )
        raise
    finally:
        _RUN_LOCK.release()


def _last_attempt_utc():
    """Momento (UTC) del último intento de pull, exitoso o no."""
    state = _fetch_sync_state() or {}
    candidates = []
    for key in ("last_finished_at", "last_started_at"):
        parsed = _parse_text_datetime(state.get(key))
        if parsed:
            candidates.append(parsed)
    return max(candidates) if candidates else None


def si_pull_on_demand_ready(ignore_throttle=False):
    """Indica si corresponde disparar un pull on-demand.

    Devuelve (bool, motivo). El throttle evita que cada carga de la vista
    martille el SQL Server del Sistema Integral.
    """
    if not current_app.config.get("SI_PULL_ON_DEMAND"):
        return False, "disabled"
    state = get_si_pull_state()
    if state.get("running"):
        return False, "running"
    if ignore_throttle:
        return True, "forced"
    min_interval = max(1, int(current_app.config.get("SI_PULL_ON_DEMAND_MIN_INTERVAL_MINUTES") or 10))
    last_attempt = _last_attempt_utc()
    if last_attempt and (datetime.utcnow() - last_attempt) < timedelta(minutes=min_interval):
        return False, "throttled"
    return True, "ready"


def maybe_si_pull_async(force=False):
    """Lanza el pull en un hilo aparte para no bloquear el request del usuario."""
    should_run, reason = si_pull_on_demand_ready(ignore_throttle=force)
    if not should_run:
        return {"started": False, "reason": reason}

    app = current_app._get_current_object()

    def _worker():
        with app.app_context():
            try:
                si_pull_run()
            except SIPullBusyError:
                pass
            except Exception:
                app.logger.exception("si_pull on-demand error")

    threading.Thread(target=_worker, name="si-pull-on-demand", daemon=True).start()
    return {"started": True, "reason": reason}


# =========================================================================
# Pull de stock (almacenes + stock de materiales + equipos serializados)
#
# Reemplaza el import manual de ALMACENES.xlsx + StockMateriales + StockDeEquipos.
# El universo son todos los almacenes del SI: móviles de técnicos (base=0) y
# depósitos base (base=1). Un mismo código de móvil aparece repetido, una vez
# por centro, siempre para el mismo técnico: por eso el móvil se identifica por
# código y el stock se agrega por (material, móvil).
# =========================================================================

STOCK_SYNC_KEY = "si_stock_pull"

_STOCK_RUN_LOCK = threading.Lock()


def get_si_stock_pull_state():
    """Estado del último pull de stock (misma tabla si_sync_state, otra clave)."""
    return get_si_pull_state(STOCK_SYNC_KEY, lock_timeout_config="SI_STOCK_PULL_LOCK_TIMEOUT_SECONDS")


def _load_stock_material_catalog(cursor):
    """Catálogo id_material -> descripción, para nombrar materiales igual que el SI."""
    cursor.execute("SELECT id_material, descri FROM Materiales")
    catalog = {}
    for row in cursor.fetchall() or []:
        data = dict(row)
        try:
            catalog[int(data["id_material"])] = (data.get("descri") or "").strip()
        except (TypeError, ValueError):
            continue
    return catalog


def _fetch_stock_almacenes(cursor):
    """Almacenes del SI con nombre de centro y datos del técnico asignado."""
    cursor.execute(
        """
        SELECT a.id, a.codigo, a.Descri, a.base, a.habilitado, a.Usr, a.Centro,
               c.Descripcion AS centro_nombre,
               d.nombre AS tec_nombre, d.apellido AS tec_apellido
        FROM almacen a
        LEFT JOIN Centros c ON c.Id_Centro = a.Centro
        LEFT JOIN Tecnicos t ON t.dni = a.Usr
        LEFT JOIN DatosPersonales d ON d.dni = t.dni
        """
    )
    return _serialize_rows(cursor.fetchall() or [])


def _fetch_stock_material_rows(cursor, max_quantity):
    """Stock actual por almacén (cantidad = Stock.Libre)."""
    cursor.execute(
        """
        SELECT s.Almacen, s.Material, s.Libre
        FROM Stock s
        WHERE s.Libre > 0 AND s.Libre < %s
        """,
        (int(max_quantity),),
    )
    return cursor.fetchall() or []


def _fetch_stock_equipment_rows(cursor, include_scrap):
    """Seriales vigentes por almacén (solo los que tienen un almacén válido)."""
    scrap_filter = "" if include_scrap else "AND e.Scrap = 0"
    cursor.execute(
        f"""
        SELECT e.Almacen, e.material, e.serial
        FROM Stock_Base_Eqp e
        INNER JOIN almacen a ON a.id = e.Almacen
        WHERE e.serial IS NOT NULL AND LTRIM(RTRIM(e.serial)) <> '' {scrap_filter}
        """
    )
    return cursor.fetchall() or []


def si_stock_pull_run(include_equipment=True):
    """Trae el stock actual del SI y lo aplica sobre las tablas de Auditoría."""
    if not current_app.config.get("SI_STOCK_PULL_ENABLED", True):
        raise RuntimeError("El pull de stock del Sistema Integral está deshabilitado")

    if not _STOCK_RUN_LOCK.acquire(blocking=False):
        raise SIPullBusyError("Ya hay un pull de stock del Sistema Integral corriendo en esta instancia")

    started_at = _utc_now_text()
    try:
        settings = _required_pull_settings()
        max_quantity = int(current_app.config.get("SI_STOCK_PULL_MAX_QUANTITY") or 500000)
        include_scrap = bool(current_app.config.get("SI_STOCK_PULL_INCLUDE_SCRAP"))

        try:
            import pymssql
        except ImportError as exc:
            raise RuntimeError("pymssql no está instalado en el entorno actual") from exc

        conn = pymssql.connect(
            server=settings["host"],
            port=int(settings["port"]),
            user=settings["user"],
            password=settings["password"],
            database=settings["database"],
            login_timeout=int(settings["connect_timeout"]),
            timeout=int(settings["query_timeout"]),
            charset="UTF-8",
            as_dict=True,
        )
        try:
            cursor = conn.cursor(as_dict=True)
            # Marca de agua con la hora del SQL Server (no la del proceso, que en
            # Render es UTC) para que el banner muestre la misma hora que el pull de OT.
            server_time = _fetch_server_now(cursor)
            _upsert_sync_state(
                sync_key=STOCK_SYNC_KEY,
                lock_acquired_at=started_at,
                last_started_at=started_at,
                last_finished_at=None,
                last_status="running",
                last_error=None,
                updated_at=started_at,
            )

            material_catalog = _load_stock_material_catalog(cursor)
            almacenes = _fetch_stock_almacenes(cursor)
            material_rows = _fetch_stock_material_rows(cursor, max_quantity)
            equipment_rows = (
                _fetch_stock_equipment_rows(cursor, include_scrap) if include_equipment else []
            )
        finally:
            conn.close()

        applied = apply_si_stock_snapshot(
            almacenes, material_rows, equipment_rows, material_catalog
        )

        finished_at = _utc_now_text()
        summary = {
            "almacenes": len(almacenes),
            "material_rows": len(material_rows),
            "equipment_rows": len(equipment_rows),
            "include_equipment": bool(include_equipment),
            "include_scrap": include_scrap,
            "max_quantity": max_quantity,
            "applied": applied,
        }
        _upsert_sync_state(
            sync_key=STOCK_SYNC_KEY,
            lock_acquired_at=None,
            last_finished_at=finished_at,
            last_success_at=server_time.strftime("%Y-%m-%d %H:%M:%S"),
            last_status="ok",
            last_error=None,
            last_summary=json.dumps(summary, ensure_ascii=False),
            updated_at=finished_at,
        )
        return {"mode": "run", "state": get_si_stock_pull_state(), **summary}
    except Exception as exc:
        finished_at = _utc_now_text()
        _upsert_sync_state(
            sync_key=STOCK_SYNC_KEY,
            lock_acquired_at=None,
            last_finished_at=finished_at,
            last_status="error",
            last_error=str(exc),
            updated_at=finished_at,
        )
        raise
    finally:
        _STOCK_RUN_LOCK.release()


def _stock_last_attempt_utc():
    state = _fetch_sync_state(STOCK_SYNC_KEY) or {}
    candidates = []
    for key in ("last_finished_at", "last_started_at"):
        parsed = _parse_text_datetime(state.get(key))
        if parsed:
            candidates.append(parsed)
    return max(candidates) if candidates else None


def si_stock_pull_on_demand_ready(ignore_throttle=False):
    """Indica si corresponde disparar un pull de stock on-demand."""
    if not current_app.config.get("SI_STOCK_PULL_ON_DEMAND"):
        return False, "disabled"
    state = get_si_stock_pull_state()
    if state.get("running"):
        return False, "running"
    if ignore_throttle:
        return True, "forced"
    min_interval = max(1, int(current_app.config.get("SI_STOCK_PULL_ON_DEMAND_MIN_INTERVAL_MINUTES") or 360))
    last_attempt = _stock_last_attempt_utc()
    if last_attempt and (datetime.utcnow() - last_attempt) < timedelta(minutes=min_interval):
        return False, "throttled"
    return True, "ready"


def maybe_si_stock_pull_async(force=False):
    """Lanza el pull de stock en un hilo aparte para no bloquear el request."""
    should_run, reason = si_stock_pull_on_demand_ready(ignore_throttle=force)
    if not should_run:
        return {"started": False, "reason": reason}

    app = current_app._get_current_object()

    def _worker():
        with app.app_context():
            try:
                si_stock_pull_run()
            except SIPullBusyError:
                pass
            except Exception:
                app.logger.exception("si_stock_pull on-demand error")

    threading.Thread(target=_worker, name="si-stock-pull-on-demand", daemon=True).start()
    return {"started": True, "reason": reason}
