import base64
import binascii
import csv
import hashlib
import hmac
import io
import json
import os
import secrets
import time
import traceback
from pathlib import Path
from uuid import uuid4
from datetime import datetime, timedelta

from flask import Blueprint, abort, current_app, flash, g, jsonify, make_response, redirect, render_template, request, session, url_for
from werkzeug.security import check_password_hash
from werkzeug.utils import secure_filename

try:
    from PIL import Image, ImageOps
except ImportError:
    Image = None
    ImageOps = None

from app.checklist import AUDIT_CHECKLIST_SECTIONS, CHECKLIST_SECTIONS, QC_SECTION_KEY
from app.models import (
    count_active_admins,
    count_users,
    create_audit,
    create_audit_supply_requests,
    create_import_batch,
    create_qc_session,
    create_user,
    count_findings,
    create_tnps_response,
    finalize_import_batch,
    get_audit_official_from_date,
    update_user,
    fetch_user_by_id,
    fetch_user_by_username,
    fetch_users,
    fetch_user_supervisor_scopes,
    fetch_user_supervisor_scope_names,
    fetch_audit_detail,
    fetch_audit_findings,
    fetch_findings,
    fetch_finding_stats,
    fetch_finding_status_breakdown,
    fetch_effectiveness_alerts,
    fetch_finding_detail,
    fetch_finding_events,
    TREATMENT_REASON_OPTIONS,
    add_finding_treatment_update,
    fetch_audit_items,
    fetch_audit_supply_requests,
    fetch_supply_requests_feed,
    fetch_all_audits,
    fetch_audit_picker_audits,
    fetch_audit_reports_management_summary,
    fetch_audit_reports_missing_evidence,
    fetch_audit_reports_section_breakdown,
    fetch_audit_reports_status_breakdown,
    fetch_audit_reports_supply_requests_detail,
    fetch_audit_reports_supply_requests_summary,
    fetch_audit_reports_supervisor_responsibility_detail,
    fetch_audit_reports_critical_findings,
    fetch_audit_reports_supervisor_breakdown,
    fetch_audit_reports_center_breakdown,
    fetch_audit_reports_company_breakdown,
    fetch_audit_reports_technician_ranking,
    fetch_audit_reports_mobile_ranking,
    fetch_audit_reports_time_series,
    fetch_dashboard_stats,
    fetch_distinct_mobile_codes,
    fetch_distinct_auditors,
    fetch_distinct_finding_auditors,
    fetch_distinct_finding_locations,
    fetch_distinct_finding_supervisors,
    fetch_distinct_storage_centers,
    fetch_distinct_warehouse_codes,
    fetch_distinct_warehouse_types,
    fetch_equipment_summary,
    fetch_equipment_inventory,
    fetch_mobile_audit_context,
    fetch_mobile_equipment,
    fetch_mobile_material_stock,
    fetch_mobile_overview_stats,
    fetch_mobile_related_audits,
    fetch_mobile_storage_locations,
    fetch_mobile_unit_by_id,
    fetch_mobile_unit_by_any_id,
    fetch_mobile_unit_detail,
    fetch_vehicles_by_employee_code,
    fetch_tnps_responses,
    fetch_tnps_response_for_audit,
    fetch_tnps_stats,
    fetch_tnps_technician_rankings,
    fetch_material_by_code,
    fetch_material_catalog,
    fetch_materials_summary,
    fetch_material_stock_rows,
    fetch_recent_audits,
    fetch_stock_stats,
    fetch_storage_locations,
    fetch_storage_locations_summary,
    fetch_technicians,
    fetch_technician_list_summary,
    count_technicians_list,
    fetch_technician_by_id,
    fetch_technician_profile_summary,
    fetch_technician_profile_benchmarks,
    fetch_technician_recent_audits,
    fetch_technician_recent_qc,
    fetch_technician_recent_service,
    fetch_technician_monthly_series,
    fetch_technician_period_over_period,
    fetch_technician_historical_profile,
    fetch_technician_distribution_ranking,
    fetch_technician_findings_trend,
    lookup_vehicle_for_technician,
    load_truck_plate_map,
    fetch_distinct_supervisors,
    fetch_distinct_centers,
    fetch_distinct_regions,
    fetch_distinct_companies,
    fetch_vehicles,
    fetch_mobile_units,
    fetch_qc_sessions,
    fetch_qc_sessions_for_audit,
    fetch_qc_session_detail,
    fetch_qc_items,
    fetch_service_sessions,
    fetch_service_session_detail,
    fetch_service_items,
    fetch_service_speedtests,
    create_service_session,
    fetch_qc_reports_management_summary,
    fetch_qc_reports_status_breakdown,
    fetch_qc_reports_time_series,
    fetch_qc_reports_technician_ranking,
    fetch_qc_reports_technician_ranking_by_nc_major,
    fetch_qc_technician_extra_summary,
    fetch_qc_technician_nc_breakdown,
    fetch_qc_technician_nc_summary,
    fetch_tnps_response_for_qc,
    count_audit_picker_audits,
    import_checklist_del_dia,
    import_equipment_inventory,
    import_material_stock,
    import_novedades_diarias,
    import_storage_locations,
    import_technician_information,
    import_technicians,
    import_vehicles,
    fetch_import_batches,
    rollback_import_batch,
    replace_user_supervisor_scopes,
    update_finding_response,
    update_finding_effectiveness,
    validate_finding,
    update_audit_record_scope,
    update_mobile_unit_technician,
    update_vehicle_extinguisher_expiry,
    update_vehicle_insurance_expiry,
    update_vehicle_gnc_expiry,
    update_vehicle_rto_expiry,
    update_vehicle_botiquin_expiry,
    create_supervisor,
    update_supervisor,
    fetch_supervisor_by_id,
    fetch_supervisors,
    count_supervisors,
    fetch_active_supervisors,
    toggle_supervisor_active,
    create_vehicle,
    update_vehicle,
    fetch_vehicle_by_id,
    fetch_vehicle_by_plate,
    toggle_vehicle_active,
    assign_vehicle_to_technician,
    create_technician,
    update_technician,
    fetch_technician_by_employee_code,
    toggle_technician_active,
    fetch_master_technicians,
    count_master_technicians,
    parse_unit_plate,
    fetch_distinct_supervisors,
    fetch_distinct_centers,
    fetch_distinct_regions,
    fetch_distinct_companies,
    fetch_vehicles,
    count_vehicles,
    fetch_technicians,
    fetch_technician_by_id,
    fetch_vehicles_by_employee_code,
)
from app.spreadsheets import parse_tabular_upload


main = Blueprint("main", __name__)

_login_attempts = {}

def csrf_token():
    token = session.get("_csrf_token")
    if token and isinstance(token, str) and len(token) >= 32:
        return token
    token = secrets.token_urlsafe(32)
    session["_csrf_token"] = token
    return token


def validate_csrf_token(value):
    expected = session.get("_csrf_token")
    provided = (value or "").strip()
    if not expected or not provided:
        return False
    if not isinstance(expected, str):
        return False
    return hmac.compare_digest(expected, provided)


def client_ip():
    forwarded = (request.headers.get("X-Forwarded-For") or "").split(",")[0].strip()
    if forwarded:
        return forwarded
    return request.remote_addr or "unknown"


def _login_rate_limit_settings():
    window_seconds = int(os.environ.get("LOGIN_RATE_LIMIT_WINDOW_SECONDS") or 300)
    max_per_ip = int(os.environ.get("LOGIN_RATE_LIMIT_MAX_IP") or 25)
    max_per_user = int(os.environ.get("LOGIN_RATE_LIMIT_MAX_USER") or 10)
    return window_seconds, max_per_ip, max_per_user


def _prune_attempts(timestamps, now, window_seconds):
    if not timestamps:
        return []
    cutoff = now - window_seconds
    return [ts for ts in timestamps if ts >= cutoff]


def is_login_rate_limited(ip, username):
    window_seconds, max_per_ip, max_per_user = _login_rate_limit_settings()
    now = int(time.time())

    ip_key = f"ip:{ip}"
    ip_attempts = _prune_attempts(_login_attempts.get(ip_key), now, window_seconds)
    _login_attempts[ip_key] = ip_attempts
    if len(ip_attempts) >= max_per_ip:
        return True

    normalized_user = (username or "").strip().lower()
    if normalized_user:
        user_key = f"user:{normalized_user}"
        user_attempts = _prune_attempts(_login_attempts.get(user_key), now, window_seconds)
        _login_attempts[user_key] = user_attempts
        if len(user_attempts) >= max_per_user:
            return True

    return False


def record_login_failure(ip, username):
    window_seconds, _max_per_ip, _max_per_user = _login_rate_limit_settings()
    now = int(time.time())

    ip_key = f"ip:{ip}"
    ip_attempts = _prune_attempts(_login_attempts.get(ip_key), now, window_seconds)
    ip_attempts.append(now)
    _login_attempts[ip_key] = ip_attempts

    normalized_user = (username or "").strip().lower()
    if normalized_user:
        user_key = f"user:{normalized_user}"
        user_attempts = _prune_attempts(_login_attempts.get(user_key), now, window_seconds)
        user_attempts.append(now)
        _login_attempts[user_key] = user_attempts


def clear_login_failures(ip, username):
    ip_key = f"ip:{ip}"
    _login_attempts.pop(ip_key, None)
    normalized_user = (username or "").strip().lower()
    if normalized_user:
        _login_attempts.pop(f"user:{normalized_user}", None)

#region debug-point audit-evidence-500
def _dbg_audit_evidence_500(event_name, payload=None):
    try:
        if os.environ.get("DEBUG_AUDIT_EVIDENCE_500") != "1":
            return
        outdir = os.path.join(os.getcwd(), ".dbg")
        os.makedirs(outdir, exist_ok=True)
        out_path = os.path.join(outdir, "trae-debug-log-audit-evidence-500.ndjson")
        entry = {
            "ts": int(time.time() * 1000),
            "sessionId": "audit-evidence-500",
            "event": event_name,
            "payload": payload or {},
        }
        with open(out_path, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry, ensure_ascii=False) + "\n")
    except Exception:
        return
#endregion debug-point audit-evidence-500


NON_COMPLIANCE_REASON_LABELS = {
    "olvido": "Olvido / En otro cliente",
    "danio": "Daño",
    "perdida": "Pérdida",
    "robo": "Robo",
    "reparacion": "En reparación",
    "desorden_sucio": "Desorden/sucio",
    "vencido": "Vencido",
    "no_apta_para_el_uso": "No apta para el uso",
    "no_asignado": "No asignado",
    "no_solicitado": "No solicitado",
    "otro": "Otro",
}

NON_IMPUTABLE_REASONS = {"danio", "reparacion", "robo"}
SUPERVISOR_RESPONSIBILITY_REASONS = {"no_asignado", "vencido", "no_apta_para_el_uso"}
SCORE_EXCLUDED_REASONS = NON_IMPUTABLE_REASONS | SUPERVISOR_RESPONSIBILITY_REASONS


def is_non_imputable_non_compliance(status, non_compliance_reason):
    if not status:
        return False
    normalized_status = str(status).strip().lower()
    normalized_reason = str(non_compliance_reason or "").strip().lower()
    return (
        normalized_status == "no_cumple" and normalized_reason in NON_IMPUTABLE_REASONS
    )



@main.app_template_filter("non_compliance_reason_label")
def non_compliance_reason_label(value):
    if value is None:
        return "-"
    raw = str(value).strip()
    if not raw:
        return "-"
    label = NON_COMPLIANCE_REASON_LABELS.get(raw.lower())
    if label:
        return label
    return raw.replace("_", " ").capitalize()


@main.app_template_filter("finding_status_label")
def finding_status_label(value):
    raw = (value or "").strip().lower()
    labels = {
        "nuevo": "Nuevo",
        "respondido": "En tratamiento",
        "resuelto": "CER-PVE",
        "cerrado_definitivo": "Cerrado definitivo",
        "reabierto": "Reabierto",
        "validado": "Validado",
    }
    return labels.get(raw) or (raw.replace("_", " ").capitalize() if raw else "-")


@main.app_template_filter("audit_photo_paths")
def audit_photo_paths(value, expires_in_seconds=900):
    if value is None:
        return []
    raw = str(value).strip()
    if not raw or raw == "-":
        return []
    if raw.startswith("[") and raw.endswith("]"):
        try:
            parsed = json.loads(raw)
        except Exception:
            parsed = [raw]
        if isinstance(parsed, list):
            items = [str(entry) for entry in parsed if entry]
        else:
            items = [raw]
    else:
        items = [raw]

    resolved = []
    for entry in items:
        candidate = (entry or "").strip()
        if not candidate:
            continue
        decoded = decode_cloudinary_ref(candidate)
        if decoded:
            signed = build_cloudinary_signed_url(
                candidate,
                expires_in_seconds=expires_in_seconds,
            )
            if signed:
                resolved.append(signed)
            continue
        resolved.append(candidate)
    return resolved



def current_user():
    if getattr(g, "_current_user_loaded", False):
        return getattr(g, "current_user", None)
    user_id = session.get("user_id")
    if not user_id:
        g._current_user_loaded = True
        g.current_user = None
        return None
        return None

    user = fetch_user_by_id(user_id)
    if not user or not user.get("is_active"):
        session.pop("user_id", None)
        g._current_user_loaded = True
        g.current_user = None
        return None

    g._current_user_loaded = True
    g.current_user = user
    return user


def is_admin():
    user = current_user()
    return bool(user and (user.get("role") == "admin"))


def is_gerente():
    user = current_user()
    return bool(user and (user.get("role") == "gerente"))


def is_auditor():
    user = current_user()
    return bool(user and (user.get("role") == "auditor"))


def is_supervisor():
    user = current_user()
    return bool(user and (user.get("role") == "supervisor"))


def can_import():
    user = current_user()
    return bool(user and (user.get("role") in {"admin", "auditor"}))


def can_create_audit():
    user = current_user()
    return bool(user and (user.get("role") in {"admin", "auditor"}))


def can_view_supply_requests():
    user = current_user()
    return bool(user and (user.get("role") in {"admin", "auditor", "gerente", "supervisor"}))


def can_create_supply_requests():
    user = current_user()
    return bool(user and (user.get("role") in {"admin", "auditor"}))


def can_view_all_audits():
    user = current_user()
    return bool(user and (user.get("role") in {"admin", "gerente"}))


def can_view_users():
    user = current_user()
    return bool(user and (user.get("role") == "admin"))


def can_create_users():
    user = current_user()
    return bool(user and (user.get("role") in {"admin", "gerente"}))


def can_edit_users():
    user = current_user()
    return bool(user and (user.get("role") == "admin"))


def can_view_reports():
    user = current_user()
    return bool(user and (user.get("role") in {"admin", "auditor", "gerente"}))


def can_manage_supervisor_scopes():
    user = current_user()
    return bool(user and (user.get("role") == "admin"))


def can_view_findings():
    user = current_user()
    return bool(user and (user.get("role") in {"admin", "gerente", "auditor", "supervisor"}))


def can_view_service():
    user = current_user()
    return bool(user and (user.get("role") in {"admin", "gerente", "auditor", "supervisor"}))


def can_respond_findings():
    user = current_user()
    return bool(user and (user.get("role") in {"admin", "supervisor"}))


def can_update_treatment_findings():
    user = current_user()
    return bool(user and (user.get("role") in {"supervisor", "auditor"}))


def can_validate_findings():
    user = current_user()
    return bool(user and (user.get("role") in {"admin", "gerente"}))


def can_verify_findings_effectiveness():
    user = current_user()
    return bool(user and (user.get("role") in {"admin", "gerente", "auditor"}))


def current_supervisor_scope_names():
    user = current_user()
    if not user or user.get("role") != "supervisor":
        return None
    return fetch_user_supervisor_scope_names(user["id"])


def current_auditor_user_id():
    user = current_user()
    return user["id"] if user and user.get("role") == "auditor" else None


def build_csv_response(rows, filename, fieldnames=None):
    normalized_rows = []
    for row in rows or []:
        normalized_rows.append({} if row is None else dict(row))

    if fieldnames is None:
        seen = set()
        ordered = []
        for row in normalized_rows:
            for key in row.keys():
                if key in seen:
                    continue
                seen.add(key)
                ordered.append(key)
        fieldnames = ordered

    buffer = io.StringIO()
    buffer.write("\ufeff")
    writer = csv.DictWriter(buffer, fieldnames=fieldnames, extrasaction="ignore")
    writer.writeheader()
    for row in normalized_rows:
        writer.writerow({key: row.get(key, "") for key in fieldnames})

    response = make_response(buffer.getvalue())
    response.headers["Content-Type"] = "text/csv; charset=utf-8"
    response.headers["Content-Disposition"] = f'attachment; filename="{filename}"'
    response.headers["Cache-Control"] = "no-store"
    return response


def build_pdf_response(rows, filename, title, columns):
    try:
        from reportlab.lib import colors
        from reportlab.lib.pagesizes import A4, landscape
        from reportlab.lib.styles import getSampleStyleSheet
        from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle
    except ImportError as exc:
        raise RuntimeError("PDF no disponible: falta dependencia reportlab.") from exc

    normalized_rows = []
    for row in rows or []:
        normalized_rows.append({} if row is None else dict(row))

    def to_text(value):
        if value is None:
            return ""
        return str(value)

    table_data = [[col.get("label", col["key"]) for col in columns]]
    for row in normalized_rows:
        table_data.append([to_text(row.get(col["key"])) for col in columns])

    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=landscape(A4),
        leftMargin=18,
        rightMargin=18,
        topMargin=18,
        bottomMargin=18,
        title=title,
    )

    styles = getSampleStyleSheet()
    story = [
        Paragraph(title, styles["Title"]),
        Spacer(1, 10),
    ]

    table = Table(table_data, repeatRows=1)
    table.setStyle(
        TableStyle(
            [
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, -1), 8),
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#F2F2F2")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.HexColor("#111111")),
                ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#D0D0D0")),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#FAFAFA")]),
            ]
        )
    )
    story.append(table)
    doc.build(story)

    pdf_bytes = buffer.getvalue()
    response = make_response(pdf_bytes)
    response.headers["Content-Type"] = "application/pdf"
    response.headers["Content-Disposition"] = f'attachment; filename="{filename}"'
    response.headers["Cache-Control"] = "no-store"
    return response


def build_pdf_from_html_response(html, filename):
    try:
        from playwright.sync_api import sync_playwright
    except ImportError as exc:
        raise RuntimeError(
            "PDF con estilos no disponible: falta dependencia playwright. "
            "Instala playwright y ejecuta: python -m playwright install chromium"
        ) from exc

    try:
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(
                headless=True,
                args=[
                    "--no-sandbox",
                    "--disable-setuid-sandbox",
                    "--disable-dev-shm-usage",
                ]
            )
            page = browser.new_page(viewport={"width": 794, "height": 1123})
            page.set_content(html, wait_until="domcontentloaded", timeout=60000)
            try:
                page.wait_for_load_state("networkidle", timeout=8000)
            except Exception:
                pass
            page.emulate_media(media="print")
            pdf_bytes = page.pdf(
                format="A4",
                print_background=True,
                prefer_css_page_size=True,
                margin={"top": "10mm", "right": "10mm", "bottom": "10mm", "left": "10mm"},
            )
            browser.close()
    except Exception as exc:
        raise RuntimeError(f"No fue posible generar el PDF (Playwright/Chromium): {type(exc).__name__}: {str(exc)[:220]}") from exc

    response = make_response(pdf_bytes)
    response.headers["Content-Type"] = "application/pdf"
    response.headers["Content-Disposition"] = f'attachment; filename="{filename}"'
    response.headers["Cache-Control"] = "no-store"
    return response


def build_audit_items_fallback_pdf(audit, items, filename, title_suffix="Detalle"):
    def status_label(value, reason=None):
        raw = (value or "").strip().lower()
        reason_raw = (reason or "").strip().lower()
        if raw == "cumple":
            return "Cumple"
        if raw == "conforme":
            return "Conforme"
        if raw == "no_cumple":
            if reason_raw in NON_IMPUTABLE_REASONS:
                return "No cumple (sin impacto)"
            if reason_raw in SUPERVISOR_RESPONSIBILITY_REASONS:
                return "No cumple (resp. supervisor)"
            return "No cumple"
        if raw == "nc_menor":
            return "No conformidad menor"
        if raw == "nc_mayor":
            return "No conformidad mayor"
        return "No aplica"

    normalized_items = []
    for item in items or []:
        row = {} if item is None else dict(item)
        photos = audit_photo_paths(row.get("photo_path"))
        normalized_items.append(
            {
                "section_title": row.get("section_title") or "-",
                "item_label": row.get("item_label") or "-",
                "status_label": status_label(row.get("status"), row.get("non_compliance_reason")),
                "critical_label": "Sí" if row.get("is_critical") else "No",
                "non_compliance_reason": non_compliance_reason_label(row.get("non_compliance_reason")),
                "notes": row.get("notes") or "-",
                "evidence_count": str(len(photos)) if photos else "0",
            }
        )

    title = f"Auditoría {audit.get('id')} - {title_suffix}"
    audit_meta = [
        {
            "section_title": "Meta",
            "item_label": f"Fecha: {audit.get('audit_date') or '-'} | Auditor: {audit.get('auditor_name') or '-'} | SA: {audit.get('sa_number') or '-'}",
            "status_label": "",
            "critical_label": "",
            "non_compliance_reason": "",
            "notes": f"Móvil: {audit.get('mobile_code') or '-'} | Técnico: {audit.get('technician_name') or '-'} | Legajo: {audit.get('employee_code') or '-'}",
            "evidence_count": "",
        },
        {
            "section_title": "Meta",
            "item_label": f"Resultado: {audit.get('result_status') or '-'} | Puntaje: {audit.get('total_score') or '-'}% | Ubicación: {audit.get('location') or '-'}",
            "status_label": "",
            "critical_label": "",
            "non_compliance_reason": "",
            "notes": f"Tipo: {audit.get('installation_type') or '-'} | Registro: {audit.get('created_at') or '-'}",
            "evidence_count": "",
        },
    ]
    rows = audit_meta + normalized_items
    columns = [
        {"key": "section_title", "label": "Sección"},
        {"key": "item_label", "label": "Ítem"},
        {"key": "status_label", "label": "Estado"},
        {"key": "critical_label", "label": "Crítico"},
        {"key": "non_compliance_reason", "label": "Motivo"},
        {"key": "notes", "label": "Notas"},
        {"key": "evidence_count", "label": "Evid."},
    ]
    return build_pdf_response(rows, filename, title, columns)


def build_reports_context(report_key, filters, auditor_user_id):
    title = ""
    subtitle = ""
    rows = []
    columns = []
    executive = None
    trend = None
    analysis = None

    title_filter = []
    if (filters.get("from_date") or "").strip():
        title_filter.append(f"Desde {filters['from_date']}")
    if (filters.get("to_date") or "").strip():
        title_filter.append(f"Hasta {filters['to_date']}")
    if (filters.get("status") or "").strip():
        title_filter.append(f"Estado {filters['status']}")
    if (filters.get("auditor") or "").strip():
        title_filter.append(f"Auditor {filters['auditor']}")
    if (filters.get("supervisor") or "").strip():
        title_filter.append(f"Supervisor {filters['supervisor']}")
    filter_suffix = " | ".join(title_filter)

    if report_key == "resumen":
        title = "Resumen ejecutivo"
        subtitle = "KPIs para gerencia con foco en estado general, criticidad y promedio."
        summary = fetch_audit_reports_management_summary(filters, auditor_user_id=auditor_user_id)
        rows = [summary]
        columns = [
            {"key": "total_audits", "label": "Auditorías"},
            {"key": "approved_count", "label": "Aprobadas"},
            {"key": "critical_count", "label": "Críticas"},
            {"key": "rejected_count", "label": "Rechazadas"},
            {"key": "approval_rate", "label": "Tasa aprobación %"},
            {"key": "average_score", "label": "Promedio"},
        ]

        status_rows = fetch_audit_reports_status_breakdown(filters, auditor_user_id=auditor_user_id)
        status_total = sum((row.get("audits_count") or 0) for row in status_rows)
        status_palette = {
            "Aprobada": "#16A34A",
            "Aprobada con observaciones": "#F59E0B",
            "Critica": "#DC2626",
            "Rechazada": "#6B7280",
        }

        circumference = round(2 * 3.1416 * 54, 2)
        approval_value = max(0, min(100, summary.get("approval_rate") or 0))
        approval_ring = {
            "circumference": circumference,
            "offset": round(circumference * (1 - (approval_value / 100)), 2),
            "value": approval_value,
        }

        donut_segments = []
        offset_accum = 0.0
        for row in status_rows:
            count = row.get("audits_count") or 0
            label = row.get("result_status") or "-"
            percent = 0.0 if status_total == 0 else round((count / status_total) * 100, 1)
            segment_len = 0.0 if percent == 0 else round(circumference * (percent / 100), 2)
            donut_segments.append(
                {
                    "label": label,
                    "count": count,
                    "percent": percent,
                    "color": status_palette.get(label, "#2563EB"),
                    "dasharray": f"{segment_len} {round(circumference - segment_len, 2)}",
                    "dashoffset": round(-offset_accum, 2),
                }
            )
            offset_accum += segment_len

        section_rows = fetch_audit_reports_section_breakdown(filters, auditor_user_id=auditor_user_id)
        top_sections = section_rows[:6]
        section_max = max([row.get("non_compliant_count") or 0 for row in top_sections] + [1])
        for row in top_sections:
            row["bar_percent"] = round(((row.get("non_compliant_count") or 0) / section_max) * 100)

        supplies_rows = fetch_audit_reports_supply_requests_summary(filters, auditor_user_id=auditor_user_id)
        top_supplies = supplies_rows[:6]
        supplies_max = max([row.get("total_quantity") or 0 for row in top_supplies] + [1])
        for row in top_supplies:
            row["bar_percent"] = round(((row.get("total_quantity") or 0) / supplies_max) * 100)

        total_audits = summary.get("total_audits") or 0
        approval_rate = summary.get("approval_rate") or 0
        critical_count = summary.get("critical_count") or 0
        rejected_count = summary.get("rejected_count") or 0
        if total_audits == 0:
            health = {"class": "status-warning", "label": "Sin datos"}
        elif rejected_count > 0 or approval_rate < 70:
            health = {"class": "status-danger", "label": "Crítico"}
        elif critical_count > 0 or approval_rate < 85:
            health = {"class": "status-warning", "label": "En riesgo"}
        else:
            health = {"class": "status-ok", "label": "OK"}

        trend_weekly = fetch_audit_reports_time_series(filters, auditor_user_id=auditor_user_id, granularity="week", limit=8)
        target_approval_rate = current_app.config.get("REPORT_TARGET_APPROVAL_RATE", 85)
        target_average_score = current_app.config.get("REPORT_TARGET_AVERAGE_SCORE", 95.0)
        try:
            target_approval_rate = int(target_approval_rate)
        except (TypeError, ValueError):
            target_approval_rate = 85
        try:
            target_average_score = float(target_average_score)
        except (TypeError, ValueError):
            target_average_score = 95.0

        trend_phrase = ""
        if trend_weekly and len(trend_weekly) > 1:
            latest = trend_weekly[0]
            previous = trend_weekly[1]
            if (latest.get("audits_count") or 0) > 0 and (previous.get("audits_count") or 0) > 0:
                delta_pp = int((latest.get("approval_rate") or 0) - (previous.get("approval_rate") or 0))
                delta_sign = "+" if delta_pp > 0 else ""
                trend_phrase = f" vs semana anterior: {delta_sign}{delta_pp} pp"

        hallazgo_value = "Sin auditorías en el período seleccionado."
        if total_audits > 0:
            hallazgo_value = (
                f"Tasa aprobación {approval_rate}% (meta {target_approval_rate}%). "
                f"Promedio {summary.get('average_score')} (meta {target_average_score}). "
                f"Críticas {critical_count}, rechazadas {rejected_count}."
                f"{trend_phrase}"
            )

        top_section = top_sections[0] if top_sections else None
        riesgo_value = "Sin datos de no conformidades por sección."
        if top_section:
            riesgo_value = (
                f"Sección con más no conformidades: {top_section.get('section_title') or '-' } "
                f"({top_section.get('non_compliant_count') or 0} NC, {top_section.get('critical_non_compliant_count') or 0} críticas)."
            )

        top_supply = top_supplies[0] if top_supplies else None
        action_parts = []
        if top_section:
            action_parts.append(f"Plan de acción en {top_section.get('section_title') or '-'}: repasar estándar y reforzar control en terreno.")
        if top_supply:
            action_parts.append(
                f"Priorizar abastecimiento: {str(top_supply.get('request_type') or '').capitalize()} {top_supply.get('material_code') or '-'} "
                f"(total {top_supply.get('total_quantity') or 0})."
            )
        if not action_parts:
            action_parts.append("Mantener monitoreo semanal y ajustar foco según próximos hallazgos.")
        accion_value = " ".join(action_parts)

        insights = [
            {"label": "Hallazgo clave", "value": hallazgo_value},
            {"label": "Riesgo principal", "value": riesgo_value},
            {"label": "Acción sugerida", "value": accion_value},
        ]
        supervisor_rows = fetch_audit_reports_supervisor_breakdown(filters, auditor_user_id=auditor_user_id, limit=200)
        supervisor_focus = [row for row in supervisor_rows if (row.get("supervisor_name") or "") != "Sin supervisor"]
        if not supervisor_focus:
            supervisor_focus = list(supervisor_rows)
        supervisor_focus = sorted(
            supervisor_focus,
            key=lambda row: (
                -(row.get("risk_index") or 0),
                -(row.get("critical_count") or 0),
                -(row.get("rejected_count") or 0),
                -(row.get("audits_count") or 0),
                str(row.get("supervisor_name") or ""),
            ),
        )
        top_supervisors = supervisor_focus[:10]
        executive = {
            "approval_ring": approval_ring,
            "donut_segments": donut_segments,
            "status_total": status_total,
            "top_sections": top_sections,
            "top_supplies": top_supplies,
            "top_supervisors": top_supervisors,
            "health": health,
            "trend_weekly": trend_weekly,
            "insights": insights,
        }
    elif report_key == "estados":
        title = "Desglose por estado"
        subtitle = "Cantidad de auditorías y score promedio por estado."
        rows = fetch_audit_reports_status_breakdown(filters, auditor_user_id=auditor_user_id)
        columns = [
            {"key": "result_status", "label": "Estado"},
            {"key": "audits_count", "label": "Cantidad"},
            {"key": "average_score", "label": "Promedio"},
        ]
    elif report_key == "secciones":
        title = "Desglose por sección"
        subtitle = "Cumplimiento y no conformidades agrupadas por sección."
        rows = fetch_audit_reports_section_breakdown(filters, auditor_user_id=auditor_user_id)
        columns = [
            {"key": "section_title", "label": "Sección"},
            {"key": "compliant_count", "label": "Cumple"},
            {"key": "non_compliant_count", "label": "No conformes"},
            {"key": "critical_non_compliant_count", "label": "Críticas"},
            {"key": "not_applicable_count", "label": "No aplica"},
        ]
    elif report_key == "supervisores":
        title = "Desglose por supervisor"
        subtitle = "Auditorías, criticidad y promedio por supervisor."
        rows = fetch_audit_reports_supervisor_breakdown(filters, auditor_user_id=auditor_user_id)
        columns = [
            {"key": "supervisor_name", "label": "Supervisor"},
            {"key": "audits_count", "label": "Auditorías"},
            {"key": "approved_count", "label": "Aprobadas"},
            {"key": "critical_count", "label": "Críticas"},
            {"key": "rejected_count", "label": "Rechazadas"},
            {"key": "approval_rate", "label": "Tasa aprobación %"},
            {"key": "critical_rate", "label": "Tasa críticas %"},
            {"key": "rejected_rate", "label": "Tasa rechazo %"},
            {"key": "no_asignado_audits", "label": "Auditorías con No asignado"},
            {"key": "no_asignado_rate", "label": "Tasa No asignado %"},
            {"key": "vencido_audits", "label": "Auditorías con Vencido"},
            {"key": "vencido_rate", "label": "Tasa Vencido %"},
            {"key": "no_apta_audits", "label": "Auditorías con No apta para el uso"},
            {"key": "no_apta_rate", "label": "Tasa No apta %"},
            {"key": "risk_index", "label": "Índice riesgo"},
            {"key": "average_score", "label": "Promedio"},
            {"key": "last_audit_date", "label": "Última auditoría"},
        ]

        def safe_float(value, default=0.0):
            try:
                return float(value)
            except (TypeError, ValueError):
                return float(default)

        def safe_int(value, default=0):
            try:
                return int(value)
            except (TypeError, ValueError):
                return int(default)

        def median(values):
            values = sorted(values)
            if not values:
                return 0
            mid = len(values) // 2
            if len(values) % 2 == 1:
                return values[mid]
            return (values[mid - 1] + values[mid]) / 2

        def std(values):
            if not values:
                return 0.0
            mean_value = sum(values) / len(values)
            return (sum((value - mean_value) ** 2 for value in values) / len(values)) ** 0.5

        normalized_rows = [dict(row) for row in (rows or [])]
        focus_rows = [
            row
            for row in normalized_rows
            if (row.get("supervisor_name") or "").strip() and (row.get("supervisor_name") or "") != "Sin supervisor"
        ]
        if not focus_rows:
            focus_rows = list(normalized_rows)

        total_audits = sum(safe_int(row.get("audits_count")) for row in focus_rows)
        total_approved = sum(safe_int(row.get("approved_count")) for row in focus_rows)
        weighted_approval_rate = 0 if total_audits == 0 else round((total_approved / total_audits) * 100)
        weighted_average_score = 0 if total_audits == 0 else round(
            sum(safe_float(row.get("average_score")) * safe_int(row.get("audits_count")) for row in focus_rows) / total_audits, 2
        )

        approval_values = [safe_float(row.get("approval_rate")) for row in focus_rows]
        average_values = [safe_float(row.get("average_score")) for row in focus_rows]
        risk_values = [safe_float(row.get("risk_index")) for row in focus_rows]

        def distribution(values, round_to=2):
            if not values:
                return {"mean": 0, "median": 0, "std": 0, "min": 0, "max": 0}
            mean_value = sum(values) / len(values)
            median_value = median(values)
            std_value = std(values)
            return {
                "mean": round(mean_value, round_to),
                "median": round(median_value, round_to),
                "std": round(std_value, round_to),
                "min": round(min(values), round_to),
                "max": round(max(values), round_to),
            }

        min_audits_threshold = current_app.config.get("REPORT_SUPERVISOR_MIN_AUDITS", 5)
        min_audits_threshold = safe_int(min_audits_threshold, default=5)
        if min_audits_threshold < 1:
            min_audits_threshold = 1

        low_approval_count = sum(
            1
            for row in focus_rows
            if safe_int(row.get("audits_count")) >= min_audits_threshold and safe_float(row.get("approval_rate")) < 70
        )

        def to_analysis_row(row):
            return {
                "supervisor_name": (row.get("supervisor_name") or "").strip() or "-",
                "audits_count": safe_int(row.get("audits_count")),
                "approval_rate": safe_int(row.get("approval_rate")),
                "risk_index": round(safe_float(row.get("risk_index")), 2),
                "average_score": round(safe_float(row.get("average_score")), 2),
            }

        top_risk = sorted(
            focus_rows,
            key=lambda row: (
                -safe_float(row.get("risk_index")),
                -safe_int(row.get("audits_count")),
                safe_float(row.get("approval_rate")),
                str(row.get("supervisor_name") or ""),
            ),
        )[:5]

        analysis = {
            "counts": {"supervisors": len(focus_rows), "audits": int(total_audits)},
            "weighted": {"approval_rate": int(weighted_approval_rate), "average_score": weighted_average_score},
            "distribution": {
                "approval_rate": distribution(approval_values, round_to=1),
                "average_score": distribution(average_values, round_to=2),
                "risk_index": distribution(risk_values, round_to=2),
            },
            "top_risk": [to_analysis_row(row) for row in top_risk],
            "thresholds": {"min_audits": int(min_audits_threshold)},
            "flags": {"low_approval_count": int(low_approval_count)},
        }
    elif report_key == "centros":
        title = "Desglose por centro"
        subtitle = "Auditorías, criticidad y promedio por centro."
        rows = fetch_audit_reports_center_breakdown(filters, auditor_user_id=auditor_user_id)
        columns = [
            {"key": "center_name", "label": "Centro"},
            {"key": "audits_count", "label": "Auditorías"},
            {"key": "critical_count", "label": "Críticas"},
            {"key": "rejected_count", "label": "Rechazadas"},
            {"key": "approval_rate", "label": "Tasa aprobación %"},
            {"key": "average_score", "label": "Promedio"},
            {"key": "last_audit_date", "label": "Última auditoría"},
        ]
    elif report_key == "empresas":
        title = "Desglose por empresa"
        subtitle = "Auditorías, criticidad y promedio por empresa."
        rows = fetch_audit_reports_company_breakdown(filters, auditor_user_id=auditor_user_id)
        columns = [
            {"key": "company_name", "label": "Empresa"},
            {"key": "audits_count", "label": "Auditorías"},
            {"key": "critical_count", "label": "Críticas"},
            {"key": "rejected_count", "label": "Rechazadas"},
            {"key": "approval_rate", "label": "Tasa aprobación %"},
            {"key": "average_score", "label": "Promedio"},
            {"key": "last_audit_date", "label": "Última auditoría"},
        ]
    elif report_key == "ranking_tecnicos":
        title = "Ranking de técnicos"
        subtitle = "Ordenado por criticidad y volumen de auditorías."
        rows = fetch_audit_reports_technician_ranking(filters, auditor_user_id=auditor_user_id)
        columns = [
            {"key": "technician_name", "label": "Técnico"},
            {"key": "technician_employee_code", "label": "Legajo"},
            {"key": "supervisor_name", "label": "Supervisor"},
            {"key": "center_name", "label": "Centro"},
            {"key": "company_name", "label": "Empresa"},
            {"key": "audits_count", "label": "Auditorías"},
            {"key": "critical_count", "label": "Críticas"},
            {"key": "rejected_count", "label": "Rechazadas"},
            {"key": "approval_rate", "label": "Tasa aprobación %"},
            {"key": "average_score", "label": "Promedio"},
            {"key": "last_audit_date", "label": "Última auditoría"},
        ]
    elif report_key == "ranking_moviles":
        title = "Ranking de móviles"
        subtitle = "Ordenado por criticidad y volumen de auditorías."
        rows = fetch_audit_reports_mobile_ranking(filters, auditor_user_id=auditor_user_id)
        columns = [
            {"key": "mobile_code", "label": "Móvil"},
            {"key": "audits_count", "label": "Auditorías"},
            {"key": "critical_count", "label": "Críticas"},
            {"key": "rejected_count", "label": "Rechazadas"},
            {"key": "approval_rate", "label": "Tasa aprobación %"},
            {"key": "average_score", "label": "Promedio"},
            {"key": "last_audit_date", "label": "Última auditoría"},
        ]
    elif report_key == "tendencia_mensual":
        title = "Tendencia mensual"
        subtitle = "Evolución por mes de auditorías, criticidad, tasa de aprobación y promedio."
        rows = fetch_audit_reports_time_series(filters, auditor_user_id=auditor_user_id, granularity="month", limit=60)
        columns = [
            {"key": "period_key", "label": "Mes"},
            {"key": "audits_count", "label": "Auditorías"},
            {"key": "approved_count", "label": "Aprobadas"},
            {"key": "critical_count", "label": "Críticas"},
            {"key": "rejected_count", "label": "Rechazadas"},
            {"key": "approval_rate", "label": "Tasa aprobación %"},
            {"key": "average_score", "label": "Promedio"},
        ]
    elif report_key == "tendencia_semanal":
        title = "Tendencia semanal"
        subtitle = "Evolución por semana de auditorías, criticidad, tasa de aprobación y promedio."
        rows = fetch_audit_reports_time_series(filters, auditor_user_id=auditor_user_id, granularity="week", limit=80)
        columns = [
            {"key": "period_key", "label": "Semana"},
            {"key": "audits_count", "label": "Auditorías"},
            {"key": "approved_count", "label": "Aprobadas"},
            {"key": "critical_count", "label": "Críticas"},
            {"key": "rejected_count", "label": "Rechazadas"},
            {"key": "approval_rate", "label": "Tasa aprobación %"},
            {"key": "average_score", "label": "Promedio"},
        ]

        latest = rows[0] if rows else None
        previous = rows[1] if rows and len(rows) > 1 else None

        approval_target = current_app.config.get("REPORT_TARGET_APPROVAL_RATE", 85)
        average_target = current_app.config.get("REPORT_TARGET_AVERAGE_SCORE", 95.0)
        try:
            approval_target = int(approval_target)
        except (TypeError, ValueError):
            approval_target = 85
        try:
            average_target = float(average_target)
        except (TypeError, ValueError):
            average_target = 95.0

        approval_warning = max(0, int(approval_target) - 15)
        average_warning = float(average_target) - 5.0

        delta = {
            "audits_count": None,
            "approval_rate_pp": None,
            "average_score": None,
            "critical_count": None,
            "rejected_count": None,
        }
        if latest and previous:
            delta["audits_count"] = int((latest.get("audits_count") or 0) - (previous.get("audits_count") or 0))
            delta["approval_rate_pp"] = int((latest.get("approval_rate") or 0) - (previous.get("approval_rate") or 0))
            delta["average_score"] = round((latest.get("average_score") or 0) - (previous.get("average_score") or 0), 2)
            delta["critical_count"] = int((latest.get("critical_count") or 0) - (previous.get("critical_count") or 0))
            delta["rejected_count"] = int((latest.get("rejected_count") or 0) - (previous.get("rejected_count") or 0))

        def metric_class(value, ok_threshold, warning_threshold):
            if value is None:
                return "metric-neutral"
            try:
                numeric = float(value)
            except (TypeError, ValueError):
                return "metric-neutral"
            if numeric >= ok_threshold:
                return "metric-ok"
            if numeric >= warning_threshold:
                return "metric-warning"
            return "metric-danger"

        latest_metrics = None
        if latest:
            latest_metrics = {
                **latest,
                "approval_class": metric_class(latest.get("approval_rate"), approval_target, approval_warning),
                "average_class": metric_class(latest.get("average_score"), average_target, average_warning),
            }

        def aggregate_time_series(period_rows):
            total = sum((row.get("audits_count") or 0) for row in period_rows)
            approved = sum((row.get("approved_count") or 0) for row in period_rows)
            critical = sum((row.get("critical_count") or 0) for row in period_rows)
            rejected = sum((row.get("rejected_count") or 0) for row in period_rows)
            weighted_sum = sum(((row.get("average_score") or 0) * (row.get("audits_count") or 0)) for row in period_rows)
            approval_rate = 0 if total == 0 else round((approved / total) * 100)
            average_score = 0 if total == 0 else round((weighted_sum / total), 2)
            return {
                "audits_count": int(total),
                "approved_count": int(approved),
                "critical_count": int(critical),
                "rejected_count": int(rejected),
                "approval_rate": int(approval_rate),
                "average_score": average_score,
            }

        last4_rows = rows[:4]
        prev4_rows = rows[4:8]
        compare_last4 = aggregate_time_series(last4_rows) if last4_rows else None
        compare_prev4 = aggregate_time_series(prev4_rows) if prev4_rows else None

        compare_delta = None
        if compare_last4 and compare_prev4:
            compare_delta = {
                "audits_count": compare_last4["audits_count"] - compare_prev4["audits_count"],
                "approval_rate_pp": compare_last4["approval_rate"] - compare_prev4["approval_rate"],
                "average_score": round(compare_last4["average_score"] - compare_prev4["average_score"], 2),
                "critical_count": compare_last4["critical_count"] - compare_prev4["critical_count"],
                "rejected_count": compare_last4["rejected_count"] - compare_prev4["rejected_count"],
            }

        insights = []
        if latest_metrics:
            d_pp = delta.get("approval_rate_pp")
            d_pp_str = f"{'+' if d_pp and d_pp > 0 else ''}{d_pp} pp" if d_pp is not None else "-"
            d_avg = delta.get("average_score")
            d_avg_str = f"{'+' if d_avg and d_avg > 0 else ''}{d_avg}" if d_avg is not None else "-"
            insights.append(
                {
                    "label": "Última semana",
                    "value": (
                        f"{latest_metrics.get('period_key')}: aprobación {latest_metrics.get('approval_rate')}% "
                        f"({d_pp_str} vs anterior), promedio {latest_metrics.get('average_score')} ({d_avg_str} vs anterior)."
                    ),
                }
            )
            insights.append(
                {
                    "label": "Metas",
                    "value": f"Aprobación ≥ {approval_target}% | Promedio ≥ {round(average_target, 2)}.",
                }
            )

        if compare_last4 and compare_prev4 and compare_delta:
            delta_pp = compare_delta.get("approval_rate_pp")
            delta_pp_str = f"{'+' if delta_pp and delta_pp > 0 else ''}{delta_pp} pp"
            delta_avg = compare_delta.get("average_score")
            delta_avg_str = f"{'+' if delta_avg and delta_avg > 0 else ''}{delta_avg}"
            delta_audits = compare_delta.get("audits_count")
            delta_audits_str = f"{'+' if delta_audits and delta_audits > 0 else ''}{delta_audits}"
            insights.append(
                {
                    "label": "Últimas 4 vs 4 anteriores",
                    "value": (
                        f"Aprobación {compare_last4.get('approval_rate')}% ({delta_pp_str}), "
                        f"promedio {compare_last4.get('average_score')} ({delta_avg_str}), "
                        f"auditorías {compare_last4.get('audits_count')} ({delta_audits_str})."
                    ),
                }
            )

        action_value = ""
        if compare_last4:
            rejected = compare_last4.get("rejected_count") or 0
            critical = compare_last4.get("critical_count") or 0
            if rejected > 0:
                action_value = "Priorizar análisis de rechazos (causas recurrentes, refuerzo de control y evidencias)."
            elif critical > 0:
                action_value = "Foco en cierre de críticas: checklist específico y validación en terreno."
            else:
                action_value = "Mantener monitoreo semanal y sostener buenas prácticas."
        if action_value:
            insights.append({"label": "Acción sugerida", "value": action_value})

        chart_rows = list(reversed(rows[:12]))
        max_audits = max([row.get("audits_count") or 0 for row in chart_rows] + [1])
        plot_left = 60
        plot_right = 760
        plot_top = 24
        plot_bottom = 180
        plot_width = plot_right - plot_left
        plot_height = plot_bottom - plot_top

        points = []
        n = len(chart_rows)
        for idx, row in enumerate(chart_rows):
            if n > 1:
                x = plot_left + (plot_width * (idx / (n - 1)))
            else:
                x = plot_left + (plot_width / 2)

            approval_rate = max(0, min(100, row.get("approval_rate") or 0))
            y = plot_bottom - ((approval_rate / 100) * plot_height)

            audits = row.get("audits_count") or 0
            bar_h = 0 if max_audits == 0 else (audits / max_audits) * plot_height
            bar_y = plot_bottom - bar_h

            points.append(
                {
                    "period_key": row.get("period_key"),
                    "period_start": row.get("period_start"),
                    "audits_count": audits,
                    "approval_rate": approval_rate,
                    "x": round(x, 2),
                    "y": round(y, 2),
                    "bar_y": round(bar_y, 2),
                    "bar_h": round(bar_h, 2),
                }
            )

        polyline = " ".join([f"{p['x']},{p['y']}" for p in points])
        trend = {
            "latest": latest_metrics,
            "previous": previous,
            "delta": delta,
            "targets": {
                "approval_rate": approval_target,
                "average_score": round(average_target, 2),
                "approval_warning": approval_warning,
                "average_warning": round(average_warning, 2),
            },
            "insights": insights,
            "compare": {
                "last4": compare_last4,
                "prev4": compare_prev4,
                "delta": compare_delta,
            },
            "chart": {
                "points": points,
                "polyline": polyline,
                "max_audits": max_audits,
                "plot": {
                    "left": plot_left,
                    "right": plot_right,
                    "top": plot_top,
                    "bottom": plot_bottom,
                },
            },
        }
    elif report_key == "hallazgos_criticos":
        title = "Hallazgos críticos"
        subtitle = "Ítems críticos no conformes con contexto de auditoría."
        rows = fetch_audit_reports_critical_findings(filters, auditor_user_id=auditor_user_id)
        columns = [
            {"key": "audit_date", "label": "Fecha"},
            {"key": "audit_id", "label": "ID"},
            {"key": "mobile_code", "label": "Móvil"},
            {"key": "technician_name", "label": "Técnico"},
            {"key": "vehicle_plate", "label": "Vehículo"},
            {"key": "location", "label": "Ubicación"},
            {"key": "result_status", "label": "Resultado"},
            {"key": "total_score", "label": "Score"},
            {"key": "section_title", "label": "Sección"},
            {"key": "item_label", "label": "Ítem"},
            {"key": "status", "label": "Estado ítem"},
            {"key": "non_compliance_reason", "label": "Motivo"},
            {"key": "notes", "label": "Notas"},
        ]
    elif report_key == "evidencias_faltantes":
        title = "Evidencias faltantes"
        subtitle = "No conformidades sin evidencia fotográfica (según reglas actuales)."
        rows = fetch_audit_reports_missing_evidence(filters, auditor_user_id=auditor_user_id)
        columns = [
            {"key": "audit_date", "label": "Fecha"},
            {"key": "audit_id", "label": "ID"},
            {"key": "mobile_code", "label": "Móvil"},
            {"key": "technician_name", "label": "Técnico"},
            {"key": "vehicle_plate", "label": "Vehículo"},
            {"key": "location", "label": "Ubicación"},
            {"key": "section_title", "label": "Sección"},
            {"key": "item_label", "label": "Ítem"},
            {"key": "non_compliance_reason", "label": "Motivo"},
            {"key": "notes", "label": "Notas"},
        ]
    elif report_key == "responsabilidad_supervisor":
        title = "Responsabilidad supervisor (detalle)"
        subtitle = "Ítems No cumple con motivo No asignado / Vencido / No apta para el uso."
        rows = fetch_audit_reports_supervisor_responsibility_detail(filters, auditor_user_id=auditor_user_id)
        columns = [
            {"key": "audit_date", "label": "Fecha"},
            {"key": "audit_id", "label": "ID"},
            {"key": "supervisor_name", "label": "Supervisor"},
            {"key": "technician_name", "label": "Técnico"},
            {"key": "technician_employee_code", "label": "Legajo"},
            {"key": "mobile_code", "label": "Móvil"},
            {"key": "vehicle_plate", "label": "Vehículo"},
            {"key": "location", "label": "Ubicación"},
            {"key": "result_status", "label": "Resultado"},
            {"key": "total_score", "label": "Score"},
            {"key": "section_title", "label": "Sección"},
            {"key": "item_label", "label": "Ítem"},
            {"key": "non_compliance_reason", "label": "Motivo"},
            {"key": "notes", "label": "Notas"},
        ]
    elif report_key == "insumos_detalle":
        title = "Solicitudes de insumos (detalle)"
        subtitle = "Listado completo de solicitudes por auditoría."
        rows = fetch_audit_reports_supply_requests_detail(filters, auditor_user_id=auditor_user_id)
        columns = [
            {"key": "audit_date", "label": "Fecha"},
            {"key": "audit_id", "label": "ID"},
            {"key": "mobile_code", "label": "Móvil"},
            {"key": "technician_name", "label": "Técnico"},
            {"key": "request_type", "label": "Tipo"},
            {"key": "material_code", "label": "Material"},
            {"key": "quantity", "label": "Cantidad"},
            {"key": "section_title", "label": "Sección"},
            {"key": "item_label", "label": "Ítem"},
            {"key": "notes", "label": "Notas"},
        ]
    elif report_key == "insumos_resumen":
        title = "Solicitudes de insumos (consolidado)"
        subtitle = "Totales por material y tipo de solicitud."
        rows = fetch_audit_reports_supply_requests_summary(filters, auditor_user_id=auditor_user_id)
        columns = [
            {"key": "request_type", "label": "Tipo"},
            {"key": "material_code", "label": "Material"},
            {"key": "requests_count", "label": "Solicitudes"},
            {"key": "total_quantity", "label": "Total"},
        ]
    else:
        return None

    return {
        "report_key": report_key,
        "title": title,
        "subtitle": subtitle,
        "filter_suffix": filter_suffix,
        "filters": filters,
        "columns": columns,
        "rows": rows,
        "summary": rows[0] if report_key == "resumen" and rows else None,
        "executive": executive if report_key == "resumen" else None,
        "trend": trend,
        "analysis": analysis,
    }


def safe_next_url(value):
    raw = (value or "").strip()
    if raw.startswith("/"):
        return raw
    return None


@main.before_app_request
def require_login():
    endpoint = request.endpoint or ""
    if endpoint.startswith("static"):
        return None

    if endpoint in {"main.login", "main.logout", "main.setup"}:
        return None

    if count_users() == 0:
        return redirect(url_for("main.setup"))

    if not current_user():
        next_url = safe_next_url(request.full_path if request.query_string else request.path)
        return redirect(url_for("main.login", next=next_url))

    return None


@main.app_context_processor
def inject_auth_context():
    user = current_user()
    show_findings_alerts_modal = False
    findings_alerts_modal_stats = None
    findings_alerts_modal_urls = None
    if user and user.get("role") in {"supervisor", "auditor"} and can_view_findings():
        now = int(time.time())
        next_show_raw = session.get("findings_alerts_next_show_at")
        next_show_at = 0
        try:
            next_show_at = int(next_show_raw) if next_show_raw is not None else 0
        except (TypeError, ValueError):
            next_show_at = 0
        if now >= next_show_at:
            try:
                stats = fetch_finding_stats(
                    None,
                    auditor_user_id=current_auditor_user_id(),
                    supervisor_scope_names=current_supervisor_scope_names(),
                )
            except Exception:
                current_app.logger.exception("Error al calcular estadísticas de alertas de hallazgos")
                session["findings_alerts_next_show_at"] = now + (15 * 60)
                stats = {}
            has_alerts = any(
                (
                    stats.get("reopened_count"),
                    stats.get("escalated_treatment_count"),
                    stats.get("stale_treatment_count"),
                    stats.get("overdue_validation_count"),
                    stats.get("overdue_effectiveness_count"),
                )
            )
            if has_alerts:
                show_findings_alerts_modal = True
                findings_alerts_modal_stats = stats
                findings_alerts_modal_urls = {
                    "reopened": url_for("main.findings_list", quick_filter="reopened", page=1),
                    "escalated_treatment": url_for("main.findings_list", quick_filter="escalated_treatment", page=1),
                    "stale_treatment": url_for("main.findings_list", quick_filter="stale_treatment", page=1),
                    "overdue_validation": url_for("main.findings_list", quick_filter="overdue_validation", page=1),
                    "overdue_effectiveness": url_for("main.findings_list", quick_filter="overdue_effectiveness", page=1),
                }
            else:
                session["findings_alerts_next_show_at"] = now + (15 * 60)

    return {
        "current_user": user,
        "csrf_token": csrf_token(),
        "is_admin": bool(user and (user.get("role") == "admin")),
        "is_gerente": bool(user and (user.get("role") == "gerente")),
        "is_auditor": bool(user and (user.get("role") == "auditor")),
        "is_supervisor": bool(user and (user.get("role") == "supervisor")),
        "show_findings_alerts_modal": show_findings_alerts_modal,
        "findings_alerts_modal_stats": findings_alerts_modal_stats,
        "findings_alerts_modal_urls": findings_alerts_modal_urls,
        "can_import": can_import(),
        "can_create_audit": can_create_audit(),
        "can_view_supply_requests": can_view_supply_requests(),
        "can_create_supply_requests": can_create_supply_requests(),
        "can_view_all_audits": can_view_all_audits(),
        "can_view_users": can_view_users(),
        "can_create_users": can_create_users(),
        "can_edit_users": can_edit_users(),
        "can_view_reports": can_view_reports(),
        "can_manage_supervisor_scopes": can_manage_supervisor_scopes(),
        "can_view_findings": can_view_findings(),
        "can_view_service": can_view_service(),
        "can_respond_findings": can_respond_findings(),
        "can_update_treatment_findings": can_update_treatment_findings(),
        "can_validate_findings": can_validate_findings(),
        "can_verify_findings_effectiveness": can_verify_findings_effectiveness(),
    }


@main.route("/setup", methods=["GET", "POST"])
def setup():
    if count_users() > 0:
        return redirect(url_for("main.login"))

    if request.method == "POST":
        try:
            username = (request.form.get("username") or "").strip()
            password = (request.form.get("password") or "").strip()
            confirm = (request.form.get("confirm_password") or "").strip()

            if not username:
                raise ValueError("Debes ingresar un usuario.")
            if len(password) < 8:
                raise ValueError("La contraseña debe tener al menos 8 caracteres.")
            if password != confirm:
                raise ValueError("Las contraseñas no coinciden.")

            create_user(username=username, password=password, role="admin", is_active=1)
            flash("Usuario administrador creado. Ya puedes iniciar sesión.", "success")
            return redirect(url_for("main.login"))
        except ValueError as exc:
            flash(str(exc), "error")

    return render_template("setup.html")


@main.route("/login", methods=["GET", "POST"])
def login():
    if count_users() == 0:
        return redirect(url_for("main.setup"))

    if current_user():
        return redirect(url_for("main.dashboard"))

    next_url = safe_next_url(request.args.get("next"))

    if request.method == "POST":
        if not validate_csrf_token(request.form.get("csrf_token")):
            flash("La sesión del formulario expiró. Recarga e intenta nuevamente.", "error")
            return render_template("login.html", next=next_url), 400

        username = (request.form.get("username") or "").strip()
        password = (request.form.get("password") or "").strip()
        next_url = safe_next_url(request.form.get("next")) or next_url

        ip = client_ip()
        if is_login_rate_limited(ip, username):
            flash("Demasiados intentos. Espera unos minutos e intenta nuevamente.", "error")
            return render_template("login.html", next=next_url), 429

        user = fetch_user_by_username(username)
        if not user or not user.get("is_active"):
            record_login_failure(ip, username)
            flash("Usuario o contraseña incorrectos.", "error")
            return render_template("login.html", next=next_url)

        if not check_password_hash(user["password_hash"], password):
            record_login_failure(ip, username)
            flash("Usuario o contraseña incorrectos.", "error")
            return render_template("login.html", next=next_url)

        clear_login_failures(ip, username)
        session.clear()
        session.permanent = True
        session["user_id"] = user["id"]
        session["findings_alerts_next_show_at"] = 0
        return redirect(next_url or url_for("main.dashboard"))

    return render_template("login.html", next=next_url)


@main.route("/api/ping")
def api_ping():
    if not current_user():
        return jsonify({"error": "unauthorized"}), 401
    return jsonify({"ok": True})


@main.route("/logout", methods=["POST"])
def logout():
    if not validate_csrf_token(request.form.get("csrf_token")):
        abort(400)
    session.clear()
    return redirect(url_for("main.login"))


@main.route("/users")
def users_list():
    if not can_view_users():
        abort(403)
    return render_template("users.html", users=fetch_users())


@main.route("/users/new", methods=["GET", "POST"])
def users_new():
    if not can_create_users():
        abort(403)

    if request.method == "POST":
        try:
            actor = current_user()
            username = (request.form.get("username") or "").strip()
            password = (request.form.get("password") or "").strip()
            confirm = (request.form.get("confirm_password") or "").strip()
            role = (request.form.get("role") or "auditor").strip().lower()
            is_active = (request.form.get("is_active") or "1").strip() == "1"

            if not username:
                raise ValueError("Debes ingresar un usuario.")
            if len(password) < 8:
                raise ValueError("La contraseña debe tener al menos 8 caracteres.")
            if password != confirm:
                raise ValueError("Las contraseñas no coinciden.")
            if actor and actor.get("role") == "gerente":
                if role != "auditor":
                    raise ValueError("El gerente solo puede crear usuarios de tipo auditor.")
            else:
                if role not in {"admin", "auditor", "gerente", "supervisor"}:
                    raise ValueError("El rol seleccionado no es válido.")

            user_id = create_user(username=username, password=password, role=role, is_active=1 if is_active else 0)
            flash("Usuario creado.", "success")
            if actor and actor.get("role") == "gerente":
                return redirect(url_for("main.users_new"))
            if role == "supervisor":
                flash("Ahora asigna el alcance del supervisor por nombre.", "success")
                return redirect(url_for("main.user_supervisor_scopes", user_id=user_id))
            return redirect(url_for("main.users_list"))
        except ValueError as exc:
            flash(str(exc), "error")

    return render_template("user_form.html", mode="new", user=None)


@main.route("/users/<int:user_id>/edit", methods=["GET", "POST"])
def users_edit(user_id):
    if not can_edit_users():
        abort(403)

    user = fetch_user_by_id(user_id)
    if not user:
        abort(404)

    if request.method == "POST":
        try:
            username = (request.form.get("username") or "").strip()
            role = (request.form.get("role") or user.get("role") or "auditor").strip().lower()
            is_active = (request.form.get("is_active") or "1").strip() == "1"
            new_password = (request.form.get("password") or "").strip()
            confirm = (request.form.get("confirm_password") or "").strip()

            password = None
            if new_password or confirm:
                if len(new_password) < 8:
                    raise ValueError("La contraseña debe tener al menos 8 caracteres.")
                if new_password != confirm:
                    raise ValueError("Las contraseñas no coinciden.")
                password = new_password

            projected_role = (role or "auditor").strip().lower()
            projected_active = 1 if is_active else 0
            if user.get("role") == "admin" and user.get("is_active") and (
                projected_role != "admin" or not projected_active
            ):
                if count_active_admins() <= 1:
                    raise ValueError("Debe existir al menos un administrador activo.")
            if user.get("role") != "admin" and projected_role not in {"auditor", "gerente", "supervisor"}:
                raise ValueError("El rol seleccionado no es válido.")

            update_user(user_id, username=username, password=password, role=role, is_active=is_active)
            if projected_role != "supervisor":
                replace_user_supervisor_scopes(user_id, [])
            flash("Usuario actualizado.", "success")
            if projected_role == "supervisor":
                return redirect(url_for("main.user_supervisor_scopes", user_id=user_id))
            return redirect(url_for("main.users_list"))
        except ValueError as exc:
            flash(str(exc), "error")

    return render_template("user_form.html", mode="edit", user=user)


@main.route("/users/<int:user_id>/scopes", methods=["GET", "POST"])
def user_supervisor_scopes(user_id):
    if not can_manage_supervisor_scopes():
        abort(403)

    user = fetch_user_by_id(user_id)
    if not user:
        abort(404)
    if user.get("role") != "supervisor":
        flash("Solo los usuarios con rol supervisor pueden tener alcance asignado.", "error")
        return redirect(url_for("main.users_list"))

    if request.method == "POST":
        raw_scopes = (request.form.get("supervisor_scopes") or "").replace(",", "\n")
        normalized_scopes = replace_user_supervisor_scopes(user_id, raw_scopes.splitlines())
        flash(f"Alcance actualizado. Supervisores asignados: {len(normalized_scopes)}.", "success")
        return redirect(url_for("main.users_list"))

    scopes = fetch_user_supervisor_scopes(user_id)
    return render_template("user_scopes_form.html", user=user, scopes=scopes)


CSV_IMPORT_TYPES = {
    "technicians": {
        "label": "Tecnicos",
        "required_columns": ["employee_code", "name", "region"],
        "importer": import_technicians,
    },
    "technician_information": {
        "label": "Información técnicos (móvil, supervisor, centro, empresa, sindicato)",
        "required_columns": [],
        "importer": import_technician_information,
    },
    "checklist_del_dia": {
        "label": "CHECK LIST DEL DIA (vehiculos, km y empresa)",
        "required_columns": [],
        "importer": import_checklist_del_dia,
    },
    "novedades_diarias": {
        "label": "NovDiarias (supervisor y centro)",
        "required_columns": [],
        "importer": import_novedades_diarias,
    },
    "vehicles": {
        "label": "Vehiculos",
        # No exigir columnas fijas (p. ej. plate/brand/model) para permitir XLSX con encabezados como "patente" o "nro_camioneta_patente".
        "required_columns": [],
        "importer": import_vehicles,
    },
    "material_stock": {
        "label": "Stock de materiales",
        "required_columns": ["material"],
        "importer": import_material_stock,
    },
    "storage_locations": {
        "label": "Almacenes y moviles",
        "required_columns": ["codigo", "descripcion", "centro"],
        "importer": import_storage_locations,
    },
    "equipment_inventory": {
        "label": "Stock de equipos",
        "required_columns": ["centro", "codigo_almacen", "almacen", "codigo_material", "material", "serial"],
        "importer": import_equipment_inventory,
    },
}


def calculate_section_score(section, form_data, files):
    valid_items = 0
    score_sum = 0.0
    has_critical_failure = False
    serialized_items = []

    photo_optional_reasons = {"olvido", "perdida", "robo", "no_asignado"}
    photo_optional_items = {"extintor", "seguro_vehicular", "oblea_gnc", "rto", "botiquin"}
    vencido_allowed_items = {"extintor", "seguro_vehicular", "oblea_gnc", "rto", "botiquin"}
    no_apta_allowed_sections = {"seguridad", "herramientas", "herramientas_mano", "vehiculo"}
    no_apta_excluded_items = {"documentacion", "seguro_vehicular", "oblea_gnc", "rto"}
    no_apta_allowed_items = {
        str(it.get("key"))
        for sec in CHECKLIST_SECTIONS
        if str(sec.get("key")) in no_apta_allowed_sections
        for it in (sec.get("items") or [])
        if str(it.get("key")) and str(it.get("key")) not in no_apta_excluded_items
    }
    status_scores = {
        "cumple": 1.0,
        "conforme": 1.0,
        "no_cumple": 0.0,
        "nc_menor": 0.5,
        "nc_mayor": 0.0,
    }
    critical_failure_statuses = {"no_cumple", "nc_mayor"}

    for item in section["items"]:
        status = form_data.get(f"status__{item['key']}", "")
        if not status and item.get("optional"):
            status = "no_aplica"
        non_compliance_reason = form_data.get(f"reason__{item['key']}", "").strip()
        non_imputable_non_compliance = is_non_imputable_non_compliance(status, non_compliance_reason)
        score_excluded_non_compliance = (
            str(status or "").strip().lower() == "no_cumple"
            and str(non_compliance_reason or "").strip().lower() in SCORE_EXCLUDED_REASONS
        )
        notes = form_data.get(f"notes__{item['key']}", "").strip().upper()
        uploaded_photo_path_raw = (form_data.get(f"uploaded_photo_path__{item['key']}") or "").strip()
        uploaded_photo_path = uploaded_photo_path_raw if uploaded_photo_path_raw and uploaded_photo_path_raw != "-" else None
        photo_file = None
        photo_files = None
        if item.get("multi_photo"):
            collected = []
            if hasattr(files, "getlist"):
                collected.extend(files.getlist(f"photos__{item['key']}"))
                collected.extend(files.getlist(f"photos_camera__{item['key']}"))
            else:
                candidate = files.get(f"photos__{item['key']}")
                if candidate:
                    collected.append(candidate)
                candidate = files.get(f"photos_camera__{item['key']}")
                if candidate:
                    collected.append(candidate)
            photo_files = [entry for entry in collected if has_uploaded_file(entry)]
        else:
            file_photo = files.get(f"photo__{item['key']}")
            camera_photo = files.get(f"photo_camera__{item['key']}")
            if has_uploaded_file(file_photo):
                photo_file = file_photo
            elif has_uploaded_file(camera_photo):
                photo_file = camera_photo
        evidence_required = item.get("evidence_required", True)
        extinguisher_expiry = ""
        if item["key"] == "extintor":
            extinguisher_expiry = (form_data.get("expiry__extintor") or "").strip()
        insurance_expiry = ""
        if item["key"] == "seguro_vehicular":
            insurance_expiry = (form_data.get("expiry__insurance") or "").strip()
        gnc_expiry = ""
        if item["key"] == "oblea_gnc":
            gnc_expiry = (form_data.get("expiry__gnc") or "").strip()
        rto_expiry = ""
        if item["key"] == "rto":
            rto_expiry = (form_data.get("expiry__rto") or "").strip()
        botiquin_expiry = ""
        if item["key"] == "botiquin":
            botiquin_expiry = (form_data.get("expiry__botiquin") or "").strip()

        if not status:
            raise ValueError(f"Debes responder el item: {item['label']}")

        if item["key"] == "extintor" and status == "cumple":
            if not extinguisher_expiry:
                raise ValueError("Debes indicar la fecha de caducidad del extintor.")
            try:
                datetime.fromisoformat(extinguisher_expiry)
            except ValueError as exc:
                raise ValueError("La fecha de caducidad del extintor no es valida.") from exc

        if item["key"] == "seguro_vehicular" and status == "cumple":
            if not insurance_expiry:
                raise ValueError("Debes indicar la fecha de vencimiento del seguro del vehiculo.")
            try:
                datetime.fromisoformat(insurance_expiry)
            except ValueError as exc:
                raise ValueError("La fecha de vencimiento del seguro no es valida.") from exc

        if item["key"] == "oblea_gnc" and status == "cumple":
            if not gnc_expiry:
                raise ValueError("Debes indicar la fecha de caducidad de la oblea de GNC.")
            try:
                datetime.fromisoformat(gnc_expiry)
            except ValueError as exc:
                raise ValueError("La fecha de caducidad de la oblea de GNC no es valida.") from exc

        if item["key"] == "rto" and status == "cumple":
            if not rto_expiry:
                raise ValueError("Debes indicar la fecha de vencimiento de la RTO.")
            try:
                datetime.fromisoformat(rto_expiry)
            except ValueError as exc:
                raise ValueError("La fecha de vencimiento de la RTO no es valida.") from exc

        if item["key"] == "botiquin" and status == "cumple":
            if not botiquin_expiry:
                raise ValueError("Debes indicar la fecha de vencimiento del botiquin.")
            try:
                datetime.fromisoformat(botiquin_expiry)
            except ValueError as exc:
                raise ValueError("La fecha de vencimiento del botiquin no es valida.") from exc

        if status == "no_cumple" and not notes:
            raise ValueError(f"Debes agregar observacion en: {item['label']}")

        if status in {"nc_menor", "nc_mayor"} and not notes:
            raise ValueError(f"Debes agregar detalle en: {item['label']}")

        if status == "no_cumple" and not non_compliance_reason:
            raise ValueError(f"Debes seleccionar el motivo en: {item['label']}")

        if status == "no_cumple":
            normalized_reason = str(non_compliance_reason or "").strip().lower()
            if normalized_reason == "vencido" and item["key"] not in vencido_allowed_items:
                raise ValueError(f"El motivo 'Vencido' no aplica para el ítem: {item['label']}")
            if normalized_reason == "no_apta_para_el_uso" and item["key"] not in no_apta_allowed_items:
                raise ValueError(f"El motivo 'No apta para el uso' no aplica para el ítem: {item['label']}")

        requires_photo = (
            evidence_required
            and item["key"] not in photo_optional_items
            and (
                (
                    status == "no_cumple"
                    and non_compliance_reason not in photo_optional_reasons
                )
                or (
                    section["key"] == "calidad_instalaciones"
                    and status in {"nc_menor", "nc_mayor"}
                )
            )
        )
        has_any_photo_upload = has_uploaded_file(photo_file)
        if not has_any_photo_upload and photo_files:
            has_any_photo_upload = any(has_uploaded_file(entry) for entry in photo_files)
        has_any_uploaded_photo_path = False
        if uploaded_photo_path:
            stripped = str(uploaded_photo_path).strip()
            if stripped and stripped != "-":
                if stripped.startswith("[") and stripped.endswith("]"):
                    try:
                        parsed = json.loads(stripped)
                        if isinstance(parsed, list) and any(str(v or "").strip() and str(v or "").strip() != "-" for v in parsed):
                            has_any_uploaded_photo_path = True
                    except Exception:
                        has_any_uploaded_photo_path = True
                else:
                    has_any_uploaded_photo_path = True
        if requires_photo and not (has_any_photo_upload or has_any_uploaded_photo_path):
            raise ValueError(f"Debes adjuntar evidencia fotografica en: {item['label']}")

        if status != "no_aplica" and not score_excluded_non_compliance:
            valid_items += 1
            score_sum += status_scores.get(status, 0.0)

        if (
            status in critical_failure_statuses
            and item["critical"]
            and not non_imputable_non_compliance
        ):
            has_critical_failure = True

        serialized_items.append(
            {
                "section_key": section["key"],
                "section_title": section["title"],
                "item_key": item["key"],
                "item_label": item["label"],
                "status": status,
                "is_critical": item["critical"],
                "non_compliance_reason": non_compliance_reason or None,
                "notes": notes or None,
                "photo_file": photo_file if has_uploaded_file(photo_file) else None,
                "photo_files": photo_files if photo_files else None,
                "photo_path": uploaded_photo_path,
            }
        )

    compliance_ratio = 1 if valid_items == 0 else score_sum / valid_items
    section_score = compliance_ratio * section["weight"]
    return section_score, has_critical_failure, serialized_items


def calculate_audit_result(form_data, files):
    total_score = 0.0
    has_critical_failure = False
    all_items = []

    for section in AUDIT_CHECKLIST_SECTIONS:
        section_score, section_failure, items = calculate_section_score(section, form_data, files)
        total_score += section_score
        has_critical_failure = has_critical_failure or section_failure
        all_items.extend(items)

    snapshot_status_scores = {"ok": 1.0, "missing": 0.0, "not_checked": 0.5}
    serialized_weight = 5
    material_weight = 5
    serialized_stock_status = (form_data.get("serialized_stock_status") or "").strip()
    material_stock_status = (form_data.get("material_stock_status") or "").strip()
    total_score += serialized_weight * snapshot_status_scores.get(serialized_stock_status, 0.0)
    total_score += material_weight * snapshot_status_scores.get(material_stock_status, 0.0)

    max_section_score = sum(float(section.get("weight") or 0.0) for section in AUDIT_CHECKLIST_SECTIONS)
    max_total_score = max_section_score + serialized_weight + material_weight
    normalized_total_score = (
        total_score * (100.0 / max_total_score) if max_total_score else total_score
    )

    if has_critical_failure:
        result_status = "Critica"
    elif normalized_total_score >= 90:
        result_status = "Aprobada"
    elif normalized_total_score >= 75:
        result_status = "Aprobada con observaciones"
    else:
        result_status = "Rechazada"

    return round(normalized_total_score, 2), result_status, all_items


def validate_required_columns(fieldnames, required_columns):
    missing_columns = [column for column in required_columns if column not in fieldnames]
    if missing_columns:
        raise ValueError(
            "Faltan columnas obligatorias: " + ", ".join(missing_columns)
        )


def has_uploaded_file(photo_file):
    return photo_file is not None and bool(photo_file.filename)


def validate_photo_file(photo_file, item_label):
    filename = secure_filename(photo_file.filename or "")
    if not filename:
        raise ValueError(f"La evidencia de {item_label} no tiene un nombre de archivo valido.")

    extension = Path(filename).suffix.lower().lstrip(".")
    if extension not in current_app.config["ALLOWED_IMAGE_EXTENSIONS"]:
        raise ValueError(
            f"La evidencia de {item_label} debe ser una imagen PNG, JPG, JPEG o WEBP."
        )
    return filename, extension


def cloudinary_enabled():
    raw = (current_app.config.get("CLOUDINARY_URL") or "").strip()
    if not raw.startswith("cloudinary://"):
        return False
    payload = raw[len("cloudinary://"):]
    if "@" not in payload:
        return False
    creds, cloud_name = payload.split("@", 1)
    if ":" not in creds:
        return False
    api_key, api_secret = creds.split(":", 1)
    api_key = (api_key or "").strip()
    api_secret = (api_secret or "").strip()
    cloud_name = (cloud_name or "").strip()
    return bool(api_key and api_secret and cloud_name)


def optimize_photo_bytes(content_bytes, extension, max_dim=2400):
    normalized_extension = (extension or "").lower().lstrip(".")
    if not content_bytes or Image is None or ImageOps is None:
        return content_bytes, normalized_extension

    try:
        image = Image.open(io.BytesIO(content_bytes))
        image = ImageOps.exif_transpose(image)
        original_width, original_height = image.size
        downscale_required = original_width > max_dim or original_height > max_dim

        resample = getattr(Image, "Resampling", Image).LANCZOS
        image.thumbnail((max_dim, max_dim), resample)

        has_alpha = image.mode in {"RGBA", "LA"} or (image.mode == "P" and "transparency" in image.info)
        if has_alpha:
            normalized = image.convert("RGBA") if image.mode != "RGBA" else image
        else:
            normalized = image.convert("RGB") if image.mode != "RGB" else image

        buffer = io.BytesIO()
        normalized.save(buffer, format="WEBP", quality=72, method=6)
        optimized_bytes = buffer.getvalue()
        if optimized_bytes and (downscale_required or len(optimized_bytes) < len(content_bytes)):
            return optimized_bytes, "webp"
        return content_bytes, normalized_extension
    except Exception:
        return content_bytes, normalized_extension


def optimize_signature_png_bytes(content_bytes):
    if not content_bytes or Image is None or ImageOps is None:
        return content_bytes

    try:
        image = Image.open(io.BytesIO(content_bytes))
        image = ImageOps.exif_transpose(image)
        buffer = io.BytesIO()
        normalized = image.convert("RGBA") if image.mode != "RGBA" else image
        normalized.save(buffer, format="PNG", optimize=True, compress_level=9)
        optimized_bytes = buffer.getvalue()
        if optimized_bytes and len(optimized_bytes) < len(content_bytes):
            return optimized_bytes
        return content_bytes
    except Exception:
        return content_bytes


def upload_image_to_cloudinary(content_bytes, folder, public_id):
    raw_url = (current_app.config.get("CLOUDINARY_URL") or "").strip()
    if not raw_url.startswith("cloudinary://"):
        raise ValueError("CLOUDINARY_URL inválida. Debe comenzar con cloudinary://")

    import cloudinary
    import cloudinary.uploader

    try:
        cloudinary.config(cloudinary_url=raw_url, secure=True)
        result = cloudinary.uploader.upload(
            io.BytesIO(content_bytes),
            folder=folder,
            public_id=public_id,
            resource_type="image",
        )
        return result.get("secure_url") or result.get("url")
    except Exception as exc:
        raise ValueError("No fue posible subir la imagen a Cloudinary. Revisa CLOUDINARY_URL.") from exc


def upload_private_image_to_cloudinary(content_bytes, folder, public_id):
    raw_url = (current_app.config.get("CLOUDINARY_URL") or "").strip()
    if not raw_url.startswith("cloudinary://"):
        raise ValueError("CLOUDINARY_URL inválida. Debe comenzar con cloudinary://")

    import cloudinary
    import cloudinary.uploader

    try:
        cloudinary.config(cloudinary_url=raw_url, secure=True)
        result = cloudinary.uploader.upload(
            io.BytesIO(content_bytes),
            folder=folder,
            public_id=public_id,
            resource_type="image",
            type="private",
        )
        return {
            "public_id": result.get("public_id"),
            "version": result.get("version"),
        }
    except Exception as exc:
        raise ValueError("No fue posible subir la imagen a Cloudinary. Revisa CLOUDINARY_URL.") from exc


def encode_cloudinary_ref(public_id, version=None, delivery_type="private", resource_type="image", file_format=None):
    if not public_id:
        raise ValueError("public_id requerido para referencia Cloudinary.")
    parts = ["cld", delivery_type, resource_type, public_id]
    if version is not None:
        parts.append(str(version))
    if file_format:
        parts.append(str(file_format))
    return "|".join(parts)


def decode_cloudinary_ref(value):
    raw = (value or "").strip()
    if not raw.startswith("cld|"):
        return None
    parts = raw.split("|")
    if len(parts) < 4:
        return None
    _, delivery_type, resource_type, public_id, *rest = parts
    version = None
    file_format = None
    if rest:
        version = rest[0] or None
    if len(rest) > 1:
        file_format = rest[1] or None
    return {
        "delivery_type": delivery_type or "private",
        "resource_type": resource_type or "image",
        "public_id": public_id,
        "version": int(version) if version and version.isdigit() else None,
        "file_format": file_format or None,
    }


def build_cloudinary_signed_url(ref_or_url, expires_in_seconds=600):
    decoded = decode_cloudinary_ref(ref_or_url)
    if not decoded:
        return ref_or_url

    raw_url = (current_app.config.get("CLOUDINARY_URL") or "").strip()
    if not raw_url.startswith("cloudinary://"):
        return None

    import cloudinary
    from cloudinary.utils import cloudinary_url

    cloudinary.config(cloudinary_url=raw_url, secure=True)

    kwargs = {
        "resource_type": decoded["resource_type"],
        "type": decoded["delivery_type"],
        "sign_url": True,
        "secure": True,
        "version": decoded["version"],
    }
    if decoded["file_format"]:
        kwargs["format"] = decoded["file_format"]

    url = None
    expires_at = int(time.time()) + int(expires_in_seconds)
    try:
        url, _options = cloudinary_url(decoded["public_id"], expires_at=expires_at, **kwargs)
    except TypeError:
        url, _options = cloudinary_url(decoded["public_id"], **kwargs)
    return url


def image_bytes_to_data_uri(content_bytes, extension):
    normalized = (extension or "").lower().lstrip(".")
    mime_map = {
        "png": "image/png",
        "jpg": "image/jpeg",
        "jpeg": "image/jpeg",
        "webp": "image/webp",
    }
    mime = mime_map.get(normalized)
    if not mime:
        raise ValueError("Formato de imagen no soportado.")
    encoded = base64.b64encode(content_bytes).decode("ascii")
    return f"data:{mime};base64,{encoded}"


def persist_item_evidence(items, audit_date):
    date_folder = datetime.fromisoformat(audit_date).strftime("%Y/%m")
    if not cloudinary_enabled():
        target_dir = current_app.config["AUDIT_EVIDENCE_DIR"] / date_folder
        target_dir.mkdir(parents=True, exist_ok=True)

    for item in items:
        existing_photo_path = item.get("photo_path")
        photo_files = item.pop("photo_files", None)
        photo_file = item.pop("photo_file", None)

        if photo_files:
            photo_paths = []
            for index, entry in enumerate(photo_files):
                filename, extension = validate_photo_file(entry, item["item_label"])
                safe_stem = secure_filename(item["item_key"]) or "evidencia"
                generated_name = f"{datetime.utcnow().strftime('%Y%m%d%H%M%S')}_{safe_stem}_{index + 1}_{uuid4().hex[:8]}"

                raw_bytes = entry.stream.read()
                if not raw_bytes:
                    raise ValueError(f"La evidencia de {item['item_label']} no contiene datos validos.")

                optimized_bytes, optimized_extension = optimize_photo_bytes(raw_bytes, extension, max_dim=2400)
                if cloudinary_enabled():
                    base_folder = (current_app.config.get("CLOUDINARY_FOLDER") or "atbb").strip().strip("/")
                    folder = f"{base_folder}/audits/{date_folder}"
                    uploaded = upload_private_image_to_cloudinary(
                        optimized_bytes,
                        folder=folder,
                        public_id=generated_name,
                    )
                    photo_paths.append(
                        encode_cloudinary_ref(
                            uploaded.get("public_id"),
                            version=uploaded.get("version"),
                            delivery_type="private",
                            resource_type="image",
                            file_format=optimized_extension,
                        )
                    )
                else:
                    generated_filename = f"{generated_name}.{optimized_extension}"
                    saved_path = target_dir / generated_filename
                    saved_path.write_bytes(optimized_bytes)
                    photo_paths.append(
                        f"uploads/audits/{date_folder}/{generated_filename}".replace("\\", "/")
                    )
            item["photo_path"] = json.dumps(photo_paths, ensure_ascii=False) if photo_paths else None
            continue

        if not photo_file:
            item["photo_path"] = existing_photo_path or None
            continue

        filename, extension = validate_photo_file(photo_file, item["item_label"])
        safe_stem = secure_filename(item["item_key"]) or "evidencia"
        generated_name = f"{datetime.utcnow().strftime('%Y%m%d%H%M%S')}_{safe_stem}_{uuid4().hex[:8]}"

        raw_bytes = photo_file.stream.read()
        if not raw_bytes:
            raise ValueError(f"La evidencia de {item['item_label']} no contiene datos validos.")

        optimized_bytes, optimized_extension = optimize_photo_bytes(raw_bytes, extension, max_dim=2400)
        if cloudinary_enabled():
            base_folder = (current_app.config.get("CLOUDINARY_FOLDER") or "atbb").strip().strip("/")
            folder = f"{base_folder}/audits/{date_folder}"
            uploaded = upload_private_image_to_cloudinary(
                optimized_bytes,
                folder=folder,
                public_id=generated_name,
            )
            item["photo_path"] = encode_cloudinary_ref(
                uploaded.get("public_id"),
                version=uploaded.get("version"),
                delivery_type="private",
                resource_type="image",
                file_format=optimized_extension,
            )
        else:
            generated_filename = f"{generated_name}.{optimized_extension}"
            saved_path = target_dir / generated_filename
            saved_path.write_bytes(optimized_bytes)
            item["photo_path"] = f"uploads/audits/{date_folder}/{generated_filename}".replace("\\", "/")


def persist_qc_item_evidence(items, qc_date):
    date_folder = datetime.fromisoformat(qc_date).strftime("%Y/%m")
    if not cloudinary_enabled():
        target_dir = current_app.config["AUDIT_EVIDENCE_DIR"] / "qc" / date_folder
        target_dir.mkdir(parents=True, exist_ok=True)

    for item in items:
        existing_photo_path = item.get("photo_path")
        photo_files = item.pop("photo_files", None)
        photo_file = item.pop("photo_file", None)

        if photo_files:
            photo_paths = []
            for index, entry in enumerate(photo_files):
                filename, extension = validate_photo_file(entry, item["item_label"])
                safe_stem = secure_filename(item["item_key"]) or "evidencia"
                generated_name = f"{datetime.utcnow().strftime('%Y%m%d%H%M%S')}_{safe_stem}_{index + 1}_{uuid4().hex[:8]}"

                raw_bytes = entry.stream.read()
                if not raw_bytes:
                    raise ValueError(f"La evidencia de {item['item_label']} no contiene datos validos.")

                optimized_bytes, optimized_extension = optimize_photo_bytes(raw_bytes, extension, max_dim=2400)
                if cloudinary_enabled():
                    base_folder = (current_app.config.get("CLOUDINARY_FOLDER") or "atbb").strip().strip("/")
                    folder = f"{base_folder}/qc/{date_folder}"
                    uploaded = upload_private_image_to_cloudinary(
                        optimized_bytes,
                        folder=folder,
                        public_id=generated_name,
                    )
                    photo_paths.append(
                        encode_cloudinary_ref(
                            uploaded.get("public_id"),
                            version=uploaded.get("version"),
                            delivery_type="private",
                            resource_type="image",
                            file_format=optimized_extension,
                        )
                    )
                else:
                    generated_filename = f"{generated_name}.{optimized_extension}"
                    saved_path = target_dir / generated_filename
                    saved_path.write_bytes(optimized_bytes)
                    photo_paths.append(
                        f"uploads/audits/qc/{date_folder}/{generated_filename}".replace("\\", "/")
                    )
            item["photo_path"] = json.dumps(photo_paths, ensure_ascii=False) if photo_paths else None
            continue

        if not photo_file:
            item["photo_path"] = existing_photo_path or None
            continue

        filename, extension = validate_photo_file(photo_file, item["item_label"])
        safe_stem = secure_filename(item["item_key"]) or "evidencia"
        generated_name = f"{datetime.utcnow().strftime('%Y%m%d%H%M%S')}_{safe_stem}_{uuid4().hex[:8]}"

        raw_bytes = photo_file.stream.read()
        if not raw_bytes:
            raise ValueError(f"La evidencia de {item['item_label']} no contiene datos validos.")

        optimized_bytes, optimized_extension = optimize_photo_bytes(raw_bytes, extension, max_dim=2400)
        if cloudinary_enabled():
            base_folder = (current_app.config.get("CLOUDINARY_FOLDER") or "atbb").strip().strip("/")
            folder = f"{base_folder}/qc/{date_folder}"
            uploaded = upload_private_image_to_cloudinary(
                optimized_bytes,
                folder=folder,
                public_id=generated_name,
            )
            item["photo_path"] = encode_cloudinary_ref(
                uploaded.get("public_id"),
                version=uploaded.get("version"),
                delivery_type="private",
                resource_type="image",
                file_format=optimized_extension,
            )
        else:
            generated_filename = f"{generated_name}.{optimized_extension}"
            saved_path = target_dir / generated_filename
            saved_path.write_bytes(optimized_bytes)
            item["photo_path"] = f"uploads/audits/qc/{date_folder}/{generated_filename}".replace("\\", "/")


def persist_qc_session_evidence(photo_file, qc_date, qc_session_id=None):
    if not has_uploaded_file(photo_file):
        return None

    _filename, extension = validate_photo_file(photo_file, "foto QC")
    raw_bytes = photo_file.stream.read()
    if not raw_bytes:
        raise ValueError("La foto del QC no contiene datos validos.")

    optimized_bytes, optimized_extension = optimize_photo_bytes(raw_bytes, extension, max_dim=2400)
    date_folder = datetime.fromisoformat(qc_date).strftime("%Y/%m")
    stable_id = str(qc_session_id) if qc_session_id is not None else uuid4().hex[:8]
    generated_name = f"qc_session_{stable_id}_{uuid4().hex[:8]}"

    if cloudinary_enabled():
        base_folder = (current_app.config.get("CLOUDINARY_FOLDER") or "atbb").strip().strip("/")
        folder = f"{base_folder}/qc-sessions/{date_folder}"
        uploaded = upload_private_image_to_cloudinary(
            optimized_bytes,
            folder=folder,
            public_id=generated_name,
        )
        return encode_cloudinary_ref(
            uploaded.get("public_id"),
            version=uploaded.get("version"),
            delivery_type="private",
            resource_type="image",
            file_format=optimized_extension,
        )

    target_dir = current_app.config["AUDIT_EVIDENCE_DIR"] / "qc-sessions" / date_folder
    target_dir.mkdir(parents=True, exist_ok=True)
    generated_filename = f"{generated_name}.{optimized_extension}"
    saved_path = target_dir / generated_filename
    saved_path.write_bytes(optimized_bytes)
    return f"uploads/audits/qc-sessions/{date_folder}/{generated_filename}".replace("\\", "/")


def persist_service_item_evidence(items, service_date):
    date_folder = datetime.fromisoformat(service_date).strftime("%Y/%m")
    if not cloudinary_enabled():
        target_dir = current_app.config["AUDIT_EVIDENCE_DIR"] / "service" / date_folder
        target_dir.mkdir(parents=True, exist_ok=True)

    for item in items:
        existing_photo_path = item.get("photo_path")
        photo_files = item.pop("photo_files", None)
        photo_file = item.pop("photo_file", None)

        if photo_files:
            photo_paths = []
            for index, entry in enumerate(photo_files):
                _filename, extension = validate_photo_file(entry, item["item_label"])
                safe_stem = secure_filename(item["item_key"]) or "evidencia"
                generated_name = f"{datetime.utcnow().strftime('%Y%m%d%H%M%S')}_{safe_stem}_{index + 1}_{uuid4().hex[:8]}"

                raw_bytes = entry.stream.read()
                if not raw_bytes:
                    raise ValueError(f"La evidencia de {item['item_label']} no contiene datos validos.")

                optimized_bytes, optimized_extension = optimize_photo_bytes(raw_bytes, extension, max_dim=2400)
                if cloudinary_enabled():
                    base_folder = (current_app.config.get("CLOUDINARY_FOLDER") or "atbb").strip().strip("/")
                    folder = f"{base_folder}/service/{date_folder}"
                    uploaded = upload_private_image_to_cloudinary(
                        optimized_bytes,
                        folder=folder,
                        public_id=generated_name,
                    )
                    photo_paths.append(
                        encode_cloudinary_ref(
                            uploaded.get("public_id"),
                            version=uploaded.get("version"),
                            delivery_type="private",
                            resource_type="image",
                            file_format=optimized_extension,
                        )
                    )
                else:
                    generated_filename = f"{generated_name}.{optimized_extension}"
                    saved_path = target_dir / generated_filename
                    saved_path.write_bytes(optimized_bytes)
                    photo_paths.append(
                        f"uploads/audits/service/{date_folder}/{generated_filename}".replace("\\", "/")
                    )
            item["photo_path"] = json.dumps(photo_paths, ensure_ascii=False) if photo_paths else None
            continue

        if not photo_file:
            item["photo_path"] = existing_photo_path or None
            continue

        _filename, extension = validate_photo_file(photo_file, item["item_label"])
        safe_stem = secure_filename(item["item_key"]) or "evidencia"
        generated_name = f"{datetime.utcnow().strftime('%Y%m%d%H%M%S')}_{safe_stem}_{uuid4().hex[:8]}"

        raw_bytes = photo_file.stream.read()
        if not raw_bytes:
            raise ValueError(f"La evidencia de {item['item_label']} no contiene datos validos.")

        optimized_bytes, optimized_extension = optimize_photo_bytes(raw_bytes, extension, max_dim=2400)
        if cloudinary_enabled():
            base_folder = (current_app.config.get("CLOUDINARY_FOLDER") or "atbb").strip().strip("/")
            folder = f"{base_folder}/service/{date_folder}"
            uploaded = upload_private_image_to_cloudinary(
                optimized_bytes,
                folder=folder,
                public_id=generated_name,
            )
            item["photo_path"] = encode_cloudinary_ref(
                uploaded.get("public_id"),
                version=uploaded.get("version"),
                delivery_type="private",
                resource_type="image",
                file_format=optimized_extension,
            )
        else:
            generated_filename = f"{generated_name}.{optimized_extension}"
            saved_path = target_dir / generated_filename
            saved_path.write_bytes(optimized_bytes)
            item["photo_path"] = f"uploads/audits/service/{date_folder}/{generated_filename}".replace("\\", "/")


def persist_service_session_evidence(photo_file, service_date, service_session_id=None):
    if not has_uploaded_file(photo_file):
        return None

    _filename, extension = validate_photo_file(photo_file, "foto Service")
    raw_bytes = photo_file.stream.read()
    if not raw_bytes:
        raise ValueError("La foto del Service no contiene datos validos.")

    optimized_bytes, optimized_extension = optimize_photo_bytes(raw_bytes, extension, max_dim=2400)
    date_folder = datetime.fromisoformat(service_date).strftime("%Y/%m")
    stable_id = str(service_session_id) if service_session_id is not None else uuid4().hex[:8]
    generated_name = f"service_session_{stable_id}_{uuid4().hex[:8]}"

    if cloudinary_enabled():
        base_folder = (current_app.config.get("CLOUDINARY_FOLDER") or "atbb").strip().strip("/")
        folder = f"{base_folder}/service-sessions/{date_folder}"
        uploaded = upload_private_image_to_cloudinary(
            optimized_bytes,
            folder=folder,
            public_id=generated_name,
        )
        return encode_cloudinary_ref(
            uploaded.get("public_id"),
            version=uploaded.get("version"),
            delivery_type="private",
            resource_type="image",
            file_format=optimized_extension,
        )

    target_dir = current_app.config["AUDIT_EVIDENCE_DIR"] / "service-sessions" / date_folder
    target_dir.mkdir(parents=True, exist_ok=True)
    generated_filename = f"{generated_name}.{optimized_extension}"
    saved_path = target_dir / generated_filename
    saved_path.write_bytes(optimized_bytes)
    return f"uploads/audits/service-sessions/{date_folder}/{generated_filename}".replace("\\", "/")


def persist_finding_evidence(photo_file, audit_date, finding_id):
    if not has_uploaded_file(photo_file):
        return None

    _filename, extension = validate_photo_file(photo_file, f"hallazgo {finding_id}")
    raw_bytes = photo_file.stream.read()
    if not raw_bytes:
        raise ValueError("La evidencia del hallazgo no contiene datos validos.")

    optimized_bytes, optimized_extension = optimize_photo_bytes(raw_bytes, extension, max_dim=2400)
    date_folder = datetime.fromisoformat(audit_date).strftime("%Y/%m")
    generated_name = f"finding_{finding_id}_{uuid4().hex[:12]}"

    if cloudinary_enabled():
        base_folder = (current_app.config.get("CLOUDINARY_FOLDER") or "atbb").strip().strip("/")
        folder = f"{base_folder}/findings/{date_folder}"
        uploaded = upload_private_image_to_cloudinary(
            optimized_bytes,
            folder=folder,
            public_id=generated_name,
        )
        return encode_cloudinary_ref(
            uploaded.get("public_id"),
            version=uploaded.get("version"),
            delivery_type="private",
            resource_type="image",
            file_format=optimized_extension,
        )

    target_dir = current_app.config["AUDIT_EVIDENCE_DIR"] / "findings" / date_folder
    target_dir.mkdir(parents=True, exist_ok=True)
    generated_filename = f"{generated_name}.{optimized_extension}"
    saved_path = target_dir / generated_filename
    saved_path.write_bytes(optimized_bytes)
    return f"uploads/audits/findings/{date_folder}/{generated_filename}".replace("\\", "/")


@main.route("/api/audits/upload-evidence", methods=["POST"])
def upload_audit_evidence():
    try:
        if not can_create_audit():
            abort(403)

        item_key = (request.form.get("item_key") or "").strip()
        item_label = (request.form.get("item_label") or "evidencia").strip() or "evidencia"
        audit_date = (request.form.get("audit_date") or "").strip()
        if not audit_date:
            audit_date = datetime.today().strftime("%Y-%m-%d")

        try:
            datetime.fromisoformat(audit_date)
        except ValueError:
            return jsonify({"error": "audit_date invalida."}), 400

        files = request.files.getlist("file") if hasattr(request.files, "getlist") else []
        if not files:
            single = request.files.get("file")
            if single:
                files = [single]

        files = [entry for entry in files if has_uploaded_file(entry)]
        _dbg_audit_evidence_500(
            "upload-evidence.request",
            {
                "item_key": item_key,
                "audit_date": audit_date,
                "cloudinary_enabled": cloudinary_enabled(),
                "files_count": len(files),
                "files_meta": [
                    {
                        "filename": getattr(f, "filename", None),
                        "content_type": getattr(f, "content_type", None),
                        "mimetype": getattr(f, "mimetype", None),
                    }
                    for f in files
                ],
            },
        )
        if not files:
            return jsonify({"error": "Debes adjuntar al menos un archivo."}), 400

        date_folder = datetime.fromisoformat(audit_date).strftime("%Y/%m")
        if not cloudinary_enabled():
            target_dir = current_app.config["AUDIT_EVIDENCE_DIR"] / date_folder
            target_dir.mkdir(parents=True, exist_ok=True)

        safe_stem = secure_filename(item_key) or "evidencia"
        base_folder = (current_app.config.get("CLOUDINARY_FOLDER") or "atbb").strip().strip("/")
        cloud_folder = f"{base_folder}/audits/{date_folder}"

        saved_paths = []
        for index, entry in enumerate(files):
            filename, extension = validate_photo_file(entry, item_label)
            generated_name = f"{datetime.utcnow().strftime('%Y%m%d%H%M%S')}_{safe_stem}_{index + 1}_{uuid4().hex[:8]}"
            raw_bytes = entry.stream.read()
            if not raw_bytes:
                return jsonify({"error": f"La evidencia de {item_label} no contiene datos validos."}), 400

            optimized_bytes, optimized_extension = optimize_photo_bytes(raw_bytes, extension, max_dim=2400)
            if cloudinary_enabled():
                uploaded = upload_private_image_to_cloudinary(
                    optimized_bytes,
                    folder=cloud_folder,
                    public_id=generated_name,
                )
                saved_paths.append(
                    encode_cloudinary_ref(
                        uploaded.get("public_id"),
                        version=uploaded.get("version"),
                        delivery_type="private",
                        resource_type="image",
                        file_format=optimized_extension,
                    )
                )
            else:
                generated_filename = f"{generated_name}.{optimized_extension}"
                saved_path = target_dir / generated_filename
                saved_path.write_bytes(optimized_bytes)
                saved_paths.append(
                    f"uploads/audits/{date_folder}/{generated_filename}".replace("\\", "/")
                )

        _dbg_audit_evidence_500(
            "upload-evidence.success",
            {
                "item_key": item_key,
                "saved_count": len(saved_paths),
                "saved_paths_sample": saved_paths[:3],
            },
        )
        if len(saved_paths) == 1:
            return jsonify({"photo_path": saved_paths[0]})
        return jsonify({"photo_paths": saved_paths})
    except Exception as exc:
        _dbg_audit_evidence_500(
            "upload-evidence.exception",
            {
                "error": repr(exc),
                "traceback": traceback.format_exc(),
            },
        )
        raise


def _resolve_uploads_relative_path(path_value):
    raw = (path_value or "").strip()
    if not raw.startswith("uploads/"):
        return None
    uploads_dir = current_app.config["UPLOADS_DIR"].resolve()
    relative = raw[len("uploads/"):]
    target = (uploads_dir / relative).resolve()
    if target == uploads_dir:
        return None
    if uploads_dir not in target.parents:
        return None
    return target


def delete_cloudinary_ref(ref):
    decoded = decode_cloudinary_ref(ref)
    if not decoded:
        return False
    raw_url = (current_app.config.get("CLOUDINARY_URL") or "").strip()
    if not raw_url.startswith("cloudinary://"):
        return False
    import cloudinary
    import cloudinary.uploader

    cloudinary.config(cloudinary_url=raw_url, secure=True)
    result = cloudinary.uploader.destroy(
        decoded["public_id"],
        resource_type=decoded["resource_type"],
        type=decoded["delivery_type"],
        invalidate=True,
    )
    status = (result or {}).get("result")
    return status in {"ok", "not found"}


@main.route("/api/audits/delete-evidence", methods=["POST"])
def delete_audit_evidence():
    if not can_create_audit():
        abort(403)

    payload = request.get_json(silent=True) or {}
    paths = payload.get("photo_paths")
    if paths is None:
        paths = request.form.getlist("photo_paths") if hasattr(request.form, "getlist") else []
    if paths is None:
        paths = []
    if isinstance(paths, str):
        paths = [paths]

    cleaned = []
    for entry in paths:
        value = str(entry or "").strip()
        if not value or value == "-":
            continue
        cleaned.append(value)

    deleted = 0
    errors = []
    for ref_or_path in cleaned:
        try:
            if decode_cloudinary_ref(ref_or_path):
                if delete_cloudinary_ref(ref_or_path):
                    deleted += 1
                else:
                    errors.append({"path": ref_or_path, "error": "No fue posible eliminar en Cloudinary."})
                continue

            target = _resolve_uploads_relative_path(ref_or_path)
            if not target:
                errors.append({"path": ref_or_path, "error": "Ruta de evidencia inválida."})
                continue
            if target.exists():
                target.unlink()
            deleted += 1
        except Exception as exc:
            errors.append({"path": ref_or_path, "error": str(exc) or "Error eliminando evidencia."})

    return jsonify({"deleted_count": deleted, "errors": errors})


@main.route("/api/qc/upload-evidence", methods=["POST"])
def upload_qc_evidence():
    try:
        if not can_create_audit():
            abort(403)

        item_key = (request.form.get("item_key") or "").strip()
        item_label = (request.form.get("item_label") or "evidencia").strip() or "evidencia"
        qc_date = (request.form.get("qc_date") or "").strip()
        if not qc_date:
            qc_date = datetime.today().strftime("%Y-%m-%d")

        try:
            datetime.fromisoformat(qc_date)
        except ValueError:
            return jsonify({"error": "qc_date invalida."}), 400

        files = request.files.getlist("file") if hasattr(request.files, "getlist") else []
        if not files:
            single = request.files.get("file")
            if single:
                files = [single]

        files = [entry for entry in files if has_uploaded_file(entry)]
        if not files:
            return jsonify({"error": "Debes adjuntar al menos un archivo."}), 400

        date_folder = datetime.fromisoformat(qc_date).strftime("%Y/%m")
        if not cloudinary_enabled():
            target_dir = current_app.config["AUDIT_EVIDENCE_DIR"] / "qc" / date_folder
            target_dir.mkdir(parents=True, exist_ok=True)

        safe_stem = secure_filename(item_key) or "evidencia"
        base_folder = (current_app.config.get("CLOUDINARY_FOLDER") or "atbb").strip().strip("/")
        cloud_folder = f"{base_folder}/qc/{date_folder}"

        saved_paths = []
        for index, entry in enumerate(files):
            _filename, extension = validate_photo_file(entry, item_label)
            generated_name = f"{datetime.utcnow().strftime('%Y%m%d%H%M%S')}_{safe_stem}_{index + 1}_{uuid4().hex[:8]}"
            raw_bytes = entry.stream.read()
            if not raw_bytes:
                return jsonify({"error": f"La evidencia de {item_label} no contiene datos validos."}), 400

            optimized_bytes, optimized_extension = optimize_photo_bytes(raw_bytes, extension, max_dim=2400)
            if cloudinary_enabled():
                uploaded = upload_private_image_to_cloudinary(
                    optimized_bytes,
                    folder=cloud_folder,
                    public_id=generated_name,
                )
                saved_paths.append(
                    encode_cloudinary_ref(
                        uploaded.get("public_id"),
                        version=uploaded.get("version"),
                        delivery_type="private",
                        resource_type="image",
                        file_format=optimized_extension,
                    )
                )
            else:
                generated_filename = f"{generated_name}.{optimized_extension}"
                saved_path = target_dir / generated_filename
                saved_path.write_bytes(optimized_bytes)
                saved_paths.append(
                    f"uploads/audits/qc/{date_folder}/{generated_filename}".replace("\\", "/")
                )

        if len(saved_paths) == 1:
            return jsonify({"photo_path": saved_paths[0]})
        return jsonify({"photo_paths": saved_paths})
    except Exception:
        raise


@main.route("/api/qc/upload-session-photo", methods=["POST"])
def upload_qc_session_photo():
    try:
        if not can_create_audit():
            abort(403)

        qc_date = (request.form.get("qc_date") or "").strip()
        if not qc_date:
            qc_date = datetime.today().strftime("%Y-%m-%d")
        try:
            datetime.fromisoformat(qc_date)
        except ValueError:
            return jsonify({"error": "qc_date invalida."}), 400

        photo_file = request.files.get("file")
        if not has_uploaded_file(photo_file):
            return jsonify({"error": "Debes adjuntar un archivo."}), 400

        _filename, extension = validate_photo_file(photo_file, "foto QC")
        raw_bytes = photo_file.stream.read()
        if not raw_bytes:
            return jsonify({"error": "La foto del QC no contiene datos validos."}), 400

        optimized_bytes, optimized_extension = optimize_photo_bytes(raw_bytes, extension, max_dim=2400)
        date_folder = datetime.fromisoformat(qc_date).strftime("%Y/%m")
        generated_name = f"qc_session_{uuid4().hex[:8]}_{uuid4().hex[:8]}"

        if cloudinary_enabled():
            base_folder = (current_app.config.get("CLOUDINARY_FOLDER") or "atbb").strip().strip("/")
            folder = f"{base_folder}/qc-sessions/{date_folder}"
            uploaded = upload_private_image_to_cloudinary(
                optimized_bytes,
                folder=folder,
                public_id=generated_name,
            )
            path = encode_cloudinary_ref(
                uploaded.get("public_id"),
                version=uploaded.get("version"),
                delivery_type="private",
                resource_type="image",
                file_format=optimized_extension,
            )
            return jsonify({"photo_path": path})

        target_dir = current_app.config["AUDIT_EVIDENCE_DIR"] / "qc-sessions" / date_folder
        target_dir.mkdir(parents=True, exist_ok=True)
        generated_filename = f"{generated_name}.{optimized_extension}"
        saved_path = target_dir / generated_filename
        saved_path.write_bytes(optimized_bytes)
        return jsonify({"photo_path": f"uploads/audits/qc-sessions/{date_folder}/{generated_filename}".replace("\\", "/")})
    except Exception:
        raise


@main.route("/api/service/upload-evidence", methods=["POST"])
def upload_service_evidence():
    try:
        if not can_create_audit():
            abort(403)

        item_key = (request.form.get("item_key") or "").strip()
        item_label = (request.form.get("item_label") or "evidencia").strip() or "evidencia"
        service_date = (request.form.get("service_date") or "").strip()
        if not service_date:
            service_date = datetime.today().strftime("%Y-%m-%d")

        try:
            datetime.fromisoformat(service_date)
        except ValueError:
            return jsonify({"error": "service_date invalida."}), 400

        files = request.files.getlist("file") if hasattr(request.files, "getlist") else []
        if not files:
            single = request.files.get("file")
            if single:
                files = [single]

        files = [entry for entry in files if has_uploaded_file(entry)]
        if not files:
            return jsonify({"error": "Debes adjuntar al menos un archivo."}), 400

        date_folder = datetime.fromisoformat(service_date).strftime("%Y/%m")
        if not cloudinary_enabled():
            target_dir = current_app.config["AUDIT_EVIDENCE_DIR"] / "service" / date_folder
            target_dir.mkdir(parents=True, exist_ok=True)

        safe_stem = secure_filename(item_key) or "evidencia"
        base_folder = (current_app.config.get("CLOUDINARY_FOLDER") or "atbb").strip().strip("/")
        cloud_folder = f"{base_folder}/service/{date_folder}"

        saved_paths = []
        for index, entry in enumerate(files):
            _filename, extension = validate_photo_file(entry, item_label)
            generated_name = f"{datetime.utcnow().strftime('%Y%m%d%H%M%S')}_{safe_stem}_{index + 1}_{uuid4().hex[:8]}"
            raw_bytes = entry.stream.read()
            if not raw_bytes:
                return jsonify({"error": f"La evidencia de {item_label} no contiene datos validos."}), 400

            optimized_bytes, optimized_extension = optimize_photo_bytes(raw_bytes, extension, max_dim=2400)
            if cloudinary_enabled():
                uploaded = upload_private_image_to_cloudinary(
                    optimized_bytes,
                    folder=cloud_folder,
                    public_id=generated_name,
                )
                saved_paths.append(
                    encode_cloudinary_ref(
                        uploaded.get("public_id"),
                        version=uploaded.get("version"),
                        delivery_type="private",
                        resource_type="image",
                        file_format=optimized_extension,
                    )
                )
            else:
                generated_filename = f"{generated_name}.{optimized_extension}"
                saved_path = target_dir / generated_filename
                saved_path.write_bytes(optimized_bytes)
                saved_paths.append(
                    f"uploads/audits/service/{date_folder}/{generated_filename}".replace("\\", "/")
                )

        if len(saved_paths) == 1:
            return jsonify({"photo_path": saved_paths[0]})
        return jsonify({"photo_paths": saved_paths})
    except Exception:
        raise


@main.route("/api/service/upload-session-photo", methods=["POST"])
def upload_service_session_photo():
    try:
        if not can_create_audit():
            abort(403)

        service_date = (request.form.get("service_date") or "").strip()
        if not service_date:
            service_date = datetime.today().strftime("%Y-%m-%d")
        try:
            datetime.fromisoformat(service_date)
        except ValueError:
            return jsonify({"error": "service_date invalida."}), 400

        photo_file = request.files.get("file")
        if not has_uploaded_file(photo_file):
            return jsonify({"error": "Debes adjuntar un archivo."}), 400

        _filename, extension = validate_photo_file(photo_file, "foto Service")
        raw_bytes = photo_file.stream.read()
        if not raw_bytes:
            return jsonify({"error": "La foto del Service no contiene datos validos."}), 400

        optimized_bytes, optimized_extension = optimize_photo_bytes(raw_bytes, extension, max_dim=2400)
        date_folder = datetime.fromisoformat(service_date).strftime("%Y/%m")
        generated_name = f"service_session_{uuid4().hex[:8]}_{uuid4().hex[:8]}"

        if cloudinary_enabled():
            base_folder = (current_app.config.get("CLOUDINARY_FOLDER") or "atbb").strip().strip("/")
            folder = f"{base_folder}/service-sessions/{date_folder}"
            uploaded = upload_private_image_to_cloudinary(
                optimized_bytes,
                folder=folder,
                public_id=generated_name,
            )
            path = encode_cloudinary_ref(
                uploaded.get("public_id"),
                version=uploaded.get("version"),
                delivery_type="private",
                resource_type="image",
                file_format=optimized_extension,
            )
            return jsonify({"photo_path": path})

        target_dir = current_app.config["AUDIT_EVIDENCE_DIR"] / "service-sessions" / date_folder
        target_dir.mkdir(parents=True, exist_ok=True)
        generated_filename = f"{generated_name}.{optimized_extension}"
        saved_path = target_dir / generated_filename
        saved_path.write_bytes(optimized_bytes)
        return jsonify({"photo_path": f"uploads/audits/service-sessions/{date_folder}/{generated_filename}".replace('\\', '/')})
    except Exception:
        raise


def persist_auditor_signature(signature_data, audit_date):
    raw_signature = (signature_data or "").strip()
    if not raw_signature:
        raise ValueError("Debes registrar la firma del auditor antes de cerrar la auditoria.")

    prefix = "data:image/png;base64,"
    if not raw_signature.startswith(prefix):
        raise ValueError("La firma del auditor no tiene un formato valido.")

    encoded_signature = raw_signature[len(prefix):]
    try:
        decoded_signature = base64.b64decode(encoded_signature, validate=True)
    except (ValueError, binascii.Error) as exc:
        raise ValueError("No fue posible procesar la firma del auditor.") from exc

    if not decoded_signature:
        raise ValueError("La firma del auditor no contiene datos validos.")
    if not decoded_signature.startswith(b"\x89PNG\r\n\x1a\n"):
        raise ValueError("La firma del auditor no corresponde a un PNG valido.")
    max_signature_bytes = int(current_app.config.get("MAX_SIGNATURE_BYTES") or 0)
    if max_signature_bytes and len(decoded_signature) > max_signature_bytes:
        raise ValueError("La firma del auditor excede el tamaño maximo permitido.")

    date_folder = datetime.fromisoformat(audit_date).strftime("%Y/%m")
    generated_name = f"{datetime.utcnow().strftime('%Y%m%d%H%M%S')}_firma_auditor_{uuid4().hex[:8]}"
    if cloudinary_enabled():
        optimized_signature = optimize_signature_png_bytes(decoded_signature)
        base_folder = (current_app.config.get("CLOUDINARY_FOLDER") or "atbb").strip().strip("/")
        folder = f"{base_folder}/audits/signatures/{date_folder}"
        uploaded = upload_private_image_to_cloudinary(
            optimized_signature,
            folder=folder,
            public_id=generated_name,
        )
        return encode_cloudinary_ref(
            uploaded.get("public_id"),
            version=uploaded.get("version"),
            delivery_type="private",
            resource_type="image",
            file_format="png",
        )

    target_dir = current_app.config["AUDIT_EVIDENCE_DIR"] / "signatures" / date_folder
    target_dir.mkdir(parents=True, exist_ok=True)

    generated_filename = f"{generated_name}.png"
    saved_path = target_dir / generated_filename
    saved_path.write_bytes(optimize_signature_png_bytes(decoded_signature))
    return f"uploads/audits/signatures/{date_folder}/{generated_filename}".replace("\\", "/")


def persist_technician_signature(signature_data, audit_date):
    raw_signature = (signature_data or "").strip()
    if not raw_signature:
        raise ValueError("Debes registrar la firma del tecnico antes de cerrar la auditoria.")

    prefix = "data:image/png;base64,"
    if not raw_signature.startswith(prefix):
        raise ValueError("La firma del tecnico no tiene un formato valido.")

    encoded_signature = raw_signature[len(prefix):]
    try:
        decoded_signature = base64.b64decode(encoded_signature, validate=True)
    except (ValueError, binascii.Error) as exc:
        raise ValueError("No fue posible procesar la firma del tecnico.") from exc

    if not decoded_signature:
        raise ValueError("La firma del tecnico no contiene datos validos.")
    if not decoded_signature.startswith(b"\x89PNG\r\n\x1a\n"):
        raise ValueError("La firma del tecnico no corresponde a un PNG valido.")
    max_signature_bytes = int(current_app.config.get("MAX_SIGNATURE_BYTES") or 0)
    if max_signature_bytes and len(decoded_signature) > max_signature_bytes:
        raise ValueError("La firma del tecnico excede el tamaño maximo permitido.")

    date_folder = datetime.fromisoformat(audit_date).strftime("%Y/%m")
    generated_name = f"{datetime.utcnow().strftime('%Y%m%d%H%M%S')}_firma_tecnico_{uuid4().hex[:8]}"
    if cloudinary_enabled():
        optimized_signature = optimize_signature_png_bytes(decoded_signature)
        base_folder = (current_app.config.get("CLOUDINARY_FOLDER") or "atbb").strip().strip("/")
        folder = f"{base_folder}/audits/signatures/{date_folder}"
        uploaded = upload_private_image_to_cloudinary(
            optimized_signature,
            folder=folder,
            public_id=generated_name,
        )
        return encode_cloudinary_ref(
            uploaded.get("public_id"),
            version=uploaded.get("version"),
            delivery_type="private",
            resource_type="image",
            file_format="png",
        )

    target_dir = current_app.config["AUDIT_EVIDENCE_DIR"] / "signatures" / date_folder
    target_dir.mkdir(parents=True, exist_ok=True)

    generated_filename = f"{generated_name}.png"
    saved_path = target_dir / generated_filename
    saved_path.write_bytes(optimize_signature_png_bytes(decoded_signature))
    return f"uploads/audits/signatures/{date_folder}/{generated_filename}".replace("\\", "/")


def build_grouped_audit_items(items):
    grouped_items = {}
    for item in items:
        grouped_items.setdefault(item["section_title"], []).append(item)
    return grouped_items


def build_audit_report_metrics(audit, items):
    total_items = len(items)
    compliant_statuses = {"cumple", "conforme"}
    non_compliant_statuses = {"no_cumple", "nc_menor", "nc_mayor"}

    def include_in_kpi(item):
        return item["status"] != "no_aplica" and not is_non_imputable_non_compliance(
            item.get("status"), item.get("non_compliance_reason")
        )

    compliant_count = sum(
        1 for item in items if include_in_kpi(item) and item["status"] in compliant_statuses
    )
    non_compliant_count = sum(
        1 for item in items if include_in_kpi(item) and item["status"] in non_compliant_statuses
    )
    not_applicable_count = sum(1 for item in items if item["status"] == "no_aplica")
    applicable_count = compliant_count + non_compliant_count
    evidence_count = sum(1 for item in items if item.get("photo_path"))
    non_imputable_findings = [
        item
        for item in items
        if is_non_imputable_non_compliance(item.get("status"), item.get("non_compliance_reason"))
    ]
    raw_non_compliant_count = sum(1 for item in items if item["status"] in non_compliant_statuses)
    critical_findings = [
        item
        for item in items
        if include_in_kpi(item) and item["status"] in non_compliant_statuses and item["is_critical"]
    ]
    findings = [item for item in items if item["status"] in non_compliant_statuses]

    compliance_rate = 0 if applicable_count == 0 else round((compliant_count / applicable_count) * 100)
    photo_optional_reasons = {"olvido", "perdida", "robo", "no_asignado"}
    photo_optional_items = {"extintor", "seguro_vehicular", "oblea_gnc", "rto", "botiquin"}

    def requires_photo(item):
        item_key = str(item.get("item_key") or "").strip()
        status = str(item.get("status") or "").strip()
        section_key = str(item.get("section_key") or "").strip()
        reason = str(item.get("non_compliance_reason") or "").strip().lower()
        if item_key in photo_optional_items:
            return False
        if section_key == "calidad_instalaciones" and status in {"nc_menor", "nc_mayor"}:
            return True
        if status == "no_cumple" and reason not in photo_optional_reasons:
            return True
        return False

    evidence_required_count = sum(1 for item in items if requires_photo(item))
    evidence_with_photo_count = sum(
        1 for item in items if requires_photo(item) and item.get("photo_path")
    )
    evidence_rate = (
        0
        if evidence_required_count == 0
        else round((evidence_with_photo_count / evidence_required_count) * 100)
    )

    sections = []
    grouped_items = build_grouped_audit_items(items)
    for section_title, section_items in grouped_items.items():
        section_compliant = sum(
            1
            for item in section_items
            if include_in_kpi(item) and item["status"] in compliant_statuses
        )
        section_non_compliant = sum(
            1
            for item in section_items
            if include_in_kpi(item) and item["status"] in non_compliant_statuses
        )
        section_applicable = section_compliant + section_non_compliant
        section_score = 0 if section_applicable == 0 else round((section_compliant / section_applicable) * 100)
        section_raw_non_compliant = sum(
            1 for item in section_items if item["status"] in non_compliant_statuses
        )
        section_non_imputable = sum(
            1
            for item in section_items
            if is_non_imputable_non_compliance(item.get("status"), item.get("non_compliance_reason"))
        )
        sections.append(
            {
                "title": section_title,
                "score": section_score,
                "compliant_count": section_compliant,
                "non_compliant_count": section_non_compliant,
                "raw_non_compliant_count": section_raw_non_compliant,
                "non_imputable_count": section_non_imputable,
                "not_applicable_count": sum(1 for item in section_items if item["status"] == "no_aplica"),
                "critical_count": sum(
                    1
                    for item in section_items
                    if include_in_kpi(item)
                    and item["status"] in non_compliant_statuses
                    and item["is_critical"]
                ),
            }
        )

    circumference = 2 * 3.1416 * 54
    progress_value = max(0, min(100, audit["total_score"]))
    ring_offset = round(circumference * (1 - (progress_value / 100)), 2)

    return {
        "summary": {
            "total_items": total_items,
            "applicable_count": applicable_count,
            "compliant_count": compliant_count,
            "non_compliant_count": non_compliant_count,
            "raw_non_compliant_count": raw_non_compliant_count,
            "not_applicable_count": not_applicable_count,
            "critical_findings_count": len(critical_findings),
            "findings_count": len(findings),
            "non_imputable_findings_count": len(non_imputable_findings),
            "evidence_count": evidence_count,
            "compliance_rate": compliance_rate,
            "evidence_rate": evidence_rate,
        },
        "sections": sections,
        "critical_findings": critical_findings,
        "findings": findings,
        "non_imputable_findings": non_imputable_findings,
        "evidence_items": [item for item in items if item.get("photo_path")],
        "score_ring": {
            "circumference": round(circumference, 2),
            "offset": ring_offset,
        },
    }


@main.route("/")
def dashboard():
    user = current_user()
    auditor_user_id = user["id"] if user and user.get("role") == "auditor" else None
    supervisor_scope_names = current_supervisor_scope_names()
    try:
        recent_audits = fetch_recent_audits(
            auditor_user_id=auditor_user_id,
            supervisor_scope_names=supervisor_scope_names,
        )
    except Exception:
        recent_audits = []

    try:
        stats = fetch_dashboard_stats(
            auditor_user_id=auditor_user_id,
            supervisor_scope_names=supervisor_scope_names,
        )
    except Exception:
        stats = {"total_audits": 0, "approved_count": 0, "critical_count": 0, "approval_rate": 0}

    if can_view_findings():
        try:
            finding_stats = fetch_finding_stats(
                auditor_user_id=auditor_user_id,
                supervisor_scope_names=supervisor_scope_names,
            )
        except Exception:
            finding_stats = None
    else:
        finding_stats = None

    effectiveness_alerts = None
    if user and user.get("role") == "auditor":
        try:
            effectiveness_alerts = fetch_effectiveness_alerts(
                auditor_user_id=user["id"],
                supervisor_scope_names=None,
            )
        except Exception:
            effectiveness_alerts = None

    finding_donut = None
    if user and user.get("role") == "supervisor" and can_view_findings():
        try:
            status_rows = fetch_finding_status_breakdown(
                auditor_user_id=None,
                supervisor_scope_names=supervisor_scope_names,
            )
            counts = {str(row.get("finding_status") or "").strip().lower(): (row.get("findings_count") or 0) for row in status_rows}
            ordered = ["nuevo", "respondido", "resuelto", "reabierto", "cerrado_definitivo"]
            status_total = sum(counts.get(key, 0) for key in ordered)
            palette = {
                "nuevo": "#6B7280",
                "respondido": "#2563EB",
                "resuelto": "#F59E0B",
                "reabierto": "#DC2626",
                "cerrado_definitivo": "#16A34A",
            }
            circumference = round(2 * 3.1416 * 54, 2)
            donut_segments = []
            offset_accum = 0.0
            for key in ordered:
                count = counts.get(key, 0)
                percent = 0.0 if status_total == 0 else round((count / status_total) * 100, 1)
                segment_len = 0.0 if percent == 0 else round(circumference * (percent / 100), 2)
                donut_segments.append(
                    {
                        "key": key,
                        "label": finding_status_label(key),
                        "count": count,
                        "percent": percent,
                        "color": palette.get(key, "#2563EB"),
                        "dasharray": f"{segment_len} {round(circumference - segment_len, 2)}",
                        "dashoffset": round(-offset_accum, 2),
                    }
                )
                offset_accum += segment_len
            finding_donut = {"status_total": status_total, "donut_segments": donut_segments}
        except Exception:
            current_app.logger.exception("Error al calcular donut de estados de hallazgos (supervisor)")
            finding_donut = None

    safety_risk_donut = None
    if user and user.get("role") in {"admin", "gerente"} and can_view_findings():
        try:
            status_rows = fetch_finding_status_breakdown(
                filters={"priority": "alta"},
                auditor_user_id=None,
                supervisor_scope_names=None,
            )
            counts = {str(row.get("finding_status") or "").strip().lower(): (row.get("findings_count") or 0) for row in status_rows}
            ordered = ["nuevo", "respondido", "resuelto", "reabierto", "cerrado_definitivo"]
            status_total = sum(counts.get(key, 0) for key in ordered)
            palette = {
                "nuevo": "#6B7280",
                "respondido": "#2563EB",
                "resuelto": "#F59E0B",
                "reabierto": "#DC2626",
                "cerrado_definitivo": "#16A34A",
            }
            circumference = round(2 * 3.1416 * 54, 2)
            donut_segments = []
            offset_accum = 0.0
            for key in ordered:
                count = counts.get(key, 0)
                percent = 0.0 if status_total == 0 else round((count / status_total) * 100, 1)
                segment_len = 0.0 if percent == 0 else round(circumference * (percent / 100), 2)
                donut_segments.append(
                    {
                        "key": key,
                        "label": finding_status_label(key),
                        "count": count,
                        "percent": percent,
                        "color": palette.get(key, "#2563EB"),
                        "dasharray": f"{segment_len} {round(circumference - segment_len, 2)}",
                        "dashoffset": round(-offset_accum, 2),
                    }
                )
                offset_accum += segment_len
            safety_risk_donut = {"status_total": status_total, "donut_segments": donut_segments}
        except Exception:
            current_app.logger.exception("Error al calcular donut de riesgo (hallazgos alta prioridad)")
            safety_risk_donut = None

    return render_template(
        "dashboard.html",
        page_class="page-dashboard",
        recent_audits=recent_audits,
        total_audits=stats["total_audits"],
        approval_rate=stats["approval_rate"],
        critical_count=stats["critical_count"],
        finding_stats=finding_stats,
        finding_donut=finding_donut,
        safety_risk_donut=safety_risk_donut,
        effectiveness_alerts=effectiveness_alerts,
    )


@main.route("/tnps", methods=["GET", "POST"])
def tnps():
    if request.method == "POST" and not can_import():
        abort(403)

    qc_context = None
    qc_id_context_raw = request.args.get("qc_id", "").strip()
    if qc_id_context_raw:
        try:
            qc_id_context = int(qc_id_context_raw)
        except ValueError:
            flash("El ID de QC no es valido.", "error")
            qc_id_context = None
        if qc_id_context is not None:
            qc_context = fetch_qc_session_detail(qc_id_context, supervisor_scope_names=current_supervisor_scope_names())
            if qc_context and is_auditor() and qc_context.get("auditor_user_id") != current_user()["id"]:
                qc_context = None
            if not qc_context:
                flash("No se encontro el QC indicado para vincular el tNPS.", "error")

    audit_context = None
    audit_id_context_raw = request.args.get("audit_id", "").strip()
    if audit_id_context_raw:
        try:
            audit_id_context = int(audit_id_context_raw)
        except ValueError:
            flash("El ID de auditoria no es valido.", "error")
            audit_id_context = None
        if audit_id_context is not None:
            audit_context = fetch_audit_detail(audit_id_context)
            if audit_context and is_auditor() and audit_context.get("auditor_user_id") != current_user()["id"]:
                audit_context = None
            if not audit_context:
                flash("No se encontro la auditoria indicada para vincular el tNPS.", "error")

    filters = {
        "from_date": request.args.get("from_date", "").strip(),
        "to_date": request.args.get("to_date", "").strip(),
        "technician_id": request.args.get("technician_id", "").strip(),
        "min_n": request.args.get("min_n", "").strip(),
    }

    technician_id = None
    if filters["technician_id"]:
        try:
            technician_id = int(filters["technician_id"])
        except ValueError:
            flash("El tecnico seleccionado no es valido.", "error")
            filters["technician_id"] = ""

    min_n = 20
    if filters["min_n"]:
        try:
            min_n = max(1, int(filters["min_n"]))
        except ValueError:
            flash("El minimo de respuestas no es valido.", "error")
            filters["min_n"] = ""

    query_filters = {
        "from_date": filters["from_date"],
        "to_date": filters["to_date"],
        "technician_id": technician_id,
    }

    if request.method == "POST":
        try:
            def parse_optional_scale(field_name, label, min_value=1, max_value=10):
                raw = (request.form.get(field_name) or "").strip()
                if raw == "":
                    return None
                try:
                    value = int(raw)
                except ValueError as exc:
                    raise ValueError(f"{label} debe ser un numero entre {min_value} y {max_value}.") from exc
                if value < min_value or value > max_value:
                    raise ValueError(f"{label} debe estar entre {min_value} y {max_value}.")
                return value

            def parse_optional_yes_no(field_name, label):
                raw = (request.form.get(field_name) or "").strip()
                if raw == "":
                    return None
                if raw not in {"0", "1"}:
                    raise ValueError(f"{label} debe ser 'Si' o 'No'.")
                return int(raw)

            response_date = datetime.strptime(request.form["response_date"], "%Y-%m-%d").date().isoformat()
            score_raw = (request.form.get("score") or "").strip()
            if score_raw == "":
                raise ValueError("Debes ingresar un puntaje entre 0 y 10.")
            score = int(score_raw)
            if score < 0 or score > 10:
                raise ValueError("El puntaje debe estar entre 0 y 10.")

            audit_id_raw = (request.form.get("audit_id") or "").strip()
            audit_id = None
            if audit_id_raw:
                try:
                    audit_id = int(audit_id_raw)
                except ValueError as exc:
                    raise ValueError("El ID de auditoria no es valido.") from exc

            qc_session_id_raw = (request.form.get("qc_session_id") or request.args.get("qc_id") or "").strip()
            qc_session_id = None
            qc_locked = None
            if qc_session_id_raw:
                try:
                    qc_session_id = int(qc_session_id_raw)
                except ValueError as exc:
                    raise ValueError("El ID de QC no es valido.") from exc
                qc_locked = fetch_qc_session_detail(qc_session_id, supervisor_scope_names=current_supervisor_scope_names())
                if not qc_locked:
                    raise ValueError("No se encontro el QC indicado para vincular el tNPS.")
                if is_auditor() and qc_locked.get("auditor_user_id") != current_user()["id"]:
                    raise ValueError("No tienes permiso para vincular este QC.")
                if audit_id is None and qc_locked.get("audit_id"):
                    audit_id = qc_locked.get("audit_id")

            locked_technician_id = None
            if qc_locked is not None:
                locked_technician_id = qc_locked.get("technician_id")
            elif audit_id is not None:
                locked_audit = fetch_audit_detail(audit_id)
                if not locked_audit:
                    raise ValueError("No se encontro la auditoria indicada para vincular el tNPS.")
                locked_technician_id = locked_audit.get("technician_id")
            else:
                form_technician_id_raw = (request.form.get("technician_id") or "").strip()
                if form_technician_id_raw:
                    try:
                        locked_technician_id = int(form_technician_id_raw)
                    except ValueError as exc:
                        raise ValueError("El tecnico seleccionado no es valido.") from exc

            create_tnps_response(
                response_date=response_date,
                score=score,
                booking_ease_score=parse_optional_scale("booking_ease_score", "Facilidad para coordinar"),
                punctuality_score=parse_optional_scale("punctuality_score", "Puntualidad del tecnico"),
                communication_clarity_score=parse_optional_scale("communication_clarity_score", "Claridad de la explicacion"),
                issue_resolved_first_visit=parse_optional_yes_no(
                    "issue_resolved_first_visit",
                    "Resolucion en primera visita",
                ),
                router_optimal_location=parse_optional_yes_no(
                    "router_optimal_location",
                    "Router en el lugar optimo",
                ),
                environment_clean_order=parse_optional_yes_no(
                    "environment_clean_order",
                    "Orden y limpieza del entorno",
                ),
                speedtest_done=parse_optional_yes_no(
                    "speedtest_done",
                    "Prueba de velocidad frente al cliente",
                ),
                comment=(request.form.get("comment") or "").strip(),
                customer_name=(request.form.get("customer_name") or "").strip(),
                technician_id=locked_technician_id,
                audit_id=audit_id,
                qc_session_id=qc_session_id,
            )
            flash("Respuesta tNPS registrada.", "success")
            if audit_id is not None:
                return redirect(url_for("main.audit_report", audit_id=audit_id))
            if qc_session_id is not None:
                return redirect(url_for("main.qc_detail", qc_session_id=qc_session_id))
            return redirect(url_for("main.tnps"))
        except (KeyError, ValueError) as exc:
            flash(str(exc), "error")

    technicians = fetch_technicians()
    stats = fetch_tnps_stats(query_filters)
    technician_rankings = fetch_tnps_technician_rankings(query_filters, min_responses=min_n)
    responses = fetch_tnps_responses(query_filters)

    return render_template(
        "tnps.html",
        filters=filters,
        technicians=technicians,
        stats=stats,
        technician_rankings=technician_rankings,
        min_n=min_n,
        responses=responses,
        audit_context=audit_context,
        qc_context=qc_context,
        today=(qc_context.get("qc_date") if qc_context else datetime.now().date().isoformat()),
        page_class="page-wide",
    )


def qc_section_definition():
    section = next((entry for entry in CHECKLIST_SECTIONS if entry.get("key") == QC_SECTION_KEY), None)
    if not section:
        raise RuntimeError(f"No existe la sección '{QC_SECTION_KEY}' en el checklist.")
    return section


def service_item_definitions():
    return [
        {
            "key": "modem_location",
            "label": "Ubicación final del módem en punto principal del domicilio",
            "critical": True,
        },
        {
            "key": "coverage",
            "label": "Cobertura WiFi corresponde en los distintos espacios",
            "critical": True,
        },
        {
            "key": "devices_verified",
            "label": "Verificación de dispositivos del cliente",
            "critical": False,
        },
        {
            "key": "speedtests",
            "label": "Test de velocidad realizado en diferentes espacios",
            "critical": True,
        },
        {
            "key": "optical_power",
            "label": "Potencia óptica: diferencia <= 1 dBm",
            "critical": True,
        },
    ]


def service_speedtest_spaces():
    return [
        {"key": "principal", "label": "Punto principal"},
        {"key": "habitacion", "label": "Habitación"},
        {"key": "alejado", "label": "Punto más alejado"},
    ]


@main.route("/service")
def service_sessions():
    if not current_user():
        return redirect(url_for("main.login"))
    if not can_view_service():
        abort(403)

    user = current_user()
    auditor_user_id = user["id"] if user and user.get("role") == "auditor" else None
    filters = {
        "from_date": request.args.get("from_date", "").strip(),
        "to_date": request.args.get("to_date", "").strip(),
        "status": request.args.get("status", "").strip(),
        "technician_id": request.args.get("technician_id", "").strip(),
        "q": request.args.get("q", "").strip(),
        "include_pruebas": "1" if request.args.get("include_pruebas") else "",
        "sort": request.args.get("sort", "").strip(),
        "dir": request.args.get("dir", "").strip(),
    }

    technician_id = None
    if filters["technician_id"]:
        try:
            technician_id = int(filters["technician_id"])
        except ValueError:
            flash("El técnico seleccionado no es válido.", "error")
            filters["technician_id"] = ""

    query_filters = {
        "from_date": filters["from_date"],
        "to_date": filters["to_date"],
        "status": filters["status"],
        "technician_id": technician_id,
        "q": filters["q"],
        "include_pruebas": filters["include_pruebas"],
        "sort": filters["sort"],
        "dir": filters["dir"],
    }

    sessions = fetch_service_sessions(
        query_filters,
        auditor_user_id=auditor_user_id,
        supervisor_scope_names=current_supervisor_scope_names(),
    )
    technicians = fetch_technicians()
    filter_active = any(
        [
            filters["from_date"],
            filters["to_date"],
            filters["status"],
            filters["technician_id"],
            filters["q"],
            filters["include_pruebas"],
        ]
    )

    return render_template(
        "service_sessions.html",
        sessions=sessions,
        filters=filters,
        technicians=technicians,
        filter_active=filter_active,
        audit_official_from_date=get_audit_official_from_date(),
        page_class="page-wide",
    )


@main.route("/service/new", methods=["GET", "POST"])
def service_new():
    if not can_create_audit():
        abort(403)

    technicians = fetch_technicians()
    today = datetime.now().date().isoformat()
    items_def = service_item_definitions()
    spaces = service_speedtest_spaces()

    if request.method == "POST":
        try:
            service_date = (request.form.get("service_date") or "").strip() or today
            datetime.fromisoformat(service_date)

            technician_id_raw = (request.form.get("technician_id") or "").strip()
            if not technician_id_raw:
                raise ValueError("Debes seleccionar un técnico.")
            try:
                technician_id = int(technician_id_raw)
            except ValueError as exc:
                raise ValueError("El técnico seleccionado no es válido.") from exc

            location = (request.form.get("location") or "").strip()
            if not location:
                raise ValueError("La provincia es obligatoria.")
            address = (request.form.get("address") or "").strip()
            sa_number = (request.form.get("sa_number") or "").strip()
            record_scope = (request.form.get("record_scope") or "").strip().lower() or "oficial"
            if record_scope not in {"oficial", "pruebas"}:
                raise ValueError("El sector seleccionado no es válido.")

            location = location.strip().upper()
            address = address.strip().upper()
            sa_number = sa_number.strip()
            if sa_number and not sa_number.isdigit():
                raise ValueError("El SA debe contener solo números.")

            def parse_optional_float(field_name, label):
                raw = (request.form.get(field_name) or "").strip()
                if raw == "":
                    return None
                try:
                    return float(raw.replace(",", "."))
                except ValueError as exc:
                    raise ValueError(f"{label} debe ser un número válido.") from exc

            optical_expected_dbm = parse_optional_float("optical_expected_dbm", "Potencia óptica esperada (dBm)")
            optical_measured_dbm = parse_optional_float("optical_measured_dbm", "Potencia óptica medida (dBm)")
            if optical_expected_dbm is None or optical_measured_dbm is None:
                raise ValueError("Debes ingresar la potencia óptica esperada y la medida.")
            optical_delta_dbm = round(abs(optical_measured_dbm - optical_expected_dbm), 2)

            items = []
            for entry in items_def:
                key = entry["key"]
                status = (request.form.get(f"status__{key}") or "").strip().lower()
                if not status:
                    raise ValueError("Debes completar el checklist de service.")
                if status not in {"conforme", "nc_menor", "nc_mayor", "no_aplica"}:
                    raise ValueError("El estado seleccionado no es válido.")
                notes = (request.form.get(f"notes__{key}") or "").strip().upper() or None

                uploaded_raw = (request.form.get(f"uploaded_photo_path__{key}") or "").strip()
                uploaded_value = uploaded_raw if uploaded_raw and uploaded_raw != "-" else None
                if uploaded_value and uploaded_value.startswith("[") and uploaded_value.endswith("]"):
                    try:
                        parsed = json.loads(uploaded_value)
                        if isinstance(parsed, list):
                            uploaded_value = json.dumps(parsed, ensure_ascii=False)
                    except Exception:
                        pass

                photo_files = []
                file_input = request.files.get(f"photo__{key}")
                if has_uploaded_file(file_input):
                    photo_files.append(file_input)
                camera_input = request.files.get(f"photo_camera__{key}")
                if has_uploaded_file(camera_input):
                    photo_files.append(camera_input)

                item_payload = {
                    "item_key": key,
                    "item_label": entry["label"],
                    "status": status,
                    "is_critical": bool(entry.get("critical")),
                    "notes": notes,
                    "photo_path": uploaded_value,
                }
                if photo_files:
                    item_payload["photo_files"] = photo_files
                items.append(item_payload)

            optical_item = next((it for it in items if it.get("item_key") == "optical_power"), None)
            if optical_item:
                optical_item["status"] = "conforme" if optical_delta_dbm <= 1 else "nc_mayor"

            persist_service_item_evidence(items, service_date)

            for item in items:
                photo_path = (item.get("photo_path") or "").strip()
                status = str(item.get("status") or "").strip().lower()
                needs_evidence = bool(item.get("is_critical")) and status in {"nc_menor", "nc_mayor"}
                if item.get("item_key") == "optical_power" and optical_delta_dbm > 1:
                    needs_evidence = True
                if needs_evidence:
                    if not photo_path or photo_path == "-":
                        raise ValueError("Debes adjuntar evidencia en los ítems críticos no conformes.")
                    if photo_path.startswith("[") and photo_path.endswith("]"):
                        try:
                            parsed = json.loads(photo_path)
                        except Exception:
                            parsed = []
                        if not parsed:
                            raise ValueError("Debes adjuntar evidencia en los ítems críticos no conformes.")
                        for candidate in parsed:
                            value = str(candidate or "").strip()
                            if not value or value == "-":
                                continue
                            if not (decode_cloudinary_ref(value) or _resolve_uploads_relative_path(value)):
                                raise ValueError("La evidencia adjunta no es válida.")
                    else:
                        if not (decode_cloudinary_ref(photo_path) or _resolve_uploads_relative_path(photo_path)):
                            raise ValueError("La evidencia adjunta no es válida.")

            def item_points(status_value):
                raw = str(status_value or "").strip().lower()
                if raw == "conforme":
                    return 1.0
                if raw == "nc_menor":
                    return 0.6
                if raw == "nc_mayor":
                    return 0.0
                return None

            points = []
            has_major_nc = False
            for item in items:
                status = str(item.get("status") or "").strip().lower()
                if status == "nc_mayor":
                    has_major_nc = True
                p = item_points(status)
                if p is None:
                    continue
                points.append(p)

            ratio = 1.0 if not points else (sum(points) / float(len(points)))
            ratio = max(0.0, min(1.0, ratio))
            total_score = round(ratio * 100, 2)

            if has_major_nc:
                result_status = "Rechazada"
            elif total_score >= 90:
                result_status = "Aprobada"
            elif total_score >= 75:
                result_status = "Aprobada con observaciones"
            else:
                result_status = "Rechazada"

            speedtests = []
            for space in spaces:
                key = space["key"]
                label = space["label"]
                down = parse_optional_float(f"speedtest_down__{key}", f"Descarga ({label})")
                up = parse_optional_float(f"speedtest_up__{key}", f"Subida ({label})")
                ping = parse_optional_float(f"speedtest_ping__{key}", f"Ping ({label})")
                if down is None or up is None or ping is None:
                    raise ValueError("Debes registrar los tests de velocidad en los espacios definidos.")
                speedtests.append(
                    {
                        "space_key": key,
                        "space_label": label,
                        "download_mbps": down,
                        "upload_mbps": up,
                        "ping_ms": ping,
                    }
                )

            uploaded_photo_path_raw = (request.form.get("uploaded_service_photo_path") or "").strip()
            uploaded_photo_path = uploaded_photo_path_raw if uploaded_photo_path_raw and uploaded_photo_path_raw != "-" else None
            if uploaded_photo_path and not (decode_cloudinary_ref(uploaded_photo_path) or _resolve_uploads_relative_path(uploaded_photo_path)):
                raise ValueError("La foto del service no es válida.")

            service_photo_file = request.files.get("service_photo")
            if not has_uploaded_file(service_photo_file):
                service_photo_file = request.files.get("service_photo_camera")
            session_photo_path = uploaded_photo_path or persist_service_session_evidence(service_photo_file, service_date)

            technician_row = next((t for t in technicians if t.get("id") == technician_id), None)
            technician_name = (technician_row.get("name") if technician_row else "") or ""
            technician_employee_code = (technician_row.get("employee_code") if technician_row else "") or ""
            technician_company = (technician_row.get("company_name") if technician_row else "") or ""
            technician_supervisor = (technician_row.get("supervisor_name") if technician_row else "") or ""
            technician_center = (technician_row.get("center_name") if technician_row else "") or ""

            technician_name = technician_name.strip().upper()
            technician_employee_code = technician_employee_code.strip().upper()
            technician_company = technician_company.strip().upper()
            technician_supervisor = technician_supervisor.strip().upper()
            technician_center = technician_center.strip().upper()

            general_notes = (request.form.get("general_notes") or "").strip().upper() or None

            service_data = {
                "service_date": service_date,
                "auditor_name": current_user()["username"],
                "auditor_user_id": current_user().get("id"),
                "sa_number": sa_number or None,
                "technician_display_name": technician_name or None,
                "technician_employee_code": technician_employee_code or None,
                "technician_company_snapshot": technician_company or None,
                "technician_supervisor_snapshot": technician_supervisor or None,
                "technician_center_snapshot": technician_center or None,
                "technician_id": technician_id,
                "location": location,
                "address": address or None,
                "optical_expected_dbm": optical_expected_dbm,
                "optical_measured_dbm": optical_measured_dbm,
                "optical_delta_dbm": optical_delta_dbm,
                "total_score": total_score,
                "result_status": result_status,
                "record_scope": record_scope,
                "general_notes": general_notes,
                "photo_path": session_photo_path,
            }

            service_session_id = create_service_session(service_data, items, speedtests)
            flash("Auditoría Service registrada.", "success")
            return redirect(url_for("main.service_detail", service_session_id=service_session_id))
        except (KeyError, ValueError) as exc:
            flash(str(exc), "error")

    return render_template(
        "service_form.html",
        technicians=technicians,
        today=today,
        items=items_def,
        spaces=spaces,
        page_class="page-wide",
    )


@main.route("/service/<int:service_session_id>")
def service_detail(service_session_id):
    if not can_view_service():
        abort(403)

    session_row = fetch_service_session_detail(
        service_session_id,
        supervisor_scope_names=current_supervisor_scope_names(),
    )
    if not session_row:
        abort(404)
    if is_auditor() and session_row.get("auditor_user_id") != current_user()["id"]:
        abort(404)

    items = fetch_service_items(service_session_id)
    speedtests = fetch_service_speedtests(service_session_id)
    return render_template(
        "service_detail.html",
        service=session_row,
        items=items,
        speedtests=speedtests,
        page_class="page-wide",
    )


@main.route("/service/<int:service_session_id>/report")
def service_report(service_session_id):
    if not can_view_service():
        abort(403)

    session_row = fetch_service_session_detail(
        service_session_id,
        supervisor_scope_names=current_supervisor_scope_names(),
    )
    if not session_row:
        abort(404)
    if is_auditor() and session_row.get("auditor_user_id") != current_user()["id"]:
        abort(404)

    expires_in_seconds = 3600 if request.args.get("print") == "1" else 900
    items = fetch_service_items(service_session_id)
    speedtests = fetch_service_speedtests(service_session_id)

    response = make_response(
        render_template(
            "service_report.html",
            service=session_row,
            items=items,
            speedtests=speedtests,
            print_mode=request.args.get("print") == "1",
            inline_css="",
            expires_in_seconds=expires_in_seconds,
        )
    )
    response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "0"
    return response


@main.route("/service/<int:service_session_id>/report.pdf")
def service_report_pdf(service_session_id):
    if not can_view_service():
        abort(403)

    session_row = fetch_service_session_detail(
        service_session_id,
        supervisor_scope_names=current_supervisor_scope_names(),
    )
    if not session_row:
        abort(404)
    if is_auditor() and session_row.get("auditor_user_id") != current_user()["id"]:
        abort(404)

    items = fetch_service_items(service_session_id)
    speedtests = fetch_service_speedtests(service_session_id)

    css_path = Path(current_app.root_path) / "static" / "css" / "main.css"
    inline_css = css_path.read_text(encoding="utf-8") if css_path.exists() else ""

    date_suffix = (session_row.get("service_date") or "sin_fecha").strip().replace("/", "-")
    filename = secure_filename(f"service_{service_session_id}_{date_suffix}.pdf") or f"service_{service_session_id}.pdf"
    filename_override = (request.args.get("filename") or "").strip()
    if filename_override:
        normalized_override = secure_filename(filename_override) or filename
        if not normalized_override.lower().endswith(".pdf"):
            normalized_override = f"{normalized_override}.pdf"
        filename = normalized_override

    html = render_template(
        "service_report.html",
        service=session_row,
        items=items,
        speedtests=speedtests,
        print_mode=True,
        inline_css=inline_css,
        expires_in_seconds=3600,
    )
    try:
        return build_pdf_from_html_response(html, filename)
    except Exception as exc:
        current_app.logger.exception("Error generando PDF Service %s", service_session_id)
        flash(str(exc), "error")
        return redirect(url_for("main.service_report", service_session_id=service_session_id, print=1))


@main.route("/qc")
def qc_sessions():
    if not current_user():
        return redirect(url_for("main.login"))

    user = current_user()
    auditor_user_id = user["id"] if user and user.get("role") == "auditor" else None
    filters = {
        "from_date": request.args.get("from_date", "").strip(),
        "to_date": request.args.get("to_date", "").strip(),
        "status": request.args.get("status", "").strip(),
        "technician_id": request.args.get("technician_id", "").strip(),
        "q": request.args.get("q", "").strip(),
        "include_pruebas": "1" if request.args.get("include_pruebas") else "",
        "sort": request.args.get("sort", "").strip(),
        "dir": request.args.get("dir", "").strip(),
    }

    technician_id = None
    if filters["technician_id"]:
        try:
            technician_id = int(filters["technician_id"])
        except ValueError:
            flash("El técnico seleccionado no es válido.", "error")
            filters["technician_id"] = ""

    query_filters = {
        "from_date": filters["from_date"],
        "to_date": filters["to_date"],
        "status": filters["status"],
        "technician_id": technician_id,
        "q": filters["q"],
        "include_pruebas": filters["include_pruebas"],
        "sort": filters["sort"],
        "dir": filters["dir"],
    }

    sessions = fetch_qc_sessions(
        query_filters,
        auditor_user_id=auditor_user_id,
        supervisor_scope_names=current_supervisor_scope_names(),
    )
    technicians = fetch_technicians()
    filter_active = any(
        [
            filters["from_date"],
            filters["to_date"],
            filters["status"],
            filters["technician_id"],
            filters["q"],
            filters["include_pruebas"],
        ]
    )

    return render_template(
        "qc_sessions.html",
        sessions=sessions,
        filters=filters,
        technicians=technicians,
        filter_active=filter_active,
        audit_official_from_date=get_audit_official_from_date(),
        page_class="page-wide",
    )


@main.route("/qc/new", methods=["GET", "POST"])
def qc_new():
    if not can_create_audit():
        abort(403)

    audit_context = None
    audit_id_context_raw = request.args.get("audit_id", "").strip()
    if audit_id_context_raw:
        try:
            audit_id_context = int(audit_id_context_raw)
        except ValueError:
            flash("El ID de auditoría no es válido.", "error")
            audit_id_context = None
        if audit_id_context is not None:
            audit_context = fetch_audit_detail(audit_id_context, supervisor_scope_names=current_supervisor_scope_names())
            if audit_context and is_auditor() and audit_context.get("auditor_user_id") != current_user()["id"]:
                audit_context = None
            if not audit_context:
                flash("No se encontró la auditoría indicada para vincular el QC.", "error")

    section = qc_section_definition()
    technicians = fetch_technicians()
    today = datetime.now().date().isoformat()

    if request.method == "POST":
        try:
            qc_date = (request.form.get("qc_date") or "").strip() or today
            datetime.fromisoformat(qc_date)

            audit_id_raw = (request.form.get("audit_id") or "").strip()
            audit_id = None
            if audit_id_raw:
                try:
                    audit_id = int(audit_id_raw)
                except ValueError as exc:
                    raise ValueError("El ID de auditoría no es válido.") from exc

            locked_audit = None
            locked_technician_id = None
            if audit_id is not None:
                locked_audit = fetch_audit_detail(audit_id, supervisor_scope_names=current_supervisor_scope_names())
                if not locked_audit:
                    raise ValueError("No se encontró la auditoría indicada para vincular el QC.")
                if is_auditor() and locked_audit.get("auditor_user_id") != current_user()["id"]:
                    raise ValueError("No tienes permiso para vincular esta auditoría.")
                locked_technician_id = locked_audit.get("technician_id")

            if locked_technician_id is None:
                technician_id_raw = (request.form.get("technician_id") or "").strip()
                if not technician_id_raw:
                    raise ValueError("Debes seleccionar un técnico.")
                try:
                    locked_technician_id = int(technician_id_raw)
                except ValueError as exc:
                    raise ValueError("El técnico seleccionado no es válido.") from exc

            location = (request.form.get("location") or "").strip()
            installation_type = (request.form.get("installation_type") or "").strip()
            if locked_audit:
                if not location:
                    location = locked_audit.get("location") or ""
                if not installation_type:
                    installation_type = locked_audit.get("installation_type") or ""

            if not location:
                raise ValueError("La provincia es obligatoria.")
            if not installation_type:
                raise ValueError("El tipo de instalación es obligatorio.")

            address = (request.form.get("address") or "").strip()
            sa_number = (request.form.get("sa_number") or "").strip()
            record_scope = (request.form.get("record_scope") or "").strip().lower() or "oficial"
            if record_scope not in {"oficial", "pruebas"}:
                raise ValueError("El sector seleccionado no es válido.")

            qc_live_installation_raw = (request.form.get("qc_live_installation") or "").strip()
            qc_live_installation = qc_live_installation_raw in {"1", "true", "yes", "si", "sí", "on"}

            installation_duration_minutes = None
            cable_type = None
            cable_meters = None

            if qc_live_installation:
                duration_raw = (request.form.get("installation_duration_minutes") or "").strip()
                if not duration_raw:
                    raise ValueError("Debes indicar los minutos totales de la instalación.")
                try:
                    installation_duration_minutes = int(duration_raw)
                except ValueError as exc:
                    raise ValueError("Los minutos totales de la instalación no son válidos.") from exc
                if installation_duration_minutes <= 0 or installation_duration_minutes > (24 * 60):
                    raise ValueError("Los minutos totales de la instalación deben estar entre 1 y 1440.")

                cable_type = (request.form.get("cable_type") or "").strip().lower()
                allowed_cable_types = {"drop_40", "drop_70", "drop_100", "drop_150", "bobina"}
                if cable_type not in allowed_cable_types:
                    raise ValueError("Debes seleccionar el tipo de cable utilizado.")

                if cable_type == "bobina":
                    meters_raw = (request.form.get("cable_meters") or "").strip()
                    if not meters_raw:
                        raise ValueError("Debes indicar los metros utilizados (bobina).")
                    try:
                        cable_meters = int(meters_raw)
                    except ValueError as exc:
                        raise ValueError("Los metros utilizados no son válidos.") from exc
                    if cable_meters < 151 or cable_meters > 500:
                        raise ValueError("Los metros utilizados para bobina deben estar entre 151 y 500.")
                else:
                    fixed_meters = {
                        "drop_40": 40,
                        "drop_70": 70,
                        "drop_100": 100,
                        "drop_150": 150,
                    }
                    cable_meters = fixed_meters.get(cable_type)

            section_score, _has_critical, items = calculate_section_score(section, request.form, request.files)
            ratio = 1 if section.get("weight") in {0, None} else (section_score / float(section["weight"]))
            ratio = max(0.0, min(1.0, ratio))
            qc_score = round(ratio * 100, 2)

            has_major_nc = any(str(it.get("status") or "").strip().lower() == "nc_mayor" for it in items)
            if has_major_nc:
                result_status = "Rechazada"
            elif qc_score >= 90:
                result_status = "Aprobada"
            elif qc_score >= 75:
                result_status = "Aprobada con observaciones"
            else:
                result_status = "Rechazada"

            persist_qc_item_evidence(items, qc_date)
            def parse_qc_photo_paths(raw_value):
                raw = (raw_value or "").strip()
                if not raw or raw == "-":
                    return []
                if raw.startswith("[") and raw.endswith("]"):
                    try:
                        parsed = json.loads(raw)
                    except json.JSONDecodeError:
                        parsed = None
                    if isinstance(parsed, list):
                        cleaned = []
                        for entry in parsed:
                            value = str(entry or "").strip()
                            if value and value != "-":
                                cleaned.append(value)
                        return cleaned
                return [raw]

            uploaded_qc_photo_paths = parse_qc_photo_paths(request.form.get("uploaded_qc_photo_path"))
            for entry in uploaded_qc_photo_paths:
                if not (decode_cloudinary_ref(entry) or _resolve_uploads_relative_path(entry)):
                    raise ValueError("La foto del QC no es válida.")

            qc_photo_files = [entry for entry in request.files.getlist("qc_photo") if has_uploaded_file(entry)]
            if not qc_photo_files:
                qc_photo_camera_file = request.files.get("qc_photo_camera")
                if has_uploaded_file(qc_photo_camera_file):
                    qc_photo_files = [qc_photo_camera_file]

            session_photo_paths = list(uploaded_qc_photo_paths)
            for entry in qc_photo_files:
                persisted = persist_qc_session_evidence(entry, qc_date)
                if persisted and persisted not in session_photo_paths:
                    session_photo_paths.append(persisted)

            qc_evidence_paths = set()
            for entry in session_photo_paths:
                qc_evidence_paths.add(entry)
            for item in items:
                for entry in parse_qc_photo_paths(item.get("photo_path")):
                    qc_evidence_paths.add(entry)

            if len(qc_evidence_paths) < 2:
                raise ValueError(
                    "Debes subir al menos 2 fotos de evidencia (en cualquier ítem del checklist y/o en la foto general del QC) para registrar el control."
                )

            if len(session_photo_paths) == 0:
                session_photo_path = None
            elif len(session_photo_paths) == 1:
                session_photo_path = session_photo_paths[0]
            else:
                session_photo_path = json.dumps(session_photo_paths, ensure_ascii=False)

            technician_row = next((t for t in technicians if t.get("id") == locked_technician_id), None)
            technician_name = (technician_row.get("name") if technician_row else "") or ""
            technician_employee_code = (technician_row.get("employee_code") if technician_row else "") or ""
            technician_company = (technician_row.get("company_name") if technician_row else "") or ""
            technician_supervisor = (technician_row.get("supervisor_name") if technician_row else "") or ""
            technician_center = (technician_row.get("center_name") if technician_row else "") or ""

            if locked_audit:
                technician_name = locked_audit.get("technician_name") or technician_name
                technician_employee_code = locked_audit.get("employee_code") or technician_employee_code
                technician_company = locked_audit.get("technician_company") or technician_company
                technician_supervisor = locked_audit.get("technician_supervisor") or technician_supervisor
                technician_center = locked_audit.get("technician_center") or technician_center
                if not address:
                    address = locked_audit.get("address") or ""
                if not sa_number:
                    sa_number = locked_audit.get("sa_number") or ""

            location = location.strip().upper()
            installation_type = installation_type.strip().upper()
            address = address.strip().upper()
            sa_number = sa_number.strip()
            if sa_number and not sa_number.isdigit():
                raise ValueError("El SA debe contener solo números.")
            technician_name = technician_name.strip().upper()
            technician_employee_code = technician_employee_code.strip().upper()
            technician_company = technician_company.strip().upper()
            technician_supervisor = technician_supervisor.strip().upper()
            technician_center = technician_center.strip().upper()
            general_notes = (request.form.get("general_notes") or "").strip().upper() or None

            qc_data = {
                "qc_date": qc_date,
                "auditor_name": current_user()["username"],
                "auditor_user_id": current_user().get("id"),
                "sa_number": sa_number or None,
                "technician_display_name": technician_name or None,
                "technician_employee_code": technician_employee_code or None,
                "technician_company_snapshot": technician_company or None,
                "technician_supervisor_snapshot": technician_supervisor or None,
                "technician_center_snapshot": technician_center or None,
                "technician_id": locked_technician_id,
                "audit_id": audit_id,
                "location": location,
                "address": address or None,
                "installation_type": installation_type,
                "total_score": qc_score,
                "result_status": result_status,
                "record_scope": record_scope,
                "general_notes": general_notes,
                "photo_path": session_photo_path,
                "qc_live_installation": qc_live_installation,
                "installation_duration_minutes": installation_duration_minutes,
                "cable_type": cable_type,
                "cable_meters": cable_meters,
            }

            qc_session_id = create_qc_session(qc_data, items)
            flash("QC de instalaciones registrado.", "success")
            return redirect(url_for("main.qc_detail", qc_session_id=qc_session_id))
        except (KeyError, ValueError) as exc:
            flash(str(exc), "error")

    return render_template(
        "qc_form.html",
        section=section,
        technicians=technicians,
        audit_context=audit_context,
        today=today,
        page_class="page-wide",
    )


@main.route("/qc/reports")
def qc_reports():
    if not can_view_reports():
        abort(403)

    user = current_user()
    auditor_user_id = user["id"] if user and user.get("role") == "auditor" else None
    filters = {
        "from_date": request.args.get("from_date", "").strip(),
        "to_date": request.args.get("to_date", "").strip(),
        "status": request.args.get("status", "").strip(),
        "technician_id": request.args.get("technician_id", "").strip(),
        "min_n": request.args.get("min_n", "").strip(),
        "include_pruebas": "1" if request.args.get("include_pruebas") else "",
    }

    technician_id = None
    if filters["technician_id"]:
        try:
            technician_id = int(filters["technician_id"])
        except ValueError:
            flash("El técnico seleccionado no es válido.", "error")
            filters["technician_id"] = ""

    min_n = 3
    if filters["min_n"]:
        try:
            min_n = max(1, int(filters["min_n"]))
        except ValueError:
            flash("El mínimo de controles no es válido.", "error")
            filters["min_n"] = ""

    query_filters = {
        "from_date": filters["from_date"],
        "to_date": filters["to_date"],
        "status": filters["status"],
        "technician_id": technician_id,
        "include_pruebas": filters["include_pruebas"],
    }

    summary = fetch_qc_reports_management_summary(
        query_filters,
        auditor_user_id=auditor_user_id,
        supervisor_scope_names=current_supervisor_scope_names(),
    )
    status_breakdown = fetch_qc_reports_status_breakdown(
        query_filters,
        auditor_user_id=auditor_user_id,
        supervisor_scope_names=current_supervisor_scope_names(),
    )
    time_series = fetch_qc_reports_time_series(
        query_filters,
        auditor_user_id=auditor_user_id,
        supervisor_scope_names=current_supervisor_scope_names(),
    )
    technician_ranking = fetch_qc_reports_technician_ranking(
        query_filters,
        auditor_user_id=auditor_user_id,
        supervisor_scope_names=current_supervisor_scope_names(),
        min_qc=min_n,
    )

    technicians = fetch_technicians()
    filter_active = any([filters["from_date"], filters["to_date"], filters["status"], filters["technician_id"], filters["include_pruebas"]])

    return render_template(
        "qc_reports.html",
        filters=filters,
        technicians=technicians,
        min_n=min_n,
        summary=summary,
        status_breakdown=status_breakdown,
        time_series=time_series,
        technician_ranking=technician_ranking,
        filter_active=filter_active,
        audit_official_from_date=get_audit_official_from_date(),
        page_class="page-wide",
    )


def _default_technician_profile_range():
    today = datetime.now()
    try:
        app_tz = _app_timezone()
        today = datetime.now(app_tz).replace(tzinfo=None)
    except Exception:
        pass
    to_date = today.strftime("%Y-%m-%d")
    from_date = (today - timedelta(days=90)).strftime("%Y-%m-%d")
    return from_date, to_date


@main.route("/technicians")
def technician_list():
    if not can_view_reports():
        abort(403)

    user = current_user()
    auditor_user_id = user["id"] if user and user.get("role") == "auditor" else None
    supervisor_scope_names = current_supervisor_scope_names()

    has_any_filter_arg = any(k in request.args for k in (
        "from_date", "to_date", "q", "region", "supervisor", "center", "company", "is_active", "all_time", "sort_by", "sort_dir"
    ))
    all_time_flag = request.args.get("all_time", "").strip() == "1"

    default_from, default_to = _default_technician_profile_range()
    if all_time_flag:
        from_date = ""
        to_date = ""
    else:
        from_date_raw = request.args.get("from_date", "").strip()
        to_date_raw = request.args.get("to_date", "").strip()
        if not has_any_filter_arg:
            from_date = default_from
            to_date = default_to
        else:
            from_date = from_date_raw
            to_date = to_date_raw

    q = request.args.get("q", "").strip()
    region = request.args.get("region", "").strip()
    supervisor = request.args.get("supervisor", "").strip()
    center = request.args.get("center", "").strip()
    company = request.args.get("company", "").strip()
    is_active = request.args.get("is_active", "").strip()
    page_raw = request.args.get("page", "").strip()
    page_size_raw = request.args.get("page_size", "").strip()
    sort_by = request.args.get("sort_by", "").strip()
    sort_dir = request.args.get("sort_dir", "").strip()

    try:
        page = max(1, int(page_raw)) if page_raw else 1
    except (TypeError, ValueError):
        page = 1

    try:
        page_size = max(1, min(200, int(page_size_raw))) if page_size_raw else 20
    except (TypeError, ValueError):
        page_size = 20

    filters = {
        "from_date": from_date,
        "to_date": to_date,
        "q": q,
        "region": region,
        "supervisor": supervisor,
        "center": center,
        "company": company,
        "is_active": is_active if is_active != "" else None,
        "all_time": all_time_flag,
        "page": page,
        "page_size": page_size,
    }

    technicians_total = count_technicians_list(
        filters,
        auditor_user_id=auditor_user_id,
        supervisor_scope_names=supervisor_scope_names,
    )
    page_count = max(1, (technicians_total + page_size - 1) // page_size) if technicians_total else 1
    if page > page_count:
        page = page_count
    offset = (page - 1) * page_size

    rows = fetch_technician_list_summary(
        filters,
        auditor_user_id=auditor_user_id,
        supervisor_scope_names=supervisor_scope_names,
        sort_by=sort_by,
        sort_dir=sort_dir,
        limit=page_size,
        offset=offset,
    )

    active_count = sum(1 for r in rows if r.get("is_active"))
    inactive_count = sum(1 for r in rows if not r.get("is_active"))
    total_audits = sum(r["audits_count"] for r in rows)
    total_qc = sum(r["qc_count"] for r in rows)
    total_service = sum(r["service_count"] for r in rows)
    nps_total_weight = sum(r["nps_count"] for r in rows)

    def _clean_num(v):
        try:
            f = float(v or 0)
        except (TypeError, ValueError):
            f = 0.0
        if f == 0:
            return 0
        r_rounded = round(f, 1)
        if r_rounded == int(r_rounded):
            return int(r_rounded)
        return r_rounded

    avg_audit_score_global = 0
    if rows and total_audits > 0:
        weighted = sum(r["audit_avg_score"] * r["audits_count"] for r in rows)
        avg_audit_score_global = _clean_num(weighted / total_audits if total_audits else 0)

    avg_qc_score_global = 0
    if rows and total_qc > 0:
        weighted = sum(r["qc_avg_score"] * r["qc_count"] for r in rows)
        avg_qc_score_global = _clean_num(weighted / total_qc if total_qc else 0)

    avg_nps_global = 0
    if rows and nps_total_weight > 0:
        weighted = sum(r["avg_nps"] * r["nps_count"] for r in rows)
        avg_nps_global = _clean_num(weighted / nps_total_weight if nps_total_weight else 0)

    show_date_filter_values_from = from_date if from_date else default_from
    show_date_filter_values_to = to_date if to_date else default_to

    has_prev_page = page > 1
    has_next_page = (offset + page_size) < technicians_total

    pages_window = []
    if page_count <= 9:
        pages_window = list(range(1, page_count + 1))
    else:
        pages_window.append(1)
        if page - 2 > 2:
            pages_window.append(None)
        start = max(2, page - 2)
        end = min(page_count - 1, page + 2)
        for p in range(start, end + 1):
            pages_window.append(p)
        if page + 2 < page_count - 1:
            pages_window.append(None)
        pages_window.append(page_count)

    return render_template(
        "technician_list.html",
        technicians=rows,
        technicians_total=technicians_total,
        filters=filters,
        show_from=show_date_filter_values_from,
        show_to=show_date_filter_values_to,
        sort_by=sort_by,
        sort_dir=sort_dir,
        page=page,
        page_count=page_count,
        page_size=page_size,
        has_prev_page=has_prev_page,
        has_next_page=has_next_page,
        pages_window=pages_window,
        filter_options={
            "regions": fetch_distinct_regions(),
            "supervisors": fetch_distinct_supervisors(),
            "centers": fetch_distinct_centers(),
            "companies": fetch_distinct_companies(),
        },
        summary={
            "total_technicians": technicians_total,
            "active_count": active_count,
            "inactive_count": inactive_count,
            "total_audits": total_audits,
            "total_qc": total_qc,
            "total_service": total_service,
            "avg_audit_score_global": avg_audit_score_global,
            "avg_qc_score_global": avg_qc_score_global,
            "avg_nps_global": avg_nps_global,
            "nps_total_weight": nps_total_weight,
        },
        page_class="page-wide",
    )


def _build_technician_csv_rows(rows):
    csv_rows = []
    for t in rows or []:
        last_any = t.get("last_activity_expr") or (t.get("last_audit_date") or t.get("last_qc_date") or t.get("last_service_date"))
        csv_rows.append({
            "Tecnico": t.get("name") or "",
            "Legajo": t.get("employee_code") or "",
            "Region": t.get("region") or "",
            "Equipo": t.get("team") or "",
            "Supervisor": t.get("supervisor_name") or "",
            "Centro": t.get("center_name") or "",
            "Empresa": t.get("company_name") or "",
            "Sindicato": t.get("union_name") or "",
            "Estado": "Activo" if t.get("is_active") else "Inactivo",
            "Auditorias": int(t.get("audits_count") or 0),
            "Audit_Aprob_Pct": t.get("audit_approval_rate") or "",
            "Audit_Score_Prom": t.get("audit_avg_score") or "",
            "Audit_Criticas": int(t.get("audit_critical_count") or 0),
            "QC_Sesiones": int(t.get("qc_count") or 0),
            "QC_Aprob_Pct": t.get("qc_approval_rate") or "",
            "QC_Score_Prom": t.get("qc_avg_score") or "",
            "Service": int(t.get("service_count") or 0),
            "Service_Score_Prom": t.get("service_avg_score") or "",
            "NPS_Prom": t.get("avg_nps") or "",
            "NPS_Respuestas": int(t.get("nps_count") or 0),
            "Ultima_Actividad": last_any or "",
            "Ultima_Auditoria": t.get("last_audit_date") or "",
            "Ultimo_QC": t.get("last_qc_date") or "",
            "Ultimo_Service": t.get("last_service_date") or "",
        })
    return csv_rows


@main.route("/technicians/export_csv")
def technician_list_export_csv():
    if not can_view_reports():
        abort(403)

    user = current_user()
    auditor_user_id = user["id"] if user and user.get("role") == "auditor" else None
    supervisor_scope_names = current_supervisor_scope_names()

    all_time_flag = request.args.get("all_time", "").strip() == "1"
    if all_time_flag:
        from_date = ""
        to_date = ""
    else:
        from_date = request.args.get("from_date", "").strip()
        to_date = request.args.get("to_date", "").strip()

    q = request.args.get("q", "").strip()
    region = request.args.get("region", "").strip()
    supervisor = request.args.get("supervisor", "").strip()
    center = request.args.get("center", "").strip()
    company = request.args.get("company", "").strip()
    is_active = request.args.get("is_active", "").strip()
    sort_by = request.args.get("sort_by", "").strip()
    sort_dir = request.args.get("sort_dir", "").strip()

    filters = {
        "from_date": from_date,
        "to_date": to_date,
        "q": q,
        "region": region,
        "supervisor": supervisor,
        "center": center,
        "company": company,
        "is_active": is_active if is_active != "" else None,
        "all_time": all_time_flag,
    }

    rows = fetch_technician_list_summary(
        filters,
        auditor_user_id=auditor_user_id,
        supervisor_scope_names=supervisor_scope_names,
        sort_by=sort_by,
        sort_dir=sort_dir,
        limit=20000,
        offset=0,
    )

    csv_rows = _build_technician_csv_rows(rows)
    range_label_from = from_date or "inicio"
    range_label_to = to_date or "hoy"
    safe_from = "".join(c if c.isalnum() else "_" for c in range_label_from)
    safe_to = "".join(c if c.isalnum() else "_" for c in range_label_to)
    filename = f"perfiles_tecnicos_{safe_from}_a_{safe_to}.csv"

    fieldnames = [
        "Tecnico", "Legajo", "Region", "Equipo", "Supervisor", "Centro", "Empresa", "Sindicato", "Estado",
        "Auditorias", "Audit_Aprob_Pct", "Audit_Score_Prom", "Audit_Criticas",
        "QC_Sesiones", "QC_Aprob_Pct", "QC_Score_Prom",
        "Service", "Service_Score_Prom",
        "NPS_Prom", "NPS_Respuestas",
        "Ultima_Actividad", "Ultima_Auditoria", "Ultimo_QC", "Ultimo_Service",
    ]
    return build_csv_response(csv_rows, filename, fieldnames=fieldnames)


@main.route("/technicians/<int:technician_id>")
def technician_profile(technician_id):
    if not can_view_reports():
        abort(403)

    user = current_user()
    auditor_user_id = user["id"] if user and user.get("role") == "auditor" else None
    supervisor_scope_names = current_supervisor_scope_names()

    technician = fetch_technician_by_id(technician_id)
    if not technician:
        abort(404)

    if supervisor_scope_names:
        allowed_names = {s.upper().strip() for s in supervisor_scope_names if s}
        tech_supervisor = (technician.get("supervisor_name") or "").upper().strip()
        if allowed_names and tech_supervisor not in allowed_names:
            abort(403)

    has_any_filter_arg = any(k in request.args for k in ("from_date", "to_date", "all_time"))
    all_time_flag = request.args.get("all_time", "").strip() == "1"
    default_from, default_to = _default_technician_profile_range()
    if all_time_flag:
        from_date = ""
        to_date = ""
    else:
        from_date_raw = request.args.get("from_date", "").strip()
        to_date_raw = request.args.get("to_date", "").strip()
        if not has_any_filter_arg:
            from_date = default_from
            to_date = default_to
        else:
            from_date = from_date_raw
            to_date = to_date_raw

    filters = {
        "from_date": from_date,
        "to_date": to_date,
        "all_time": all_time_flag,
    }

    summary = fetch_technician_profile_summary(
        technician_id, filters=filters, auditor_user_id=auditor_user_id
    ) or {}
    benchmarks = fetch_technician_profile_benchmarks(
        technician_id, filters=filters, auditor_user_id=auditor_user_id
    ) or {}
    try:
        recent_audits = fetch_technician_recent_audits(technician_id, filters=filters, limit=8) or []
    except Exception:
        recent_audits = []
    try:
        recent_qc = fetch_technician_recent_qc(technician_id, filters=filters, limit=8) or []
    except Exception:
        recent_qc = []
    try:
        recent_service = fetch_technician_recent_service(technician_id, filters=filters, limit=8) or []
    except Exception:
        recent_service = []
    try:
        monthly_series = fetch_technician_monthly_series(technician_id, filters=filters, granularity="month", limit=18) or []
    except Exception:
        monthly_series = []
    try:
        pvp = fetch_technician_period_over_period(technician_id, filters=filters) or {}
    except Exception:
        pvp = {}
    try:
        historic = fetch_technician_historical_profile(technician_id, filters=filters) or {}
    except Exception:
        historic = {}
    try:
        vehicle = lookup_vehicle_for_technician(technician) or {}
    except Exception:
        vehicle = {}
    try:
        distribution = fetch_technician_distribution_ranking(technician_id, filters=filters, auditor_user_id=auditor_user_id) or {}
    except Exception:
        distribution = {}
    try:
        findings_trend = fetch_technician_findings_trend(technician_id, filters=filters, limit_months=6) or {}
    except Exception:
        findings_trend = {}

    if not isinstance(summary, dict):
        summary = {}
    if not isinstance(benchmarks, dict):
        benchmarks = {}
    if not isinstance(pvp, dict):
        pvp = {}
    if not isinstance(historic, dict):
        historic = {}
    historic.setdefault("today", "")
    historic.setdefault("age", {})
    historic["age"].setdefault("first", "")
    historic["age"].setdefault("last", "")
    historic["age"].setdefault("label", "")
    historic["age"].setdefault("total_days", None)
    historic["age"].setdefault("total_months", None)
    historic["age"].setdefault("years", None)
    historic["age"].setdefault("months", None)
    historic.setdefault("volumes", {})
    historic["volumes"].setdefault("audits_total", 0)
    historic["volumes"].setdefault("qc_total", 0)
    historic["volumes"].setdefault("service_total", 0)
    historic["volumes"].setdefault("nps_total", 0)
    historic["volumes"].setdefault("avg_per_month", {})
    historic["volumes"]["avg_per_month"].setdefault("audits", 0)
    historic["volumes"]["avg_per_month"].setdefault("qc", 0)
    historic["volumes"]["avg_per_month"].setdefault("service", 0)
    historic["volumes"]["avg_per_month"].setdefault("nps", 0)
    historic.setdefault("quality", {})
    historic["quality"].setdefault("audit_avg_score", None)
    historic["quality"].setdefault("qc_avg_score", None)
    historic["quality"].setdefault("service_avg_score", None)
    historic["quality"].setdefault("avg_nps", None)
    historic["quality"].setdefault("audit_approval_rate", 0)
    historic["quality"].setdefault("qc_approval_rate", 0)
    historic["quality"].setdefault("audit_critical_count", 0)
    historic["quality"].setdefault("audit_critical_rate", 0)
    historic["quality"].setdefault("audit_rejected_count", 0)
    historic.setdefault("peaks", {})
    historic["peaks"].setdefault("audit", None)
    historic["peaks"].setdefault("qc", None)
    historic["peaks"].setdefault("service", None)
    historic["peaks"].setdefault("worst_audit_approval", None)
    historic["peaks"].setdefault("worst_qc_approval", None)
    historic.setdefault("streaks", {})
    historic["streaks"].setdefault("days_since_last_activity", None)
    historic["streaks"].setdefault("days_since_last_audit", None)
    historic["streaks"].setdefault("days_since_last_qc", None)
    historic["streaks"].setdefault("days_since_last_service", None)
    historic["streaks"].setdefault("last_audit_date", "")
    historic["streaks"].setdefault("last_qc_date", "")
    historic["streaks"].setdefault("last_service_date", "")
    historic.setdefault("monthly_series", [])
    historic.setdefault("lifetime_summary", {})

    if not isinstance(pvp, dict):
        pvp = {}
    pvp.setdefault("rows", [])
    pvp.setdefault("previous_range_label", "")
    pvp.setdefault("current_range_label", "")

    if not isinstance(summary, dict):
        summary = {}
    summary.setdefault("top_audit_no_cumple_items", [])
    summary.setdefault("top_qc_nc_mayor_items", [])

    if not isinstance(vehicle, dict):
        vehicle = {}
    vehicle.setdefault("truck_number", None)
    vehicle.setdefault("plate", None)
    vehicle.setdefault("source", None)
    if not isinstance(distribution, dict):
        distribution = {}
    distribution.setdefault("scope_rows", [])
    distribution.setdefault("peer_count", 0)
    distribution.setdefault("scope_label", "")
    if not isinstance(findings_trend, dict):
        findings_trend = {}
    findings_trend.setdefault("audit_findings", [])
    findings_trend.setdefault("qc_findings", [])
    findings_trend.setdefault("months", [])
    findings_trend.setdefault("today", "")

    show_from = from_date if from_date else default_from
    show_to = to_date if to_date else default_to

    last_any = (
        summary.get("last_audit_date")
        or summary.get("last_qc_date")
        or summary.get("last_service_date")
    )

    return render_template(
        "technician_profile.html",
        technician=technician,
        filters=filters,
        show_from=show_from,
        show_to=show_to,
        summary=summary or {},
        benchmarks=benchmarks or {},
        recent_audits=recent_audits,
        recent_qc=recent_qc,
        recent_service=recent_service,
        monthly_series=monthly_series,
        pvp=pvp or {},
        historic=historic or {},
        vehicle=vehicle or {},
        distribution=distribution or {},
        findings_trend=findings_trend or {},
        last_activity=last_any or "",
        page_class="page-wide",
    )


@main.route("/reports/technicians")
def technician_reports():
    if not can_view_reports():
        abort(403)

    user = current_user()
    auditor_user_id = user["id"] if user and user.get("role") == "auditor" else None
    filters = {
        "from_date": request.args.get("from_date", "").strip(),
        "to_date": request.args.get("to_date", "").strip(),
        "technician_id": request.args.get("technician_id", "").strip(),
        "min_n": request.args.get("min_n", "").strip(),
        "include_pruebas": "1" if request.args.get("include_pruebas") else "",
    }

    technician_id = None
    if filters["technician_id"]:
        try:
            technician_id = int(filters["technician_id"])
        except ValueError:
            flash("El técnico seleccionado no es válido.", "error")
            filters["technician_id"] = ""

    min_n = 3
    if filters["min_n"]:
        try:
            min_n = max(1, int(filters["min_n"]))
        except ValueError:
            flash("El mínimo de controles no es válido.", "error")
            filters["min_n"] = ""

    query_filters = {
        "from_date": filters["from_date"],
        "to_date": filters["to_date"],
        "technician_id": technician_id,
        "include_pruebas": filters["include_pruebas"],
    }

    technicians = fetch_technicians()
    technician_ranking = fetch_qc_reports_technician_ranking(
        query_filters,
        auditor_user_id=auditor_user_id,
        supervisor_scope_names=current_supervisor_scope_names(),
        min_qc=min_n,
    )
    technician_ranking_nc_major = fetch_qc_reports_technician_ranking_by_nc_major(
        query_filters,
        auditor_user_id=auditor_user_id,
        supervisor_scope_names=current_supervisor_scope_names(),
        min_qc=min_n,
    )

    technician_selected = None
    if technician_id is not None:
        technician_selected = next((t for t in technicians if t.get("id") == technician_id), None)
        if not technician_selected:
            flash("El técnico seleccionado no existe.", "error")
            filters["technician_id"] = ""
            technician_id = None
            query_filters["technician_id"] = None

    summary = None
    extra_summary = None
    nc_summary = None
    nc_breakdown_major = []
    nc_breakdown_minor = []
    if technician_id is not None:
        summary = fetch_qc_reports_management_summary(
            query_filters,
            auditor_user_id=auditor_user_id,
            supervisor_scope_names=current_supervisor_scope_names(),
        )
        extra_summary = fetch_qc_technician_extra_summary(
            query_filters,
            auditor_user_id=auditor_user_id,
            supervisor_scope_names=current_supervisor_scope_names(),
        )
        nc_summary = fetch_qc_technician_nc_summary(
            query_filters,
            auditor_user_id=auditor_user_id,
            supervisor_scope_names=current_supervisor_scope_names(),
        )
        breakdown = fetch_qc_technician_nc_breakdown(
            query_filters,
            auditor_user_id=auditor_user_id,
            supervisor_scope_names=current_supervisor_scope_names(),
            limit=80,
        )
        nc_breakdown_major = sorted(breakdown, key=lambda r: (r["nc_mayor_count"], r["nc_total_count"], r["evaluated_count"]), reverse=True)[:20]
        nc_breakdown_minor = sorted(breakdown, key=lambda r: (r["nc_menor_count"], r["nc_total_count"], r["evaluated_count"]), reverse=True)[:20]

    return render_template(
        "technician_reports.html",
        technicians=technicians,
        technician_selected=technician_selected,
        technician_ranking=technician_ranking,
        technician_ranking_nc_major=technician_ranking_nc_major,
        summary=summary,
        extra_summary=extra_summary,
        nc_summary=nc_summary,
        nc_breakdown_major=nc_breakdown_major,
        nc_breakdown_minor=nc_breakdown_minor,
        filters=filters,
        min_n=min_n,
        audit_official_from_date=get_audit_official_from_date(),
        page_class="page-wide",
    )


@main.route("/qc/<int:qc_session_id>")
def qc_detail(qc_session_id):
    session_row = fetch_qc_session_detail(qc_session_id, supervisor_scope_names=current_supervisor_scope_names())
    if not session_row:
        abort(404)
    if is_auditor():
        user = current_user()
        if session_row.get("auditor_user_id") != user["id"] and (session_row.get("auditor_name") or "") != user["username"]:
            abort(404)

    items = fetch_qc_items(qc_session_id)
    grouped_items = build_grouped_audit_items(items)
    tnps_response = fetch_tnps_response_for_qc(qc_session_id)
    tnps_source = "qc"
    if not tnps_response and session_row.get("audit_id"):
        tnps_response = fetch_tnps_response_for_audit(session_row["audit_id"])
        tnps_source = "audit"

    response = make_response(
        render_template(
            "qc_detail.html",
            qc=session_row,
            grouped_items=grouped_items,
            tnps_response=tnps_response,
            tnps_source=tnps_source,
        )
    )
    response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "0"
    return response


@main.route("/supply-requests", methods=["GET", "POST"])
def supply_requests():
    if not can_view_supply_requests():
        abort(403)

    user = current_user()
    auditor_user_id = user["id"] if user and user.get("role") == "auditor" else None
    supervisor_scope_names = current_supervisor_scope_names()
    filters = {
        "from_date": request.args.get("from_date", "").strip(),
        "to_date": request.args.get("to_date", "").strip(),
        "q": request.args.get("q", "").strip(),
    }
    page_raw = (request.args.get("page") or "").strip()
    page = 1
    if page_raw:
        try:
            page = max(1, int(page_raw))
        except ValueError:
            page = 1
    page_size = 25
    offset = (page - 1) * page_size
    audits_total = count_audit_picker_audits(
        filters,
        auditor_user_id=auditor_user_id,
        supervisor_scope_names=supervisor_scope_names,
    )
    audits = fetch_audit_picker_audits(
        filters,
        auditor_user_id=auditor_user_id,
        supervisor_scope_names=supervisor_scope_names,
        limit=page_size,
        offset=offset,
    )
    has_prev_page = page > 1
    has_next_page = (offset + page_size) < audits_total

    material_catalog = fetch_material_catalog()
    material_index = {row["material_code"]: row["material_name"] for row in material_catalog}

    audit_context = None
    audit_id = None
    audit_id_raw = (request.args.get("audit_id") or request.form.get("audit_id") or "").strip()
    if audit_id_raw:
        try:
            audit_id = int(audit_id_raw)
        except ValueError:
            flash("El ID de auditoría no es válido.", "error")
            audit_id = None

    supply_requests_feed = []
    if not can_create_supply_requests() and audit_id is None:
        supply_requests_feed = fetch_supply_requests_feed(
            filters,
            auditor_user_id=auditor_user_id,
            supervisor_scope_names=supervisor_scope_names,
            limit=200,
        )

    if audit_id is not None:
        audit_context = fetch_audit_detail(audit_id, supervisor_scope_names=supervisor_scope_names)
        if audit_context and is_auditor():
            current = current_user()
            if audit_context.get("auditor_user_id") != current["id"] and (audit_context.get("auditor_name") or "") != current["username"]:
                audit_context = None
        if not audit_context:
            flash("No se encontró la auditoría seleccionada.", "error")

    items = fetch_audit_items(audit_id) if audit_context else []
    grouped_items = build_grouped_audit_items(items) if items else {}
    supply_requests_rows = fetch_audit_supply_requests(audit_id) if audit_context else []

    if request.method == "POST":
        if not can_create_supply_requests():
            abort(403)
        try:
            if not audit_context or audit_id is None:
                raise ValueError("Debes seleccionar una auditoría para registrar la solicitud.")

            request_type = (request.form.get("request_type") or "").strip()
            if request_type not in {"reponer", "cambiar"}:
                raise ValueError("Solicitud inválida. Usa reponer o cambiar.")

            material_code_raw = (request.form.get("material_code") or "").strip()
            if not material_code_raw:
                raise ValueError("Debes indicar el código del material en la solicitud.")

            material_code = material_code_raw.split(" - ", 1)[0].strip()
            normalized_material_code = material_code.upper()
            if normalized_material_code != "SIN CODIGO":
                if not material_index:
                    raise ValueError(
                        "No hay materiales importados para validar códigos. Importa Stock de materiales primero."
                    )
                material = fetch_material_by_code(material_code)
                if not material:
                    raise ValueError(f"El código {material_code} no existe en materiales importados.")
            else:
                material = None

            quantity_raw = (request.form.get("quantity") or "").strip()
            quantity = None
            if quantity_raw:
                try:
                    quantity = int(quantity_raw)
                except ValueError as exc:
                    raise ValueError("La cantidad solicitada no es válida.") from exc

            notes = (request.form.get("notes") or "").strip().upper() or None
            if normalized_material_code == "SIN CODIGO" and not notes:
                raise ValueError("Si seleccionas SIN CODIGO, debes completar la nota.")

            audit_item_id_raw = (request.form.get("audit_item_id") or "").strip()
            selected_item = None
            if audit_item_id_raw:
                try:
                    audit_item_id = int(audit_item_id_raw)
                except ValueError as exc:
                    raise ValueError("El ítem seleccionado no es válido.") from exc
                selected_item = next((it for it in items if it.get("id") == audit_item_id), None)
                if not selected_item:
                    raise ValueError("El ítem seleccionado no pertenece a la auditoría.")

            if selected_item:
                section_key = selected_item.get("section_key") or "accion"
                section_title = selected_item.get("section_title") or "Acción"
                item_key = selected_item.get("item_key") or f"material_{material_code}"
                item_label = selected_item.get("item_label") or (material["material_name"] if material else "SIN CODIGO")
            else:
                section_key = "accion"
                section_title = "Acción"
                item_key = f"material_{material_code}" if normalized_material_code != "SIN CODIGO" else "sin_codigo"
                item_label = material["material_name"] if material else "SIN CODIGO"

            create_audit_supply_requests(
                audit_id,
                [
                    {
                        "section_key": section_key,
                        "section_title": section_title,
                        "item_key": item_key,
                        "item_label": item_label,
                        "request_type": request_type,
                        "material_code": normalized_material_code
                        if normalized_material_code == "SIN CODIGO"
                        else material_code,
                        "quantity": quantity,
                        "notes": notes,
                    }
                ],
            )
            flash("Solicitud registrada.", "success")
            return redirect(url_for("main.supply_requests", audit_id=audit_id))
        except ValueError as exc:
            flash(str(exc), "error")

    return render_template(
        "supply_requests.html",
        audits=audits,
        audits_total=audits_total,
        audit=audit_context,
        audit_id=audit_id,
        filters=filters,
        page=page,
        page_size=page_size,
        has_prev_page=has_prev_page,
        has_next_page=has_next_page,
        grouped_items=grouped_items,
        supply_requests=supply_requests_rows,
        supply_requests_feed=supply_requests_feed,
        material_index=material_index,
        page_class="page-wide",
    )


@main.route("/audits")
def audit_list():
    user = current_user()
    auditor_user_id = user["id"] if user and user.get("role") == "auditor" else None
    supervisor_scope_names = current_supervisor_scope_names()
    filters = {
        "from_date": request.args.get("from_date", "").strip(),
        "to_date": request.args.get("to_date", "").strip(),
        "status": request.args.get("status", "").strip(),
        "auditor": request.args.get("auditor", "").strip(),
        "include_pruebas": request.args.get("include_pruebas", "").strip(),
        "sort": request.args.get("sort", "").strip(),
        "dir": request.args.get("dir", "").strip(),
    }

    if auditor_user_id is not None:
        filters["auditor"] = ""

    audits = fetch_all_audits(
        filters,
        auditor_user_id=auditor_user_id,
        supervisor_scope_names=supervisor_scope_names,
    )
    filter_active = any(
        [
            filters["from_date"],
            filters["to_date"],
            filters["status"],
            filters["auditor"],
            filters["include_pruebas"],
        ]
    )
    return render_template(
        "audits.html",
        audits=audits,
        filters=filters,
        filter_active=filter_active,
        audit_official_from_date=get_audit_official_from_date(),
    )


@main.route("/reports")
def reports():
    if not can_view_reports():
        abort(403)

    user = current_user()
    auditor_user_id = user["id"] if user and user.get("role") == "auditor" else None

    filters = {
        "from_date": request.args.get("from_date", "").strip(),
        "to_date": request.args.get("to_date", "").strip(),
        "status": request.args.get("status", "").strip(),
        "auditor": request.args.get("auditor", "").strip(),
        "include_pruebas": request.args.get("include_pruebas", "").strip(),
    }
    if auditor_user_id is not None:
        filters["auditor"] = ""

    summary = fetch_audit_reports_management_summary(filters, auditor_user_id=auditor_user_id)
    status_breakdown = fetch_audit_reports_status_breakdown(filters, auditor_user_id=auditor_user_id)
    section_breakdown = fetch_audit_reports_section_breakdown(filters, auditor_user_id=auditor_user_id)[:8]
    trend_monthly = fetch_audit_reports_time_series(filters, auditor_user_id=auditor_user_id, granularity="month", limit=12)
    trend_weekly = fetch_audit_reports_time_series(filters, auditor_user_id=auditor_user_id, granularity="week", limit=12)
    auditors = fetch_distinct_auditors() if can_view_all_audits() else []

    return render_template(
        "reports.html",
        filters=filters,
        summary=summary,
        status_breakdown=status_breakdown,
        section_breakdown=section_breakdown,
        trend_monthly=trend_monthly,
        trend_weekly=trend_weekly,
        auditors=auditors,
        audit_official_from_date=get_audit_official_from_date(),
    )


@main.route("/reports/export/<report_key>.csv")
def export_report(report_key):
    if not can_view_reports():
        abort(403)

    user = current_user()
    auditor_user_id = user["id"] if user and user.get("role") == "auditor" else None

    filters = {
        "from_date": request.args.get("from_date", "").strip(),
        "to_date": request.args.get("to_date", "").strip(),
        "status": request.args.get("status", "").strip(),
        "auditor": request.args.get("auditor", "").strip(),
        "include_pruebas": request.args.get("include_pruebas", "").strip(),
        "supervisor": request.args.get("supervisor", "").strip(),
    }
    if auditor_user_id is not None:
        filters["auditor"] = ""

    date_from = filters["from_date"] or "inicio"
    date_to = filters["to_date"] or "hoy"
    status_suffix = (filters.get("status") or "").strip().replace(" ", "_") or "todos"
    auditor_suffix = (filters.get("auditor") or "").strip().replace(" ", "_") or "todos"
    filename = f"reporte_{report_key}_{date_from}_a_{date_to}_{status_suffix}_{auditor_suffix}.csv"

    filter_context = {
        "from_date": filters["from_date"],
        "to_date": filters["to_date"],
        "status_filter": filters["status"],
        "auditor_filter": filters["auditor"],
    }

    if report_key == "resumen":
        summary = fetch_audit_reports_management_summary(filters, auditor_user_id=auditor_user_id)
        row = {**filter_context, **summary}
        return build_csv_response(
            [row],
            filename,
            fieldnames=list(filter_context.keys()) + list(summary.keys()),
        )

    if report_key == "estados":
        rows = fetch_audit_reports_status_breakdown(filters, auditor_user_id=auditor_user_id)
        rows = [{**filter_context, **row} for row in rows]
        return build_csv_response(
            rows,
            filename,
            fieldnames=list(filter_context.keys()) + ["result_status", "audits_count", "average_score"],
        )

    if report_key == "secciones":
        rows = fetch_audit_reports_section_breakdown(filters, auditor_user_id=auditor_user_id)
        rows = [{**filter_context, **row} for row in rows]
        return build_csv_response(
            rows,
            filename,
            fieldnames=list(filter_context.keys())
            + [
                "section_title",
                "compliant_count",
                "non_compliant_count",
                "critical_non_compliant_count",
                "not_applicable_count",
            ],
        )

    if report_key == "supervisores":
        rows = fetch_audit_reports_supervisor_breakdown(filters, auditor_user_id=auditor_user_id)
        rows = [{**filter_context, **row} for row in rows]
        return build_csv_response(
            rows,
            filename,
            fieldnames=list(filter_context.keys())
            + [
                "supervisor_name",
                "audits_count",
                "approved_count",
                "critical_count",
                "rejected_count",
                "approval_rate",
                "critical_rate",
                "rejected_rate",
                "no_asignado_audits",
                "no_asignado_rate",
                "no_asignado_items_count",
                "vencido_audits",
                "vencido_rate",
                "vencido_items_count",
                "no_apta_audits",
                "no_apta_rate",
                "no_apta_items_count",
                "risk_index",
                "average_score",
                "last_audit_date",
            ],
        )

    if report_key == "centros":
        rows = fetch_audit_reports_center_breakdown(filters, auditor_user_id=auditor_user_id)
        rows = [{**filter_context, **row} for row in rows]
        return build_csv_response(
            rows,
            filename,
            fieldnames=list(filter_context.keys())
            + [
                "center_name",
                "audits_count",
                "approved_count",
                "critical_count",
                "rejected_count",
                "approval_rate",
                "average_score",
                "last_audit_date",
            ],
        )

    if report_key == "empresas":
        rows = fetch_audit_reports_company_breakdown(filters, auditor_user_id=auditor_user_id)
        rows = [{**filter_context, **row} for row in rows]
        return build_csv_response(
            rows,
            filename,
            fieldnames=list(filter_context.keys())
            + [
                "company_name",
                "audits_count",
                "approved_count",
                "critical_count",
                "rejected_count",
                "approval_rate",
                "average_score",
                "last_audit_date",
            ],
        )

    if report_key == "ranking_tecnicos":
        rows = fetch_audit_reports_technician_ranking(filters, auditor_user_id=auditor_user_id)
        rows = [{**filter_context, **row} for row in rows]
        return build_csv_response(
            rows,
            filename,
            fieldnames=list(filter_context.keys())
            + [
                "technician_name",
                "technician_employee_code",
                "supervisor_name",
                "center_name",
                "company_name",
                "audits_count",
                "approved_count",
                "critical_count",
                "rejected_count",
                "approval_rate",
                "average_score",
                "last_audit_date",
            ],
        )

    if report_key == "ranking_moviles":
        rows = fetch_audit_reports_mobile_ranking(filters, auditor_user_id=auditor_user_id)
        rows = [{**filter_context, **row} for row in rows]
        return build_csv_response(
            rows,
            filename,
            fieldnames=list(filter_context.keys())
            + [
                "mobile_code",
                "audits_count",
                "approved_count",
                "critical_count",
                "rejected_count",
                "approval_rate",
                "average_score",
                "last_audit_date",
            ],
        )

    if report_key == "tendencia_mensual":
        rows = fetch_audit_reports_time_series(filters, auditor_user_id=auditor_user_id, granularity="month", limit=120)
        rows = [{**filter_context, **row} for row in rows]
        return build_csv_response(
            rows,
            filename,
            fieldnames=list(filter_context.keys())
            + [
                "period_key",
                "period_start",
                "audits_count",
                "approved_count",
                "critical_count",
                "rejected_count",
                "approval_rate",
                "average_score",
            ],
        )

    if report_key == "tendencia_semanal":
        rows = fetch_audit_reports_time_series(filters, auditor_user_id=auditor_user_id, granularity="week", limit=200)
        rows = [{**filter_context, **row} for row in rows]
        return build_csv_response(
            rows,
            filename,
            fieldnames=list(filter_context.keys())
            + [
                "period_key",
                "period_start",
                "audits_count",
                "approved_count",
                "critical_count",
                "rejected_count",
                "approval_rate",
                "average_score",
            ],
        )

    if report_key == "hallazgos_criticos":
        rows = fetch_audit_reports_critical_findings(filters, auditor_user_id=auditor_user_id)
        return build_csv_response(
            rows,
            filename,
            fieldnames=[
                "audit_id",
                "audit_date",
                "auditor_name",
                "mobile_code",
                "technician_name",
                "vehicle_plate",
                "location",
                "installation_type",
                "result_status",
                "total_score",
                "section_title",
                "item_label",
                "status",
                "non_compliance_reason",
                "notes",
                "photo_path",
            ],
        )

    if report_key == "evidencias_faltantes":
        rows = fetch_audit_reports_missing_evidence(filters, auditor_user_id=auditor_user_id)
        return build_csv_response(
            rows,
            filename,
            fieldnames=[
                "audit_id",
                "audit_date",
                "auditor_name",
                "mobile_code",
                "technician_name",
                "vehicle_plate",
                "location",
                "installation_type",
                "result_status",
                "total_score",
                "section_title",
                "item_label",
                "non_compliance_reason",
                "notes",
            ],
        )

    if report_key == "responsabilidad_supervisor":
        rows = fetch_audit_reports_supervisor_responsibility_detail(filters, auditor_user_id=auditor_user_id)
        return build_csv_response(
            rows,
            filename,
            fieldnames=[
                "audit_id",
                "audit_date",
                "auditor_name",
                "mobile_code",
                "supervisor_name",
                "technician_name",
                "technician_employee_code",
                "vehicle_plate",
                "location",
                "installation_type",
                "result_status",
                "total_score",
                "section_title",
                "item_label",
                "non_compliance_reason",
                "notes",
            ],
        )

    if report_key == "insumos_detalle":
        rows = fetch_audit_reports_supply_requests_detail(filters, auditor_user_id=auditor_user_id)
        return build_csv_response(
            rows,
            filename,
            fieldnames=[
                "audit_id",
                "audit_date",
                "auditor_name",
                "mobile_code",
                "technician_name",
                "vehicle_plate",
                "location",
                "installation_type",
                "result_status",
                "total_score",
                "created_at",
                "section_title",
                "item_label",
                "request_type",
                "material_code",
                "quantity",
                "notes",
            ],
        )

    if report_key == "insumos_resumen":
        rows = fetch_audit_reports_supply_requests_summary(filters, auditor_user_id=auditor_user_id)
        rows = [{**filter_context, **row} for row in rows]
        return build_csv_response(
            rows,
            filename,
            fieldnames=list(filter_context.keys()) + ["request_type", "material_code", "requests_count", "total_quantity"],
        )

    abort(404)


@main.route("/reports/export/<report_key>.pdf")
def export_report_pdf(report_key):
    if not can_view_reports():
        abort(403)

    user = current_user()
    auditor_user_id = user["id"] if user and user.get("role") == "auditor" else None

    filters = {
        "from_date": request.args.get("from_date", "").strip(),
        "to_date": request.args.get("to_date", "").strip(),
        "status": request.args.get("status", "").strip(),
        "auditor": request.args.get("auditor", "").strip(),
        "include_pruebas": request.args.get("include_pruebas", "").strip(),
        "supervisor": request.args.get("supervisor", "").strip(),
    }
    if auditor_user_id is not None:
        filters["auditor"] = ""

    date_from = filters["from_date"] or "inicio"
    date_to = filters["to_date"] or "hoy"
    status_suffix = (filters.get("status") or "").strip().replace(" ", "_") or "todos"
    auditor_suffix = (filters.get("auditor") or "").strip().replace(" ", "_") or "todos"
    filename = f"reporte_{report_key}_{date_from}_a_{date_to}_{status_suffix}_{auditor_suffix}.pdf"

    context = build_reports_context(report_key, filters, auditor_user_id)
    if not context:
        abort(404)

    css_path = Path(current_app.root_path) / "static" / "css" / "main.css"
    inline_css = css_path.read_text(encoding="utf-8") if css_path.exists() else ""

    html = render_template(
        "reports_print.html",
        **context,
        inline_css=inline_css,
        print_mode=True,
    )
    try:
        return build_pdf_from_html_response(html, filename)
    except Exception as exc:
        current_app.logger.exception("Error generando PDF de reporte %s", report_key)
        flash(str(exc), "error")
        return redirect(
            url_for(
                "main.reports_print",
                report_key=report_key,
                from_date=filters.get("from_date", ""),
                to_date=filters.get("to_date", ""),
                status=filters.get("status", ""),
                auditor=filters.get("auditor", ""),
                include_pruebas=filters.get("include_pruebas", ""),
                print=1,
            )
        )


@main.route("/reports/<report_key>/report")
def reports_print(report_key):
    if not can_view_reports():
        abort(403)

    user = current_user()
    auditor_user_id = user["id"] if user and user.get("role") == "auditor" else None

    filters = {
        "from_date": request.args.get("from_date", "").strip(),
        "to_date": request.args.get("to_date", "").strip(),
        "status": request.args.get("status", "").strip(),
        "auditor": request.args.get("auditor", "").strip(),
        "include_pruebas": request.args.get("include_pruebas", "").strip(),
        "supervisor": request.args.get("supervisor", "").strip(),
    }
    if auditor_user_id is not None:
        filters["auditor"] = ""
    context = build_reports_context(report_key, filters, auditor_user_id)
    if not context:
        abort(404)

    response = make_response(
        render_template(
            "reports_print.html",
            **context,
            inline_css="",
            print_mode=request.args.get("print") == "1",
        )
    )
    response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "0"
    return response


@main.route("/findings")
def findings_list():
    if not can_view_findings():
        abort(403)

    filters = {
        "from_date": request.args.get("from_date", "").strip(),
        "to_date": request.args.get("to_date", "").strip(),
        "audit_id": request.args.get("audit_id", "").strip(),
        "mobile_code": request.args.get("mobile_code", "").strip(),
        "location": request.args.get("location", "").strip(),
        "auditor": request.args.get("auditor", "").strip(),
        "owner": request.args.get("owner", "").strip(),
        "technician_supervisor": request.args.get("technician_supervisor", "").strip(),
        "section_key": request.args.get("section_key", "").strip(),
        "finding_status": request.args.get("finding_status", "").strip(),
        "priority": request.args.get("priority", "").strip(),
        "validation_status": request.args.get("validation_status", "").strip(),
        "effectiveness": request.args.get("effectiveness", "").strip(),
        "quick_filter": request.args.get("quick_filter", "").strip(),
        "q": request.args.get("q", "").strip(),
        "sort": request.args.get("sort", "").strip(),
        "dir": request.args.get("dir", "").strip(),
    }
    auditor_user_id = current_auditor_user_id()
    supervisor_scope_names = current_supervisor_scope_names()
    page_raw = (request.args.get("page") or "").strip()
    page = 1
    if page_raw:
        try:
            page = max(1, int(page_raw))
        except ValueError:
            page = 1
    page_size = 50
    if auditor_user_id is not None:
        filters["auditor"] = ""
    panel_filters = dict(filters)
    panel_filters["quick_filter"] = ""
    findings_total = count_findings(
        filters,
        auditor_user_id=auditor_user_id,
        supervisor_scope_names=supervisor_scope_names,
    )
    page_count = max(1, (findings_total + page_size - 1) // page_size) if findings_total else 1
    if page > page_count:
        page = page_count
    offset = (page - 1) * page_size
    findings = fetch_findings(
        filters,
        auditor_user_id=auditor_user_id,
        supervisor_scope_names=supervisor_scope_names,
        limit=page_size,
        offset=offset,
    )
    finding_stats = fetch_finding_stats(
        panel_filters,
        auditor_user_id=auditor_user_id,
        supervisor_scope_names=supervisor_scope_names,
    )
    filter_active = any(filters.values())
    has_prev_page = page > 1
    has_next_page = (offset + page_size) < findings_total

    pages_window_findings = []
    if page_count <= 9:
        pages_window_findings = list(range(1, page_count + 1))
    else:
        pages_window_findings.append(1)
        if page - 2 > 2:
            pages_window_findings.append(None)
        start = max(2, page - 2)
        end = min(page_count - 1, page + 2)
        for p in range(start, end + 1):
            pages_window_findings.append(p)
        if page + 2 < page_count - 1:
            pages_window_findings.append(None)
        pages_window_findings.append(page_count)
    mobile_units = fetch_mobile_units()
    location_options = fetch_distinct_finding_locations(
        panel_filters,
        auditor_user_id=auditor_user_id,
        supervisor_scope_names=supervisor_scope_names,
    )
    auditor_options = fetch_distinct_finding_auditors(
        panel_filters,
        auditor_user_id=auditor_user_id,
        supervisor_scope_names=supervisor_scope_names,
    )
    supervisor_options = fetch_distinct_finding_supervisors(
        panel_filters,
        auditor_user_id=auditor_user_id,
        supervisor_scope_names=supervisor_scope_names,
    )
    section_options = [{"key": section["key"], "title": section["title"]} for section in CHECKLIST_SECTIONS]

    def build_quick_filter_url(quick_filter_key):
        query = {key: value for key, value in panel_filters.items() if value}
        query.pop("quick_filter", None)
        query["page"] = 1
        if quick_filter_key:
            for field_name in ("finding_status", "priority", "validation_status", "effectiveness"):
                query.pop(field_name, None)
            query["quick_filter"] = quick_filter_key
        return url_for("main.findings_list", **query)

    active_quick_filter = filters["quick_filter"]
    quick_filter_urls = {
        "reopened": build_quick_filter_url("reopened"),
        "stale_treatment": build_quick_filter_url("stale_treatment"),
        "escalated_treatment": build_quick_filter_url("escalated_treatment"),
        "overdue_validation": build_quick_filter_url("overdue_validation"),
        "overdue_effectiveness": build_quick_filter_url("overdue_effectiveness"),
    }
    quick_filter_cards = [
        {
            "key": "",
            "label": "Total",
            "value": finding_stats["total_findings"],
            "helper": "Ver toda la bandeja actual.",
            "tone": "neutral",
            "href": build_quick_filter_url(""),
            "active": not active_quick_filter,
        },
        {
            "key": "active",
            "label": "Activos",
            "value": finding_stats["active_findings"],
            "helper": "Nuevo, en tratamiento, CER-PVE o reabierto.",
            "tone": "primary",
            "href": build_quick_filter_url("active"),
            "active": active_quick_filter == "active",
        },
        {
            "key": "new",
            "label": "Nuevos",
            "value": finding_stats["new_count"],
            "helper": "Pendientes de primera respuesta.",
            "tone": "warning",
            "href": build_quick_filter_url("new"),
            "active": active_quick_filter == "new",
        },
        {
            "key": "in_progress",
            "label": "En tratamiento",
            "value": finding_stats["in_progress_count"],
            "helper": "Hallazgos respondidos en gestión del supervisor.",
            "tone": "primary",
            "href": build_quick_filter_url("in_progress"),
            "active": active_quick_filter == "in_progress",
        },
        {
            "key": "stale_treatment",
            "label": "Sin novedades",
            "value": finding_stats["stale_treatment_count"],
            "helper": f"{finding_stats['treatment_alert_days']} día(s) o más sin actualización.",
            "tone": "warning",
            "href": build_quick_filter_url("stale_treatment"),
            "active": active_quick_filter == "stale_treatment",
        },
        {
            "key": "escalated_treatment",
            "label": "Escalados",
            "value": finding_stats["escalated_treatment_count"],
            "helper": f"{finding_stats['treatment_escalation_days']} día(s) o más sin novedades.",
            "tone": "danger",
            "href": build_quick_filter_url("escalated_treatment"),
            "active": active_quick_filter == "escalated_treatment",
        },
        {
            "key": "high_priority",
            "label": "Alta prioridad",
            "value": finding_stats["high_priority_count"],
            "helper": "Casos que requieren atención preferente.",
            "tone": "warning",
            "href": build_quick_filter_url("high_priority"),
            "active": active_quick_filter == "high_priority",
        },
        {
            "key": "reopened",
            "label": "Reabiertos",
            "value": finding_stats["reopened_count"],
            "helper": "Necesitan nueva gestión del supervisor.",
            "tone": "danger",
            "href": build_quick_filter_url("reopened"),
            "active": active_quick_filter == "reopened",
        },
        {
            "key": "pending_validation",
            "label": "Pendientes validación",
            "value": finding_stats["pending_validation_count"],
            "helper": "Hallazgos en CER-PVE esperando revisión.",
            "tone": "warning",
            "href": build_quick_filter_url("pending_validation"),
            "active": active_quick_filter == "pending_validation",
        },
        {
            "key": "overdue_validation",
            "label": "CER-PVE vencidos",
            "value": finding_stats["overdue_validation_count"],
            "helper": f"Más de {finding_stats['pending_validation_alert_days']} día(s) sin validar.",
            "tone": "danger",
            "href": build_quick_filter_url("overdue_validation"),
            "active": active_quick_filter == "overdue_validation",
        },
        {
            "key": "overdue_effectiveness",
            "label": "Eficacia vencida",
            "value": finding_stats["overdue_effectiveness_count"],
            "helper": "Seguimientos validados con fecha de eficacia vencida.",
            "tone": "danger",
            "href": build_quick_filter_url("overdue_effectiveness"),
            "active": active_quick_filter == "overdue_effectiveness",
        },
    ]
    return_to = safe_next_url(request.full_path if request.query_string else request.path) or url_for("main.findings_list")
    return render_template(
        "findings.html",
        findings=findings,
        findings_total=findings_total,
        finding_stats=finding_stats,
        quick_filter_cards=quick_filter_cards,
        quick_filter_urls=quick_filter_urls,
        filters=filters,
        filter_active=filter_active,
        mobile_units=mobile_units,
        location_options=location_options,
        auditor_options=auditor_options,
        supervisor_options=supervisor_options,
        section_options=section_options,
        page=page,
        page_size=page_size,
        page_count=page_count,
        has_prev_page=has_prev_page,
        has_next_page=has_next_page,
        pages_window_findings=pages_window_findings,
        return_to=return_to,
    )


@main.route("/api/findings/alerts/ack", methods=["POST"])
def ack_findings_alerts():
    if not current_user() or not can_view_findings():
        return jsonify({"error": "unauthorized"}), 401
    csrf_value = (request.headers.get("X-CSRF-Token") or "").strip()
    if not validate_csrf_token(csrf_value):
        return jsonify({"error": "csrf_failed"}), 400
    now = int(time.time())
    session["findings_alerts_next_show_at"] = now + (4 * 60 * 60)
    return jsonify({"ok": True, "next_show_at": session["findings_alerts_next_show_at"]})


@main.route("/findings/<int:finding_id>")
def finding_detail(finding_id):
    if not can_view_findings():
        abort(403)

    return_to = safe_next_url(request.args.get("return_to")) or url_for("main.findings_list")
    finding = fetch_finding_detail(
        finding_id,
        auditor_user_id=current_auditor_user_id(),
        supervisor_scope_names=current_supervisor_scope_names(),
    )
    if not finding:
        abort(404)
    finding_events = fetch_finding_events(finding_id)
    return render_template(
        "finding_detail.html",
        finding=finding,
        finding_events=finding_events,
        treatment_reason_options=TREATMENT_REASON_OPTIONS,
        return_to=return_to,
    )


@main.route("/findings/<int:finding_id>/respond", methods=["POST"])
def finding_respond(finding_id):
    if not can_respond_findings():
        abort(403)

    return_to = safe_next_url(request.form.get("return_to")) or url_for("main.findings_list")
    finding = fetch_finding_detail(
        finding_id,
        auditor_user_id=current_auditor_user_id(),
        supervisor_scope_names=current_supervisor_scope_names(),
    )
    if not finding:
        abort(404)

    try:
        response_notes = (request.form.get("response_notes") or "").strip().upper()
        finding_status = (request.form.get("finding_status") or "").strip().lower()
        treatment_reason = (request.form.get("treatment_reason") or "").strip().lower()
        treatment_note = (request.form.get("treatment_note") or "").strip().upper()
        treatment_next_step = (request.form.get("treatment_next_step") or "").strip().upper()
        treatment_commitment_date = (request.form.get("treatment_commitment_date") or "").strip()
        closure_criteria = (request.form.get("closure_criteria") or "").strip().upper()
        effectiveness_due_date = (request.form.get("effectiveness_due_date") or "").strip()
        evidence_file = request.files.get("evidence_file")
        evidence_path = None
        if has_uploaded_file(evidence_file):
            evidence_path = persist_finding_evidence(evidence_file, finding["audit_date"], finding_id)

        update_finding_response(
            finding_id,
            finding_status=finding_status,
            response_notes=response_notes,
            treatment_reason=treatment_reason,
            treatment_note=treatment_note,
            treatment_next_step=treatment_next_step,
            treatment_commitment_date=treatment_commitment_date,
            evidence_path=evidence_path,
            closure_criteria=closure_criteria,
            effectiveness_due_date=effectiveness_due_date,
            responded_by_user_id=current_user()["id"],
        )
        flash("Respuesta del hallazgo guardada.", "success")
    except ValueError as exc:
        flash(str(exc), "error")

    return redirect(url_for("main.finding_detail", finding_id=finding_id, return_to=return_to))


@main.route("/findings/<int:finding_id>/treatment-update", methods=["POST"])
def finding_treatment_update(finding_id):
    if not can_update_treatment_findings():
        abort(403)

    return_to = safe_next_url(request.form.get("return_to")) or url_for("main.findings_list")
    finding = fetch_finding_detail(
        finding_id,
        auditor_user_id=current_auditor_user_id(),
        supervisor_scope_names=current_supervisor_scope_names(),
    )
    if not finding:
        abort(404)

    try:
        add_finding_treatment_update(
            finding_id,
            treatment_reason=(request.form.get("treatment_reason") or "").strip().lower(),
            treatment_note=(request.form.get("treatment_note") or "").strip().upper(),
            treatment_next_step=(request.form.get("treatment_next_step") or "").strip().upper(),
            treatment_commitment_date=(request.form.get("treatment_commitment_date") or "").strip(),
            actor_user_id=current_user()["id"],
        )
        flash("Novedad de tratamiento guardada.", "success")
    except ValueError as exc:
        flash(str(exc), "error")

    return redirect(url_for("main.finding_detail", finding_id=finding_id, return_to=return_to))


@main.route("/findings/<int:finding_id>/validate", methods=["POST"])
def finding_validate(finding_id):
    if not can_validate_findings():
        abort(403)

    return_to = safe_next_url(request.form.get("return_to")) or url_for("main.findings_list")
    finding = fetch_finding_detail(
        finding_id,
        auditor_user_id=current_auditor_user_id(),
        supervisor_scope_names=current_supervisor_scope_names(),
    )
    if not finding:
        abort(404)

    validation_action = (request.form.get("validation_action") or "").strip().lower()
    validation_notes = (request.form.get("validation_notes") or "").strip().upper()
    if validation_action not in {"approve", "reject"}:
        flash("La accion de validacion no es valida.", "error")
        return redirect(url_for("main.finding_detail", finding_id=finding_id, return_to=return_to))

    try:
        validate_finding(
            finding_id,
            validated_by_user_id=current_user()["id"],
            approved=(validation_action == "approve"),
            validation_notes=validation_notes,
        )
        flash("Validacion actualizada.", "success")
    except ValueError as exc:
        flash(str(exc), "error")
    return redirect(url_for("main.finding_detail", finding_id=finding_id, return_to=return_to))


@main.route("/findings/<int:finding_id>/effectiveness", methods=["POST"])
def finding_effectiveness_update(finding_id):
    if not can_verify_findings_effectiveness():
        abort(403)

    return_to = safe_next_url(request.form.get("return_to")) or url_for("main.findings_list")
    finding = fetch_finding_detail(
        finding_id,
        auditor_user_id=current_auditor_user_id(),
        supervisor_scope_names=current_supervisor_scope_names(),
    )
    if not finding:
        abort(404)

    effectiveness_status = (request.form.get("effectiveness_status") or "").strip().lower()
    effectiveness_notes = (request.form.get("effectiveness_notes") or "").strip().upper()
    try:
        user = current_user()
        allow_override = bool(user and user.get("role") in {"admin", "gerente"})
        update_finding_effectiveness(
            finding_id,
            effectiveness_status=effectiveness_status,
            effectiveness_notes=effectiveness_notes,
            verified_by_user_id=current_user()["id"],
            allow_override=allow_override,
        )
        flash("Verificación de eficacia actualizada.", "success")
    except ValueError as exc:
        flash(str(exc), "error")

    return redirect(url_for("main.finding_detail", finding_id=finding_id, return_to=return_to))


@main.route("/audits/<int:audit_id>/record-scope", methods=["POST"])
def audit_record_scope_update(audit_id):
    if not is_admin():
        abort(403)

    audit = fetch_audit_detail(audit_id)
    if not audit:
        abort(404)

    record_scope = (request.form.get("record_scope") or "").strip().lower()
    if record_scope not in {"oficial", "pruebas"}:
        flash("El sector seleccionado no es valido.", "error")
        return redirect(url_for("main.audit_detail", audit_id=audit_id))

    if not update_audit_record_scope(audit_id, record_scope):
        flash("No fue posible actualizar el sector de la auditoria.", "error")
        return redirect(url_for("main.audit_detail", audit_id=audit_id))

    if record_scope == "pruebas":
        flash("La auditoria fue movida a pruebas y ya no impacta en el circuito oficial.", "success")
    else:
        flash("La auditoria volvio al circuito oficial.", "success")
    return redirect(url_for("main.audit_detail", audit_id=audit_id))


@main.route("/audits/<int:audit_id>")
def audit_detail(audit_id):
    audit = fetch_audit_detail(audit_id, supervisor_scope_names=current_supervisor_scope_names())
    if not audit:
        abort(404)
    if is_auditor():
        user = current_user()
        if audit.get("auditor_user_id") != user["id"] and (audit.get("auditor_name") or "") != user["username"]:
            abort(404)

    audit["auditor_signature_path"] = build_cloudinary_signed_url(
        audit.get("auditor_signature_path"),
        expires_in_seconds=900,
    )
    audit["technician_signature_path"] = build_cloudinary_signed_url(
        audit.get("technician_signature_path"),
        expires_in_seconds=900,
    )

    items = fetch_audit_items(audit_id)
    grouped_items = build_grouped_audit_items(items)
    supply_requests = fetch_audit_supply_requests(audit_id)
    findings = fetch_audit_findings(audit_id)
    tnps_response = fetch_tnps_response_for_audit(audit_id)
    qc_sessions = fetch_qc_sessions_for_audit(
        audit_id,
        auditor_user_id=(current_user()["id"] if is_auditor() else None),
        supervisor_scope_names=current_supervisor_scope_names(),
    )
    response = make_response(
        render_template(
            "audit_detail.html",
            audit=audit,
            grouped_items=grouped_items,
            supply_requests=supply_requests,
            findings=findings,
            tnps_response=tnps_response,
            qc_sessions=qc_sessions,
        )
    )
    response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "0"
    return response


@main.route("/audits/<int:audit_id>/report")
def audit_report(audit_id):
    audit = fetch_audit_detail(audit_id, supervisor_scope_names=current_supervisor_scope_names())
    if not audit:
        abort(404)
    if is_auditor():
        user = current_user()
        if audit.get("auditor_user_id") != user["id"] and (audit.get("auditor_name") or "") != user["username"]:
            abort(404)

    expires_in_seconds = 3600 if request.args.get("print") == "1" else 900
    audit["auditor_signature_path"] = build_cloudinary_signed_url(
        audit.get("auditor_signature_path"),
        expires_in_seconds=expires_in_seconds,
    )
    audit["technician_signature_path"] = build_cloudinary_signed_url(
        audit.get("technician_signature_path"),
        expires_in_seconds=expires_in_seconds,
    )

    items = fetch_audit_items(audit_id)
    report = build_audit_report_metrics(audit, items)
    grouped_items_all = build_grouped_audit_items(items)

    detail_status_raw = (request.args.get("status") or "").strip()
    detail_section_raw = (request.args.get("section") or "").strip()

    status_to_statuses = {
        "cumple": {"cumple", "conforme"},
        "no_cumple": {"no_cumple", "nc_menor", "nc_mayor"},
        "no_aplica": {"no_aplica"},
    }
    status_labels = {
        "cumple": "Cumple",
        "no_cumple": "No cumple",
        "no_aplica": "No aplica",
    }

    detail_status = detail_status_raw if detail_status_raw in status_to_statuses else ""
    selected_statuses = status_to_statuses.get(detail_status)
    detail_section = ""
    if detail_section_raw:
        if detail_section_raw in grouped_items_all:
            detail_section = detail_section_raw
        else:
            detail_section_raw_folded = detail_section_raw.casefold()
            for section_title in grouped_items_all.keys():
                if section_title.casefold() == detail_section_raw_folded:
                    detail_section = section_title
                    break

    grouped_items_detail_source = (
        {detail_section: grouped_items_all.get(detail_section, [])}
        if detail_section
        else grouped_items_all
    )
    grouped_items_detail = {}
    for section_title, section_items in grouped_items_detail_source.items():
        filtered_items = (
            [item for item in section_items if item["status"] in selected_statuses]
            if selected_statuses
            else list(section_items)
        )
        if filtered_items:
            grouped_items_detail[section_title] = filtered_items

    detail_filter_active = bool(detail_status or detail_section)
    detail_filter = {
        "status": detail_status,
        "status_label": status_labels.get(detail_status, ""),
        "section": detail_section,
    }
    tnps_response = fetch_tnps_response_for_audit(audit_id)
    supply_requests = fetch_audit_supply_requests(audit_id)
    response = make_response(
        render_template(
            "audit_report.html",
            audit=audit,
            grouped_items=grouped_items_detail if detail_filter_active else grouped_items_all,
            report=report,
            tnps_response=tnps_response,
            supply_requests=supply_requests,
            print_mode=request.args.get("print") == "1",
            pdf_detail_mode=False,
            detail_filter_active=detail_filter_active,
            detail_filter=detail_filter,
        )
    )
    response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "0"
    return response


@main.route("/audits/<int:audit_id>/report.pdf")
def audit_report_pdf(audit_id):
    audit = fetch_audit_detail(audit_id)
    if not audit:
        abort(404)
    if is_auditor():
        user = current_user()
        if audit.get("auditor_user_id") != user["id"] and (audit.get("auditor_name") or "") != user["username"]:
            abort(404)

    expires_in_seconds = 3600
    audit["auditor_signature_path"] = build_cloudinary_signed_url(
        audit.get("auditor_signature_path"),
        expires_in_seconds=expires_in_seconds,
    )
    audit["technician_signature_path"] = build_cloudinary_signed_url(
        audit.get("technician_signature_path"),
        expires_in_seconds=expires_in_seconds,
    )

    items = fetch_audit_items(audit_id)
    report = build_audit_report_metrics(audit, items)
    grouped_items_all = build_grouped_audit_items(items)
    tnps_response = fetch_tnps_response_for_audit(audit_id)
    supply_requests = fetch_audit_supply_requests(audit_id)

    css_path = Path(current_app.root_path) / "static" / "css" / "main.css"
    inline_css = css_path.read_text(encoding="utf-8") if css_path.exists() else ""

    date_suffix = (audit.get("audit_date") or "sin_fecha").strip().replace("/", "-")
    filename = secure_filename(f"auditoria_{audit_id}_{date_suffix}.pdf") or f"auditoria_{audit_id}.pdf"
    filename_override = (request.args.get("filename") or "").strip()
    if filename_override:
        normalized_override = secure_filename(filename_override) or filename
        if not normalized_override.lower().endswith(".pdf"):
            normalized_override = f"{normalized_override}.pdf"
        filename = normalized_override

    html = render_template(
        "audit_report.html",
        audit=audit,
        grouped_items=grouped_items_all,
        report=report,
        tnps_response=tnps_response,
        supply_requests=supply_requests,
        inline_css=inline_css,
        print_mode=True,
        pdf_detail_mode=False,
        detail_filter_active=False,
        detail_filter={},
    )
    try:
        return build_pdf_from_html_response(html, filename)
    except Exception as exc:
        current_app.logger.exception("Error generando PDF auditoría %s (informe)", audit_id)
        return build_audit_items_fallback_pdf(audit, items, filename, title_suffix="Informe")


@main.route("/audits/<int:audit_id>/detail.pdf")
def audit_detail_pdf(audit_id):
    audit = fetch_audit_detail(audit_id)
    if not audit:
        abort(404)
    if is_auditor():
        user = current_user()
        if audit.get("auditor_user_id") != user["id"] and (audit.get("auditor_name") or "") != user["username"]:
            abort(404)

    date_suffix = (audit.get("audit_date") or "sin_fecha").strip().replace("/", "-")
    filename = secure_filename(f"auditoria_{audit_id}_{date_suffix}_detalle.pdf") or f"auditoria_{audit_id}_detalle.pdf"
    return redirect(url_for("main.audit_report_pdf", audit_id=audit_id, filename=filename))


@main.route("/imports", methods=["GET", "POST"])
def imports():
    if not can_import():
        abort(403)
    import_summary = None
    import_types = CSV_IMPORT_TYPES
    if is_auditor():
        allowed = {"material_stock", "equipment_inventory"}
        import_types = {key: value for key, value in CSV_IMPORT_TYPES.items() if key in allowed}

    if request.method == "POST":
        if not validate_csrf_token(request.form.get("csrf_token")):
            flash("Token inválido. Refresca la página y vuelve a intentar.", "error")
            return redirect(url_for("main.imports"))

        import_type = request.form.get("import_type", "")
        import_config = import_types.get(import_type)

        if not import_config:
            flash("Selecciona un tipo de importacion valido.", "error")
            return redirect(url_for("main.imports"))

        batch_id = None
        try:
            fieldnames, rows, meta = parse_tabular_upload(request.files.get("csv_file"))
            validate_required_columns(fieldnames, import_config["required_columns"])
            file_sha256 = hashlib.sha256(meta.get("raw_content") or b"").hexdigest()
            user = current_user()
            can_rollback = import_type in {"material_stock", "equipment_inventory"}

            scope = {}
            if import_type == "material_stock":
                material_col = "material" if "material" in fieldnames else ("material_name" if "material_name" in fieldnames else (fieldnames[0] if fieldnames else ""))
                scope = {
                    "mobile_codes": [
                        str(col)
                        for col in fieldnames
                        if col and col not in {material_col, "total"}
                    ]
                }
            elif import_type == "equipment_inventory":
                warehouse_codes = {
                    (row.get("codigo_almacen") or "").strip()
                    for row in rows
                    if (row.get("codigo_almacen") or "").strip() and (row.get("almacen") or "").strip()
                }
                scope = {"warehouse_codes": sorted(warehouse_codes)}

            batch_id = create_import_batch(
                import_type,
                import_config["label"],
                filename=meta.get("filename"),
                file_sha256=file_sha256,
                uploaded_by_user=user,
                row_count=len(rows),
                can_rollback=can_rollback,
                scope=scope,
            )

            if import_type in {"material_stock", "equipment_inventory"}:
                import_summary = import_config["importer"](rows, import_batch_id=batch_id)
            else:
                import_summary = import_config["importer"](rows)
            finalize_import_batch(
                batch_id,
                status="completed",
                created_count=import_summary["created_count"],
                updated_count=import_summary["updated_count"],
                skipped_rows=import_summary["skipped_rows"],
            )

            flash(
                f"{import_config['label']} importados: {import_summary['created_count']} creados, "
                f"{import_summary['updated_count']} actualizados.",
                "success",
            )
            if import_summary["skipped_rows"]:
                flash(
                    "Se omitieron filas: " + " | ".join(import_summary["skipped_rows"][:5]),
                    "error",
                )
        except ValueError as exc:
            if batch_id:
                finalize_import_batch(batch_id, status="failed", error_message=str(exc)[:400])
            flash(str(exc), "error")
        except Exception as exc:
            if batch_id:
                finalize_import_batch(
                    batch_id,
                    status="failed",
                    error_message=f"{type(exc).__name__}: {str(exc)[:400]}",
                )
            current_app.logger.exception("Error importando %s", import_type)
            flash(
                "Error interno importando el archivo. "
                f"Detalle: {type(exc).__name__}: {str(exc)[:180]}",
                "error",
            )

    import_batches = fetch_import_batches(50) if is_admin() else []
    return render_template(
        "imports.html",
        import_types=import_types,
        technicians_count=len(fetch_technicians()),
        vehicles_count=len(fetch_vehicles()),
        mobile_units_count=len(fetch_mobile_units()),
        stock_stats=fetch_stock_stats(),
        materials_summary=fetch_materials_summary(),
        storage_locations_summary=fetch_storage_locations_summary(),
        equipment_summary=fetch_equipment_summary(),
        import_summary=import_summary,
        import_batches=import_batches,
    )


@main.route("/imports/<int:batch_id>/rollback", methods=["POST"])
def rollback_import(batch_id):
    if not is_admin():
        abort(403)
    if not validate_csrf_token(request.form.get("csrf_token")):
        flash("Token inválido. Refresca la página y vuelve a intentar.", "error")
        return redirect(url_for("main.imports"))

    user = current_user()
    try:
        rollback_import_batch(batch_id, user["id"])
        flash("Importación revertida. El inventario volvió al estado anterior.", "success")
    except ValueError as exc:
        flash(str(exc), "error")
    except Exception as exc:
        current_app.logger.exception("Error revirtiendo importación %s", batch_id)
        flash(
            "Error interno revirtiendo la importación. "
            f"Detalle: {type(exc).__name__}: {str(exc)[:180]}",
            "error",
        )

    return redirect(url_for("main.imports"))


@main.route("/storage-locations")
def storage_locations():
    filters = {
        "q": request.args.get("q", "").strip(),
        "center": request.args.get("center", "").strip(),
        "warehouse_type": request.args.get("warehouse_type", "").strip(),
        "enabled": request.args.get("enabled", "").strip(),
    }
    rows = fetch_storage_locations(filters)
    return render_template(
        "storage_locations.html",
        rows=rows,
        filters=filters,
        centers=fetch_distinct_storage_centers(),
        warehouse_types=fetch_distinct_warehouse_types(),
    )


@main.route("/equipment")
def equipment():
    filters = {
        "q": request.args.get("q", "").strip(),
        "center": request.args.get("center", "").strip(),
        "warehouse_code": request.args.get("warehouse_code", "").strip(),
    }
    rows = fetch_equipment_inventory(filters)
    return render_template(
        "equipment.html",
        rows=rows,
        filters=filters,
        centers=fetch_distinct_storage_centers(),
        warehouse_codes=fetch_distinct_warehouse_codes(),
    )


@main.route("/materials-stock")
def materials_stock():
    filters = {
        "q": request.args.get("q", "").strip(),
        "mobile_code": request.args.get("mobile_code", "").strip(),
    }
    rows = fetch_material_stock_rows(filters)
    return render_template(
        "materials_stock.html",
        rows=rows,
        filters=filters,
        mobile_codes=fetch_distinct_mobile_codes(),
    )


@main.route("/mobiles/<mobile_code>")
def mobile_detail(mobile_code):
    mobile = fetch_mobile_unit_detail(mobile_code)
    if not mobile:
        abort(404)

    user = current_user()
    auditor_user_id = user["id"] if user and user.get("role") == "auditor" else None
    return render_template(
        "mobile_detail.html",
        mobile=mobile,
        overview=fetch_mobile_overview_stats(mobile_code),
        storage_locations=fetch_mobile_storage_locations(mobile_code),
        equipment_rows=fetch_mobile_equipment(mobile_code),
        stock_rows=fetch_mobile_material_stock(mobile_code),
        related_audits=fetch_mobile_related_audits(mobile_code, auditor_user_id=auditor_user_id),
        related_vehicles=fetch_vehicles_by_employee_code(mobile.get("employee_code")),
        technicians=fetch_technicians(),
    )


@main.route("/mobiles/<mobile_code>/technician", methods=["POST"])
def assign_mobile_technician(mobile_code):
    if not is_admin():
        abort(403)

    mobile = fetch_mobile_unit_detail(mobile_code)
    if not mobile:
        abort(404)

    technician_id_raw = request.form.get("technician_id", "").strip()
    technician_id = None
    if technician_id_raw:
        try:
            technician_id = int(technician_id_raw)
        except ValueError:
            flash("El tecnico seleccionado no es valido.", "error")
            return redirect(url_for("main.mobile_detail", mobile_code=mobile_code))

    update_mobile_unit_technician(mobile_code, technician_id)
    if technician_id is None:
        flash(f"Se desvinculo el movil {mobile_code} del tecnico.", "success")
    else:
        flash(f"Se actualizo el tecnico vinculado al movil {mobile_code}.", "success")

    return redirect(url_for("main.mobile_detail", mobile_code=mobile_code))


@main.route("/api/mobiles/<int:mobile_unit_id>/audit-context")
def mobile_audit_context(mobile_unit_id):
    context = fetch_mobile_audit_context(mobile_unit_id)
    if not context:
        return jsonify({"error": "Movil no encontrado."}), 404
    return jsonify(context)


@main.route("/audits/new", methods=["GET", "POST"])
def new_audit():
    if not can_create_audit():
        abort(403)
    mobile_units = fetch_mobile_units()
    print(f"DEBUG: Mobile Units: {mobile_units}")
    vehicles = fetch_vehicles()
    material_catalog = fetch_material_catalog()
    material_index = {row["material_code"]: row["material_name"] for row in material_catalog}
    herramientas_section = next((section for section in CHECKLIST_SECTIONS if section["key"] == "herramientas"), None)
    herramientas_title = herramientas_section["title"] if herramientas_section else "Herramientas"
    hand_tools = []
    hand_tools_section = next(
        (section for section in CHECKLIST_SECTIONS if section["key"] == "herramientas_mano"),
        None,
    )
    if hand_tools_section:
        hand_tools = [
            {
                "key": item["key"],
                "label": item["label"],
                "material_code": item.get("material_code") or "",
            }
            for item in hand_tools_section["items"]
            if item.get("hand_tool")
        ]

    if request.method == "POST":
        try:
            user = current_user()
            auditor_user_id = user["id"] if user else None
            mobile_unit_id_raw = request.form.get("mobile_unit_id", "").strip()
            if not mobile_unit_id_raw:
                raise ValueError("Debes seleccionar un movil tecnico.")

            mobile_unit_id = int(mobile_unit_id_raw)
            selected_mobile = fetch_mobile_unit_by_any_id(mobile_unit_id)
            if not selected_mobile:
                raise ValueError("Debes seleccionar un movil tecnico valido.")

            technician_display_name = (
                selected_mobile.get("technician_name")
                or selected_mobile.get("user_name")
                or None
            )
            technician_employee_code = selected_mobile.get("employee_code") or None
            technician_company_snapshot = (selected_mobile.get("technician_company_name") or "").strip().upper() or None
            technician_supervisor_snapshot = (selected_mobile.get("technician_supervisor_name") or "").strip().upper() or None
            technician_center_snapshot = (selected_mobile.get("technician_center_name") or "").strip().upper() or None
            is_virtual_mobile = bool(selected_mobile.get("_is_virtual")) or int(selected_mobile.get("id") or 0) < 0
            if not technician_display_name and technician_employee_code:
                technician_display_name = technician_employee_code

            vehicle_id_raw = request.form.get("vehicle_id", "").strip()
            if not vehicle_id_raw:
                raise ValueError("Debes seleccionar un vehiculo.")

            audit_date = datetime.strptime(request.form["audit_date"], "%Y-%m-%d").date().isoformat()
            total_score, result_status, items = calculate_audit_result(request.form, request.files)
            persist_item_evidence(items, audit_date)
            auditor_signature_path = persist_auditor_signature(
                request.form.get("auditor_signature"),
                audit_date,
            )
            technician_signature_path = persist_technician_signature(
                request.form.get("technician_signature"),
                audit_date,
            )

            extinguisher_expiry = (request.form.get("expiry__extintor") or "").strip()
            extintor_status = (request.form.get("status__extintor") or "").strip()
            if extintor_status == "cumple" and extinguisher_expiry:
                if extinguisher_expiry < audit_date:
                    raise ValueError(
                        "La fecha de caducidad del extintor no puede ser anterior a la fecha de la auditoria."
                    )
                update_vehicle_extinguisher_expiry(int(vehicle_id_raw), extinguisher_expiry)

            insurance_expiry = (request.form.get("expiry__insurance") or "").strip()
            seguro_vehicular_status = (request.form.get("status__seguro_vehicular") or "").strip()
            if seguro_vehicular_status == "cumple" and insurance_expiry:
                if insurance_expiry < audit_date:
                    raise ValueError(
                        "La fecha de vencimiento del seguro no puede ser anterior a la fecha de la auditoria."
                    )
                update_vehicle_insurance_expiry(int(vehicle_id_raw), insurance_expiry)

            gnc_expiry = (request.form.get("expiry__gnc") or "").strip()
            gnc_status = (request.form.get("status__oblea_gnc") or "").strip()
            if gnc_status == "cumple" and gnc_expiry:
                if gnc_expiry < audit_date:
                    raise ValueError(
                        "La fecha de caducidad de la oblea de GNC no puede ser anterior a la fecha de la auditoria."
                    )
                update_vehicle_gnc_expiry(int(vehicle_id_raw), gnc_expiry)

            rto_expiry = (request.form.get("expiry__rto") or "").strip()
            rto_status = (request.form.get("status__rto") or "").strip()
            if rto_status == "cumple" and rto_expiry:
                if rto_expiry < audit_date:
                    raise ValueError(
                        "La fecha de vencimiento de la RTO no puede ser anterior a la fecha de la auditoria."
                    )
                update_vehicle_rto_expiry(int(vehicle_id_raw), rto_expiry)

            botiquin_expiry = (request.form.get("expiry__botiquin") or "").strip()
            botiquin_status = (request.form.get("status__botiquin") or "").strip()
            if botiquin_status == "cumple" and botiquin_expiry:
                if botiquin_expiry < audit_date:
                    raise ValueError(
                        "La fecha de vencimiento del botiquin no puede ser anterior a la fecha de la auditoria."
                    )
                update_vehicle_botiquin_expiry(int(vehicle_id_raw), botiquin_expiry)

            serialized_stock_status = (request.form.get("serialized_stock_status") or "").strip()
            if not serialized_stock_status:
                raise ValueError(
                    "Debes indicar el estado de serializados (Completo, Faltan o No revisado)."
                )
            if serialized_stock_status not in {"ok", "missing", "not_checked"}:
                raise ValueError("El estado de serializados no es valido.")

            serialized_stock_notes = (request.form.get("serialized_stock_notes") or "").strip().upper() or None
            if serialized_stock_status == "missing" and not serialized_stock_notes:
                raise ValueError("Si faltan serializados, debes detallar los faltantes.")

            material_stock_status = (request.form.get("material_stock_status") or "").strip()
            if not material_stock_status:
                raise ValueError(
                    "Debes indicar el estado del stock (Completo, Faltan o No revisado)."
                )
            if material_stock_status not in {"ok", "missing", "not_checked"}:
                raise ValueError("El estado del stock no es valido.")

            material_stock_notes = (request.form.get("material_stock_notes") or "").strip().upper() or None
            if material_stock_status == "missing" and not material_stock_notes:
                raise ValueError("Si faltan materiales en stock, debes detallar los faltantes.")

            if serialized_stock_status == "missing":
                items.append(
                    {
                        "section_key": "stock_snapshot",
                        "section_title": "Herramientas y stock",
                        "item_key": "serialized_stock_missing",
                        "item_label": "Equipos serializados del móvil",
                        "status": "no_cumple",
                        "is_critical": True,
                        "non_compliance_reason": "faltantes_serializados",
                        "notes": serialized_stock_notes,
                        "photo_path": None,
                    }
                )

            if material_stock_status == "missing":
                items.append(
                    {
                        "section_key": "stock_snapshot",
                        "section_title": "Herramientas y stock",
                        "item_key": "material_stock_missing",
                        "item_label": "Stock de materiales del inventario",
                        "status": "no_cumple",
                        "is_critical": False,
                        "non_compliance_reason": "faltantes_stock_materiales",
                        "notes": material_stock_notes,
                        "photo_path": None,
                    }
                )

            supply_requests = []
            indices = []
            for key in request.form.keys():
                if key.startswith("supply_request_type__"):
                    try:
                        indices.append(int(key.split("__", 1)[1]))
                    except (IndexError, ValueError):
                        continue

            herramientas_item_map = {}
            if herramientas_section:
                herramientas_item_map = {
                    item["key"]: item["label"] for item in herramientas_section["items"]
                }

            for index in sorted(set(indices)):
                request_type = (request.form.get(f"supply_request_type__{index}") or "").strip()
                if not request_type:
                    continue

                if request_type not in {"reponer", "cambiar"}:
                    raise ValueError("Solicitud invalida. Usa reponer o cambiar.")

                material_code_raw = (request.form.get(f"supply_request_code__{index}") or "").strip()
                if not material_code_raw:
                    raise ValueError("Debes indicar el codigo del material en la solicitud.")

                material_code = material_code_raw.split(" - ", 1)[0].strip()
                normalized_material_code = material_code.upper()
                if normalized_material_code != "SIN CODIGO":
                    if not material_index:
                        raise ValueError(
                            "No hay materiales importados para validar codigos. Importa Stock de materiales primero."
                        )
                    material = fetch_material_by_code(material_code)
                    if not material:
                        raise ValueError(
                            f"El codigo {material_code} no existe en materiales importados."
                        )
                else:
                    material = None

                quantity_raw = (request.form.get(f"supply_request_qty__{index}") or "").strip()
                quantity = None
                if quantity_raw:
                    try:
                        quantity = int(quantity_raw)
                    except ValueError:
                        raise ValueError("La cantidad solicitada no es valida.")

                notes = (request.form.get(f"supply_request_notes__{index}") or "").strip().upper() or None
                related_item_key = (request.form.get(f"supply_request_item__{index}") or "").strip()
                related_label = herramientas_item_map.get(related_item_key)
                if normalized_material_code == "SIN CODIGO" and not notes:
                    raise ValueError("Si seleccionas SIN CODIGO, debes completar la nota.")

                supply_requests.append(
                    {
                        "section_key": "herramientas",
                        "section_title": herramientas_title,
                        "item_key": related_item_key or f"material_{material_code}",
                        "item_label": related_label or (material["material_name"] if material else "SIN CODIGO"),
                        "request_type": request_type,
                        "material_code": normalized_material_code if normalized_material_code == "SIN CODIGO" else material_code,
                        "quantity": quantity,
                        "notes": notes,
                    }
                )

            auditor_name = request.form["auditor_name"].strip().upper()
            if user and user.get("role") == "auditor":
                auditor_name = user["username"].upper()

            sa_number = (request.form.get("sa_number") or "").strip()
            if sa_number and not sa_number.isdigit():
                raise ValueError("El SA debe contener solo números.")

            audit_id = create_audit(
                {
                    "audit_date": audit_date,
                    "auditor_name": auditor_name,
                    "auditor_user_id": auditor_user_id,
                    "sa_number": sa_number or None,
                    "auditor_signature_path": auditor_signature_path,
                    "technician_signature_path": technician_signature_path,
                    "technician_display_name": technician_display_name,
                    "technician_employee_code": technician_employee_code,
                    "technician_company_snapshot": technician_company_snapshot,
                    "technician_supervisor_snapshot": technician_supervisor_snapshot,
                    "technician_center_snapshot": technician_center_snapshot,
                    "location": request.form["location"].strip().upper(),
                    "address": (request.form.get("address") or "").strip().upper() or None,
                    "installation_type": request.form["installation_type"].strip().upper(),
                    "mobile_unit_id": None if is_virtual_mobile else mobile_unit_id,
                    "technician_id": selected_mobile.get("technician_id"),
                    "vehicle_id": int(vehicle_id_raw),
                    "total_score": total_score,
                    "result_status": result_status,
                    "general_notes": request.form.get("general_notes", "").strip().upper() or None,
                    "serialized_stock_status": serialized_stock_status,
                    "serialized_stock_notes": serialized_stock_notes,
                    "material_stock_status": material_stock_status,
                    "material_stock_notes": material_stock_notes,
                },
                items,
                supply_requests,
            )
            flash("Auditoria guardada correctamente.", "success")
            return redirect(url_for("main.audit_detail", audit_id=audit_id))
        except ValueError as exc:
            flash(str(exc), "error")

    response = make_response(
        render_template(
            "audit_form.html",
            checklist_sections=AUDIT_CHECKLIST_SECTIONS,
            mobile_units=mobile_units,
            vehicles=vehicles,
            material_index=material_index,
            herramientas_section=herramientas_section,
            hand_tools=hand_tools,
            auditor_rules={
                "include_quality_section": False,
                "impact_targets": [
                    {
                        "who": "Técnico",
                        "how": "El score de la auditoría se calcula sobre ítems imputables.",
                    },
                    {
                        "who": "Supervisor",
                        "how": "Los reportes por supervisor agregan las auditorías de sus técnicos.",
                    },
                ],
                "score_rules": {
                    "status_scores": {
                        "cumple": 1.0,
                        "conforme": 1.0,
                        "nc_menor": 0.5,
                        "nc_mayor": 0.0,
                        "no_cumple": 0.0,
                    },
                    "non_imputable_note": "Si un ítem queda en No cumple con motivo sin impacto, se excluye del cálculo del score (no suma ni resta).",
                    "weight_note": "El impacto exacto en el score final depende del peso de la sección y la cantidad de ítems imputables evaluados en esa sección.",
                },
                "safety_usage_items": [
                    "casco",
                    "lentes",
                    "chaleco",
                    "botas",
                    "senalizacion",
                    "orden_entorno",
                    "guantes_fibra_sintetica_poliuretano",
                    "guante_dielectrico_1000v",
                    "arnes_completo_anticaidas",
                    "cola_amarre_separada",
                    "mentonera_libus_15mm_gancho_c",
                ],
                "reason_rows": [
                    {
                        "code": code,
                        "label": NON_COMPLIANCE_REASON_LABELS.get(code, code),
                        "counts_in_score": code not in SCORE_EXCLUDED_REASONS,
                        "item_score_value": (
                            0.0 if code not in SCORE_EXCLUDED_REASONS else None
                        ),
                        "impact": (
                            "Responsabilidad supervisor (excluido del score)"
                            if code in SUPERVISOR_RESPONSIBILITY_REASONS
                            else (
                                "Impacta (responsabilidad técnico)"
                                if code not in SCORE_EXCLUDED_REASONS
                                else "Sin impacto (no imputable)"
                            )
                        ),
                        "impacts_who": (
                            "Supervisor"
                            if code in SUPERVISOR_RESPONSIBILITY_REASONS
                            else ("Nadie" if code in NON_IMPUTABLE_REASONS else "Técnico")
                        ),
                    }
                    for code in sorted(NON_COMPLIANCE_REASON_LABELS.keys())
                ],
                "special_reasons": [
                    {
                        "code": "vencido",
                        "label": NON_COMPLIANCE_REASON_LABELS.get("vencido", "vencido"),
                        "only_items": ["extintor", "seguro_vehicular", "oblea_gnc", "rto", "botiquin"],
                    },
                    {
                        "code": "no_apta_para_el_uso",
                        "label": NON_COMPLIANCE_REASON_LABELS.get("no_apta_para_el_uso", "no_apta_para_el_uso"),
                        "only_items": ["carga_segura", "escalera_aluminio_extensible", "escalera_fibra_tijera_doble"],
                    },
                ],
                "photo_rules": {
                    "optional_reasons": ["olvido", "perdida", "robo", "no_asignado"],
                    "optional_items": ["extintor", "seguro_vehicular", "oblea_gnc", "rto", "botiquin"],
                },
                "critical_rules": {
                    "critical_statuses": ["no_cumple", "nc_mayor"],
                    "note": "Una auditoría puede quedar Crítica si un ítem crítico falla con estado imputable.",
                },
            },
            today=datetime.today().strftime("%Y-%m-%d"),
        )
    )
    response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "0"
    return response


def _require_admin_and_csrf():
    if not is_admin():
        abort(403)
    if request.method == "POST":
        token = request.form.get("csrf_token") or request.headers.get("X-CSRF-Token")
        if not validate_csrf_token(token):
            abort(400)


def _parse_page_and_size(page_raw, size_raw, default_size=20, max_size=200):
    try:
        page = max(1, int(page_raw)) if page_raw else 1
    except (TypeError, ValueError):
        page = 1
    try:
        page_size = max(1, min(max_size, int(size_raw))) if size_raw else default_size
    except (TypeError, ValueError):
        page_size = default_size
    return page, page_size


def _pages_window(page, page_count):
    if page_count <= 9:
        return list(range(1, page_count + 1))
    window = [1]
    if page - 2 > 2:
        window.append(None)
    start = max(2, page - 2)
    end = min(page_count - 1, page + 2)
    for p in range(start, end + 1):
        window.append(p)
    if page + 2 < page_count - 1:
        window.append(None)
    window.append(page_count)
    return window


def _normalize_bool(val):
    if val is None:
        return False
    if isinstance(val, bool):
        return val
    try:
        ival = int(val)
        return ival != 0
    except (TypeError, ValueError):
        pass
    s = str(val).strip().lower()
    return s in {"1", "true", "yes", "s", "si", "activo", "active"}


@main.route("/master")
def master_index():
    if not is_admin():
        abort(403)
    stats = {
        "supervisors_total": count_supervisors(),
        "supervisors_active": count_supervisors(is_active=True),
        "supervisors_inactive": count_supervisors(is_active=False),
        "vehicles_total": count_vehicles(),
        "vehicles_active": count_vehicles(status="activo"),
        "vehicles_assigned": count_vehicles(assigned="yes"),
        "technicians_total": count_master_technicians(),
        "technicians_active": count_master_technicians(is_active=1),
        "technicians_inactive": count_master_technicians(is_active=0),
    }
    return render_template(
        "master/index.html",
        active_tab="home",
        stats=stats,
        page_class="page-wide",
    )


@main.route("/master/supervisors")
def master_supervisor_list():
    if not is_admin():
        abort(403)
    q = request.args.get("q", "").strip()
    is_active_raw = request.args.get("is_active", "").strip()
    sort_by = request.args.get("sort_by", "").strip()
    sort_dir = request.args.get("sort_dir", "").strip()
    page_raw = request.args.get("page", "")
    page_size_raw = request.args.get("page_size", "")
    is_active_filter = None
    if is_active_raw == "1":
        is_active_filter = True
    elif is_active_raw == "0":
        is_active_filter = False
    page, page_size = _parse_page_and_size(page_raw, page_size_raw)
    total = count_supervisors(q=q, is_active=is_active_filter)
    page_count = max(1, (total + page_size - 1) // page_size) if total else 1
    if page > page_count:
        page = page_count
    offset = (page - 1) * page_size
    rows = fetch_supervisors(q=q, is_active=is_active_filter, limit=page_size, offset=offset)
    return render_template(
        "master/supervisor_list.html",
        active_tab="supervisors",
        rows=rows,
        total=total,
        page=page,
        page_count=page_count,
        page_size=page_size,
        pages_window=_pages_window(page, page_count),
        has_prev_page=page > 1,
        has_next_page=(offset + page_size) < total,
        q=q,
        is_active=is_active_raw,
        sort_by=sort_by,
        sort_dir=sort_dir,
        page_class="page-wide",
    )


@main.route("/master/supervisors/new", methods=["GET", "POST"])
def master_supervisor_new():
    _require_admin_and_csrf()
    if request.method == "POST":
        try:
            name = (request.form.get("name") or "").strip()
            region = (request.form.get("region") or "").strip()
            phone = (request.form.get("phone") or "").strip()
            email = (request.form.get("email") or "").strip()
            is_active = (request.form.get("is_active") or "1").strip() == "1"
            create_supervisor(name=name, region=region, phone=phone, email=email, is_active=1 if is_active else 0)
            flash("Supervisor creado.", "success")
            return redirect(url_for("main.master_supervisor_list"))
        except ValueError as exc:
            flash(str(exc), "error")
    return render_template(
        "master/supervisor_form.html",
        active_tab="supervisors",
        mode="new",
        row=None,
    )


@main.route("/master/supervisors/<int:supervisor_id>/edit", methods=["GET", "POST"])
def master_supervisor_edit(supervisor_id):
    _require_admin_and_csrf()
    row = fetch_supervisor_by_id(supervisor_id)
    if not row:
        abort(404)
    if request.method == "POST":
        try:
            name = (request.form.get("name") or "").strip()
            region = (request.form.get("region") or "").strip()
            phone = (request.form.get("phone") or "").strip()
            email = (request.form.get("email") or "").strip()
            is_active_raw = (request.form.get("is_active") or "").strip()
            do_rename = (request.form.get("skip_rename") or "").strip() != "1"
            include_inactive = (request.form.get("include_inactive_technicians") or "").strip() == "1"
            is_active = None
            if is_active_raw == "1":
                is_active = True
            elif is_active_raw == "0":
                is_active = False
            update_supervisor(
                supervisor_id,
                name=name,
                region=region,
                phone=phone,
                email=email,
                is_active=is_active,
                rename_technicians=do_rename,
                only_active_technicians=(not include_inactive),
            )
            flash("Supervisor actualizado.", "success")
            return redirect(url_for("main.master_supervisor_list"))
        except ValueError as exc:
            flash(str(exc), "error")
    return render_template(
        "master/supervisor_form.html",
        active_tab="supervisors",
        mode="edit",
        row=row,
    )


@main.route("/master/supervisors/<int:supervisor_id>/toggle", methods=["POST"])
def master_supervisor_toggle(supervisor_id):
    _require_admin_and_csrf()
    result = toggle_supervisor_active(supervisor_id)
    if not result:
        abort(404)
    state = "activado" if _normalize_bool(result.get("is_active")) else "desactivado"
    flash(f"Supervisor {state}.", "success")
    return redirect(request.referrer or url_for("main.master_supervisor_list"))


@main.route("/master/vehicles")
def master_vehicle_list():
    if not is_admin():
        abort(403)
    q = request.args.get("q", "").strip()
    status = request.args.get("status", "").strip()
    assigned = request.args.get("assigned", "").strip()
    sort_by = request.args.get("sort_by", "").strip()
    sort_dir = request.args.get("sort_dir", "").strip()
    page_raw = request.args.get("page", "")
    page_size_raw = request.args.get("page_size", "")
    page, page_size = _parse_page_and_size(page_raw, page_size_raw)
    total = count_vehicles(q=q, status=status, assigned=assigned)
    page_count = max(1, (total + page_size - 1) // page_size) if total else 1
    if page > page_count:
        page = page_count
    offset = (page - 1) * page_size
    rows = fetch_vehicles(q=q, status=status, assigned=assigned, limit=page_size, offset=offset, sort_by=sort_by, sort_dir=sort_dir)
    return render_template(
        "master/vehicle_list.html",
        active_tab="vehicles",
        rows=rows,
        total=total,
        page=page,
        page_count=page_count,
        page_size=page_size,
        pages_window=_pages_window(page, page_count),
        has_prev_page=page > 1,
        has_next_page=(offset + page_size) < total,
        q=q,
        status=status,
        assigned=assigned,
        sort_by=sort_by,
        sort_dir=sort_dir,
        technicians_options=fetch_technicians(),
        page_class="page-wide",
    )


@main.route("/master/vehicles/new", methods=["GET", "POST"])
def master_vehicle_new():
    _require_admin_and_csrf()
    if request.method == "POST":
        try:
            combined = (request.form.get("combined_unit_plate") or "").strip()
            unit_field = (request.form.get("unit_number") or "").strip()
            plate_field = (request.form.get("plate") or "").strip()
            parsed_unit, parsed_plate = parse_unit_plate(combined)
            final_unit = unit_field or parsed_unit
            final_plate = plate_field or parsed_plate
            brand = (request.form.get("brand") or "").strip()
            model = (request.form.get("model") or "").strip()
            year = (request.form.get("year") or "").strip()
            status = (request.form.get("status") or "activo").strip()
            odometer = (request.form.get("odometer_km") or "").strip()
            assigned = (request.form.get("assigned_employee_code") or "").strip()
            review = (request.form.get("review_date") or "").strip()
            ins = (request.form.get("insurance_expiry") or "").strip()
            ext = (request.form.get("extinguisher_expiry") or "").strip()
            gnc = (request.form.get("gnc_expiry") or "").strip()
            rto = (request.form.get("rto_expiry") or "").strip()
            bot = (request.form.get("botiquin_expiry") or "").strip()
            create_vehicle(
                plate=final_plate, brand=brand, model=model, year=year, status=status,
                unit_number=final_unit, odometer_km=odometer, assigned_employee_code=assigned,
                review_date=review, insurance_expiry=ins, extinguisher_expiry=ext,
                gnc_expiry=gnc, rto_expiry=rto, botiquin_expiry=bot,
            )
            flash("Vehículo creado.", "success")
            return redirect(url_for("main.master_vehicle_list"))
        except ValueError as exc:
            flash(str(exc), "error")
    return render_template(
        "master/vehicle_form.html",
        active_tab="vehicles",
        mode="new",
        row=None,
        technicians_options=fetch_technicians(),
    )


@main.route("/master/vehicles/<int:vehicle_id>/edit", methods=["GET", "POST"])
def master_vehicle_edit(vehicle_id):
    _require_admin_and_csrf()
    row = fetch_vehicle_by_id(vehicle_id)
    if not row:
        abort(404)
    if request.method == "POST":
        try:
            combined = (request.form.get("combined_unit_plate") or "").strip()
            unit_field = (request.form.get("unit_number") or "").strip()
            plate_field = (request.form.get("plate") or "").strip()
            parsed_unit, parsed_plate = parse_unit_plate(combined)
            final_unit = unit_field or parsed_unit
            final_plate = plate_field or parsed_plate
            brand = (request.form.get("brand") or "").strip()
            model = (request.form.get("model") or "").strip()
            year = (request.form.get("year") or "").strip()
            status = (request.form.get("status") or "").strip()
            odometer = (request.form.get("odometer_km") or "").strip()
            assigned = (request.form.get("assigned_employee_code") or "").strip()
            review = (request.form.get("review_date") or "").strip()
            ins = (request.form.get("insurance_expiry") or "").strip()
            ext = (request.form.get("extinguisher_expiry") or "").strip()
            gnc = (request.form.get("gnc_expiry") or "").strip()
            rto = (request.form.get("rto_expiry") or "").strip()
            bot = (request.form.get("botiquin_expiry") or "").strip()
            update_vehicle(
                vehicle_id,
                plate=final_plate if (final_plate or plate_field) else None,
                brand=brand if brand else None,
                model=model if model else None,
                year=year if year else None,
                status=status if status else None,
                unit_number=final_unit if (final_unit or unit_field) else None,
                odometer_km=odometer if odometer else None,
                assigned_employee_code=assigned if assigned != "" else None,
                review_date=review if review else None,
                insurance_expiry=ins if ins else None,
                extinguisher_expiry=ext if ext else None,
                gnc_expiry=gnc if gnc else None,
                rto_expiry=rto if rto else None,
                botiquin_expiry=bot if bot else None,
            )
            if assigned != "":
                assign_vehicle_to_technician(vehicle_id, assigned)
            else:
                assign_vehicle_to_technician(vehicle_id, None)
            flash("Vehículo actualizado.", "success")
            return redirect(url_for("main.master_vehicle_list"))
        except ValueError as exc:
            flash(str(exc), "error")
    return render_template(
        "master/vehicle_form.html",
        active_tab="vehicles",
        mode="edit",
        row=row,
        technicians_options=fetch_technicians(),
    )


@main.route("/master/vehicles/<int:vehicle_id>/toggle", methods=["POST"])
def master_vehicle_toggle(vehicle_id):
    _require_admin_and_csrf()
    result = toggle_vehicle_active(vehicle_id)
    if not result:
        abort(404)
    state = "activado" if (result.get("status") or "").lower() == "activo" else "desactivado"
    flash(f"Vehículo {state}.", "success")
    return redirect(request.referrer or url_for("main.master_vehicle_list"))


@main.route("/master/vehicles/<int:vehicle_id>/assign", methods=["POST"])
def master_vehicle_assign(vehicle_id):
    _require_admin_and_csrf()
    code = (request.form.get("assigned_employee_code") or "").strip() or None
    result = assign_vehicle_to_technician(vehicle_id, code)
    if not result:
        abort(404)
    flash("Asignación actualizada.", "success")
    return redirect(request.referrer or url_for("main.master_vehicle_list"))


@main.route("/master/technicians")
def master_technician_list():
    if not is_admin():
        abort(403)
    q = request.args.get("q", "").strip()
    region = request.args.get("region", "").strip()
    supervisor = request.args.get("supervisor", "").strip()
    center = request.args.get("center", "").strip()
    company = request.args.get("company", "").strip()
    is_active = request.args.get("is_active", "").strip()
    sort_by = request.args.get("sort_by", "").strip()
    sort_dir = request.args.get("sort_dir", "").strip()
    page_raw = request.args.get("page", "")
    page_size_raw = request.args.get("page_size", "")
    page, page_size = _parse_page_and_size(page_raw, page_size_raw)
    total = count_master_technicians(q=q, region=region, supervisor=supervisor, center=center, company=company, is_active=is_active if is_active != "" else None)
    page_count = max(1, (total + page_size - 1) // page_size) if total else 1
    if page > page_count:
        page = page_count
    offset = (page - 1) * page_size
    rows = fetch_master_technicians(
        q=q, region=region, supervisor=supervisor, center=center, company=company,
        is_active=is_active if is_active != "" else None,
        limit=page_size, offset=offset, sort_by=sort_by, sort_dir=sort_dir,
    )
    filter_options = {
        "regions": fetch_distinct_regions(),
        "supervisors": fetch_distinct_supervisors(),
        "centers": fetch_distinct_centers(),
        "companies": fetch_distinct_companies(),
    }
    return render_template(
        "master/technician_list.html",
        active_tab="technicians",
        rows=rows,
        total=total,
        page=page,
        page_count=page_count,
        page_size=page_size,
        pages_window=_pages_window(page, page_count),
        has_prev_page=page > 1,
        has_next_page=(offset + page_size) < total,
        q=q,
        region=region,
        supervisor=supervisor,
        center=center,
        company=company,
        is_active=is_active,
        sort_by=sort_by,
        sort_dir=sort_dir,
        filter_options=filter_options,
        page_class="page-wide",
    )


@main.route("/master/technicians/new", methods=["GET", "POST"])
def master_technician_new():
    _require_admin_and_csrf()
    if request.method == "POST":
        try:
            employee_code = (request.form.get("employee_code") or "").strip()
            name = (request.form.get("name") or "").strip()
            region = (request.form.get("region") or "").strip()
            phone = (request.form.get("phone") or "").strip()
            commune = (request.form.get("commune") or "").strip()
            team = (request.form.get("team") or "").strip()
            company_name = (request.form.get("company_name") or "").strip()
            union_name = (request.form.get("union_name") or "").strip()
            supervisor_id_raw = (request.form.get("supervisor_id") or "").strip()
            supervisor_name = (request.form.get("supervisor_name") or "").strip()
            center_name = (request.form.get("center_name") or "").strip()
            is_active = (request.form.get("is_active") or "1").strip() == "1"
            assigned_vehicle_id = (request.form.get("vehicle_id") or "").strip()
            supervisor_id = int(supervisor_id_raw) if supervisor_id_raw else None
            technician_id = create_technician(
                employee_code=employee_code, name=name, region=region,
                phone=phone, commune=commune, team=team,
                company_name=company_name, union_name=union_name,
                supervisor_name=supervisor_name, supervisor_id=supervisor_id,
                center_name=center_name, is_active=is_active,
            )
            if assigned_vehicle_id:
                try:
                    assign_vehicle_to_technician(int(assigned_vehicle_id), employee_code)
                except Exception:
                    pass
            flash(f"Técnico {employee_code} creado.", "success")
            return redirect(url_for("main.master_technician_list"))
        except ValueError as exc:
            flash(str(exc), "error")
    vehicles_options = fetch_vehicles(status="activo", assigned="no", limit=500)
    return render_template(
        "master/technician_form.html",
        active_tab="technicians",
        mode="new",
        row=None,
        supervisors_options=fetch_active_supervisors(),
        filter_options={
            "regions": fetch_distinct_regions(),
            "centers": fetch_distinct_centers(),
            "companies": fetch_distinct_companies(),
        },
        vehicles_options=vehicles_options,
    )


@main.route("/master/technicians/<int:technician_id>/edit", methods=["GET", "POST"])
def master_technician_edit(technician_id):
    _require_admin_and_csrf()
    row = fetch_technician_by_id(technician_id)
    if not row:
        abort(404)
    if request.method == "POST":
        try:
            employee_code = (request.form.get("employee_code") or "").strip()
            name = (request.form.get("name") or "").strip()
            region = (request.form.get("region") or "").strip()
            phone = (request.form.get("phone") or "").strip()
            commune = (request.form.get("commune") or "").strip()
            team = (request.form.get("team") or "").strip()
            company_name = (request.form.get("company_name") or "").strip()
            union_name = (request.form.get("union_name") or "").strip()
            supervisor_id_raw = (request.form.get("supervisor_id") or "").strip()
            supervisor_name = (request.form.get("supervisor_name") or "").strip()
            center_name = (request.form.get("center_name") or "").strip()
            is_active_raw = (request.form.get("is_active") or "").strip()
            assigned_vehicle_id = (request.form.get("vehicle_id") or "").strip()
            clear_vehicle = (request.form.get("clear_vehicle") or "").strip() == "1"
            supervisor_id = int(supervisor_id_raw) if supervisor_id_raw else None
            is_active = None
            if is_active_raw == "1":
                is_active = True
            elif is_active_raw == "0":
                is_active = False
            update_technician(
                technician_id,
                employee_code=employee_code if employee_code else None,
                name=name if name else None,
                region=region if region else None,
                phone=phone if phone else None,
                commune=commune if commune else None,
                team=team if team else None,
                company_name=company_name if company_name else None,
                union_name=union_name if union_name else None,
                supervisor_name=supervisor_name if supervisor_name else None,
                supervisor_id=supervisor_id,
                center_name=center_name if center_name else None,
                is_active=is_active,
            )
            new_code = employee_code or row.get("employee_code")
            if assigned_vehicle_id:
                try:
                    assign_vehicle_to_technician(int(assigned_vehicle_id), new_code)
                except Exception:
                    pass
            elif clear_vehicle:
                try:
                    current_vehicles = fetch_vehicles_by_employee_code(new_code) or []
                    for v in current_vehicles:
                        assign_vehicle_to_technician(v["id"], None)
                except Exception:
                    pass
            flash("Técnico actualizado.", "success")
            return redirect(url_for("main.master_technician_list"))
        except ValueError as exc:
            flash(str(exc), "error")
    vehicles_options = fetch_vehicles(limit=500)
    return render_template(
        "master/technician_form.html",
        active_tab="technicians",
        mode="edit",
        row=row,
        supervisors_options=fetch_active_supervisors(),
        filter_options={
            "regions": fetch_distinct_regions(),
            "centers": fetch_distinct_centers(),
            "companies": fetch_distinct_companies(),
        },
        vehicles_options=vehicles_options,
    )


@main.route("/master/technicians/<int:technician_id>/toggle", methods=["POST"])
def master_technician_toggle(technician_id):
    _require_admin_and_csrf()
    result = toggle_technician_active(technician_id)
    if not result:
        abort(404)
    state = "activado" if _normalize_bool(result.get("is_active")) else "desactivado"
    flash(f"Técnico {state}.", "success")
    return redirect(request.referrer or url_for("main.master_technician_list"))
