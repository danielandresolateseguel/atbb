import base64
import binascii
from pathlib import Path
from uuid import uuid4
from datetime import datetime

from flask import Blueprint, abort, current_app, flash, jsonify, redirect, render_template, request, url_for
from werkzeug.utils import secure_filename

from app.checklist import CHECKLIST_SECTIONS
from app.models import (
    create_audit,
    fetch_audit_detail,
    fetch_audit_items,
    fetch_all_audits,
    fetch_dashboard_stats,
    fetch_distinct_mobile_codes,
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
    fetch_mobile_unit_detail,
    fetch_vehicles_by_employee_code,
    fetch_materials_summary,
    fetch_material_stock_rows,
    fetch_recent_audits,
    fetch_stock_stats,
    fetch_storage_locations,
    fetch_storage_locations_summary,
    fetch_technicians,
    fetch_vehicles,
    fetch_mobile_units,
    import_checklist_del_dia,
    import_equipment_inventory,
    import_material_stock,
    import_novedades_diarias,
    import_storage_locations,
    import_technicians,
    import_vehicles,
    update_mobile_unit_technician,
)
from app.spreadsheets import parse_tabular_upload


main = Blueprint("main", __name__)


CSV_IMPORT_TYPES = {
    "technicians": {
        "label": "Tecnicos",
        "required_columns": ["employee_code", "name", "region"],
        "importer": import_technicians,
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
    compliant_items = 0
    has_critical_failure = False
    serialized_items = []

    for item in section["items"]:
        status = form_data.get(f"status__{item['key']}", "")
        notes = form_data.get(f"notes__{item['key']}", "").strip()
        photo_file = files.get(f"photo__{item['key']}")

        if not status:
            raise ValueError(f"Debes responder el item: {item['label']}")

        if status == "no_cumple" and not notes:
            raise ValueError(f"Debes agregar observacion en: {item['label']}")

        if status == "no_cumple" and not has_uploaded_file(photo_file):
            raise ValueError(f"Debes adjuntar evidencia fotografica en: {item['label']}")

        if status != "no_aplica":
            valid_items += 1
            if status == "cumple":
                compliant_items += 1

        if status == "no_cumple" and item["critical"]:
            has_critical_failure = True

        serialized_items.append(
            {
                "section_key": section["key"],
                "section_title": section["title"],
                "item_key": item["key"],
                "item_label": item["label"],
                "status": status,
                "is_critical": item["critical"],
                "notes": notes or None,
                "photo_file": photo_file if has_uploaded_file(photo_file) else None,
            }
        )

    compliance_ratio = 1 if valid_items == 0 else compliant_items / valid_items
    section_score = compliance_ratio * section["weight"]
    return section_score, has_critical_failure, serialized_items


def calculate_audit_result(form_data, files):
    total_score = 0
    has_critical_failure = False
    all_items = []

    for section in CHECKLIST_SECTIONS:
        section_score, section_failure, items = calculate_section_score(section, form_data, files)
        total_score += section_score
        has_critical_failure = has_critical_failure or section_failure
        all_items.extend(items)

    if has_critical_failure:
        result_status = "Critica"
    elif total_score >= 90:
        result_status = "Aprobada"
    elif total_score >= 75:
        result_status = "Aprobada con observaciones"
    else:
        result_status = "Rechazada"

    return round(total_score, 2), result_status, all_items


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


def persist_item_evidence(items, audit_date):
    date_folder = datetime.fromisoformat(audit_date).strftime("%Y/%m")
    target_dir = current_app.config["AUDIT_EVIDENCE_DIR"] / date_folder
    target_dir.mkdir(parents=True, exist_ok=True)

    for item in items:
        photo_file = item.pop("photo_file", None)
        if not photo_file:
            item["photo_path"] = None
            continue

        filename, extension = validate_photo_file(photo_file, item["item_label"])
        safe_stem = secure_filename(item["item_key"]) or "evidencia"
        generated_name = f"{datetime.utcnow().strftime('%Y%m%d%H%M%S')}_{safe_stem}_{uuid4().hex[:8]}.{extension}"
        saved_path = target_dir / generated_name
        photo_file.save(saved_path)
        item["photo_path"] = f"uploads/audits/{date_folder}/{generated_name}".replace("\\", "/")


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

    date_folder = datetime.fromisoformat(audit_date).strftime("%Y/%m")
    target_dir = current_app.config["AUDIT_EVIDENCE_DIR"] / "signatures" / date_folder
    target_dir.mkdir(parents=True, exist_ok=True)

    generated_name = f"{datetime.utcnow().strftime('%Y%m%d%H%M%S')}_firma_auditor_{uuid4().hex[:8]}.png"
    saved_path = target_dir / generated_name
    saved_path.write_bytes(decoded_signature)
    return f"uploads/audits/signatures/{date_folder}/{generated_name}".replace("\\", "/")


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

    date_folder = datetime.fromisoformat(audit_date).strftime("%Y/%m")
    target_dir = current_app.config["AUDIT_EVIDENCE_DIR"] / "signatures" / date_folder
    target_dir.mkdir(parents=True, exist_ok=True)

    generated_name = f"{datetime.utcnow().strftime('%Y%m%d%H%M%S')}_firma_tecnico_{uuid4().hex[:8]}.png"
    saved_path = target_dir / generated_name
    saved_path.write_bytes(decoded_signature)
    return f"uploads/audits/signatures/{date_folder}/{generated_name}".replace("\\", "/")


def build_grouped_audit_items(items):
    grouped_items = {}
    for item in items:
        grouped_items.setdefault(item["section_title"], []).append(item)
    return grouped_items


def build_audit_report_metrics(audit, items):
    total_items = len(items)
    compliant_count = sum(1 for item in items if item["status"] == "cumple")
    non_compliant_count = sum(1 for item in items if item["status"] == "no_cumple")
    not_applicable_count = sum(1 for item in items if item["status"] == "no_aplica")
    applicable_count = compliant_count + non_compliant_count
    evidence_count = sum(1 for item in items if item.get("photo_path"))
    critical_findings = [
        item for item in items if item["status"] == "no_cumple" and item["is_critical"]
    ]
    findings = [item for item in items if item["status"] == "no_cumple"]

    compliance_rate = 0 if applicable_count == 0 else round((compliant_count / applicable_count) * 100)
    evidence_rate = 0 if non_compliant_count == 0 else round((evidence_count / non_compliant_count) * 100)

    sections = []
    grouped_items = build_grouped_audit_items(items)
    for section_title, section_items in grouped_items.items():
        section_compliant = sum(1 for item in section_items if item["status"] == "cumple")
        section_non_compliant = sum(1 for item in section_items if item["status"] == "no_cumple")
        section_applicable = section_compliant + section_non_compliant
        section_score = 0 if section_applicable == 0 else round((section_compliant / section_applicable) * 100)
        sections.append(
            {
                "title": section_title,
                "score": section_score,
                "compliant_count": section_compliant,
                "non_compliant_count": section_non_compliant,
                "not_applicable_count": sum(1 for item in section_items if item["status"] == "no_aplica"),
                "critical_count": sum(
                    1
                    for item in section_items
                    if item["status"] == "no_cumple" and item["is_critical"]
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
            "not_applicable_count": not_applicable_count,
            "critical_findings_count": len(critical_findings),
            "findings_count": len(findings),
            "evidence_count": evidence_count,
            "compliance_rate": compliance_rate,
            "evidence_rate": evidence_rate,
        },
        "sections": sections,
        "critical_findings": critical_findings,
        "findings": findings,
        "evidence_items": [item for item in items if item.get("photo_path")],
        "score_ring": {
            "circumference": round(circumference, 2),
            "offset": ring_offset,
        },
    }


@main.route("/")
def dashboard():
    recent_audits = fetch_recent_audits()
    stats = fetch_dashboard_stats()

    return render_template(
        "dashboard.html",
        recent_audits=recent_audits,
        total_audits=stats["total_audits"],
        approval_rate=stats["approval_rate"],
        critical_count=stats["critical_count"],
    )


@main.route("/audits")
def audit_list():
    audits = fetch_all_audits()
    return render_template("audits.html", audits=audits)


@main.route("/audits/<int:audit_id>")
def audit_detail(audit_id):
    audit = fetch_audit_detail(audit_id)
    if not audit:
        abort(404)

    items = fetch_audit_items(audit_id)
    grouped_items = build_grouped_audit_items(items)

    return render_template(
        "audit_detail.html",
        audit=audit,
        grouped_items=grouped_items,
    )


@main.route("/audits/<int:audit_id>/report")
def audit_report(audit_id):
    audit = fetch_audit_detail(audit_id)
    if not audit:
        abort(404)

    items = fetch_audit_items(audit_id)
    report = build_audit_report_metrics(audit, items)
    return render_template(
        "audit_report.html",
        audit=audit,
        grouped_items=build_grouped_audit_items(items),
        report=report,
        print_mode=request.args.get("print") == "1",
    )


@main.route("/imports", methods=["GET", "POST"])
def imports():
    import_summary = None

    if request.method == "POST":
        import_type = request.form.get("import_type", "")
        import_config = CSV_IMPORT_TYPES.get(import_type)

        if not import_config:
            flash("Selecciona un tipo de importacion valido.", "error")
            return redirect(url_for("main.imports"))

        try:
            fieldnames, rows = parse_tabular_upload(request.files.get("csv_file"))
            validate_required_columns(fieldnames, import_config["required_columns"])
            import_summary = import_config["importer"](rows)

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
            flash(str(exc), "error")

    return render_template(
        "imports.html",
        import_types=CSV_IMPORT_TYPES,
        technicians_count=len(fetch_technicians()),
        vehicles_count=len(fetch_vehicles()),
        mobile_units_count=len(fetch_mobile_units()),
        stock_stats=fetch_stock_stats(),
        materials_summary=fetch_materials_summary(),
        storage_locations_summary=fetch_storage_locations_summary(),
        equipment_summary=fetch_equipment_summary(),
        import_summary=import_summary,
    )


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

    return render_template(
        "mobile_detail.html",
        mobile=mobile,
        overview=fetch_mobile_overview_stats(mobile_code),
        storage_locations=fetch_mobile_storage_locations(mobile_code),
        equipment_rows=fetch_mobile_equipment(mobile_code),
        stock_rows=fetch_mobile_material_stock(mobile_code),
        related_audits=fetch_mobile_related_audits(mobile_code),
        related_vehicles=fetch_vehicles_by_employee_code(mobile.get("employee_code")),
        technicians=fetch_technicians(),
    )


@main.route("/mobiles/<mobile_code>/technician", methods=["POST"])
def assign_mobile_technician(mobile_code):
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
    mobile_units = fetch_mobile_units()
    vehicles = fetch_vehicles()

    if request.method == "POST":
        try:
            mobile_unit_id_raw = request.form.get("mobile_unit_id", "").strip()
            if not mobile_unit_id_raw:
                raise ValueError("Debes seleccionar un movil tecnico.")

            mobile_unit_id = int(mobile_unit_id_raw)
            selected_mobile = fetch_mobile_unit_by_id(mobile_unit_id)
            if not selected_mobile:
                raise ValueError("Debes seleccionar un movil tecnico valido.")

            resolved_technician_id = selected_mobile["technician_id"]
            if resolved_technician_id is None:
                raise ValueError(
                    f"El movil tecnico {selected_mobile['mobile_code']} no tiene tecnico vinculado."
                )

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

            audit_id = create_audit(
                {
                    "audit_date": audit_date,
                    "auditor_name": request.form["auditor_name"].strip(),
                    "auditor_signature_path": auditor_signature_path,
                    "technician_signature_path": technician_signature_path,
                    "location": request.form["location"].strip(),
                    "installation_type": request.form["installation_type"].strip(),
                    "mobile_unit_id": mobile_unit_id,
                    "technician_id": resolved_technician_id,
                    "vehicle_id": int(vehicle_id_raw),
                    "total_score": total_score,
                    "result_status": result_status,
                    "general_notes": request.form.get("general_notes", "").strip() or None,
                },
                items,
            )
            flash("Auditoria guardada correctamente.", "success")
            return redirect(url_for("main.audit_detail", audit_id=audit_id))
        except ValueError as exc:
            flash(str(exc), "error")

    return render_template(
        "audit_form.html",
        checklist_sections=CHECKLIST_SECTIONS,
        mobile_units=mobile_units,
        vehicles=vehicles,
        today=datetime.today().strftime("%Y-%m-%d"),
    )
