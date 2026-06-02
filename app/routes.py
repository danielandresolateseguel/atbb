import base64
import binascii
import io
from pathlib import Path
from uuid import uuid4
from datetime import datetime

from flask import Blueprint, abort, current_app, flash, g, jsonify, make_response, redirect, render_template, request, session, url_for
from werkzeug.security import check_password_hash
from werkzeug.utils import secure_filename

try:
    from PIL import Image, ImageOps
except ImportError:
    Image = None
    ImageOps = None

from app.checklist import CHECKLIST_SECTIONS
from app.models import (
    count_active_admins,
    count_users,
    create_audit,
    create_user,
    create_tnps_response,
    update_user,
    fetch_user_by_id,
    fetch_user_by_username,
    fetch_users,
    fetch_audit_detail,
    fetch_audit_items,
    fetch_audit_supply_requests,
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
    fetch_tnps_responses,
    fetch_tnps_response_for_audit,
    fetch_tnps_stats,
    fetch_material_by_code,
    fetch_material_catalog,
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
    update_vehicle_extinguisher_expiry,
    update_vehicle_insurance_expiry,
    update_vehicle_gnc_expiry,
    update_vehicle_rto_expiry,
    update_vehicle_botiquin_expiry,
)
from app.spreadsheets import parse_tabular_upload


main = Blueprint("main", __name__)


def current_user():
    if getattr(g, "_current_user_loaded", False):
        return getattr(g, "current_user", None)

    user_id = session.get("user_id")
    if not user_id:
        g._current_user_loaded = True
        g.current_user = None
        return None

    user = fetch_user_by_id(user_id)
    if not user or not user.get("is_active"):
        session.pop("user_id", None)
        g._current_user_loaded = True
        g.current_user = None
        return None

    if user.get("role") == "supervisor":
        update_user(user["id"], role="admin")
        user["role"] = "admin"

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


def can_import():
    user = current_user()
    return bool(user and (user.get("role") in {"admin", "auditor"}))


def can_create_audit():
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
    return {
        "current_user": user,
        "is_admin": bool(user and (user.get("role") == "admin")),
        "is_gerente": bool(user and (user.get("role") == "gerente")),
        "is_auditor": bool(user and (user.get("role") == "auditor")),
        "can_import": can_import(),
        "can_create_audit": can_create_audit(),
        "can_view_all_audits": can_view_all_audits(),
        "can_view_users": can_view_users(),
        "can_create_users": can_create_users(),
        "can_edit_users": can_edit_users(),
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
        username = (request.form.get("username") or "").strip()
        password = (request.form.get("password") or "").strip()
        next_url = safe_next_url(request.form.get("next")) or next_url

        user = fetch_user_by_username(username)
        if not user or not user.get("is_active"):
            flash("Usuario o contraseña incorrectos.", "error")
            return render_template("login.html", next=next_url)

        if not check_password_hash(user["password_hash"], password):
            flash("Usuario o contraseña incorrectos.", "error")
            return render_template("login.html", next=next_url)

        session.clear()
        session["user_id"] = user["id"]
        return redirect(next_url or url_for("main.dashboard"))

    return render_template("login.html", next=next_url)


@main.route("/logout")
def logout():
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
                if role not in {"admin", "auditor", "gerente"}:
                    raise ValueError("El rol seleccionado no es válido.")

            create_user(username=username, password=password, role=role, is_active=1 if is_active else 0)
            flash("Usuario creado.", "success")
            if actor and actor.get("role") == "gerente":
                return redirect(url_for("main.users_new"))
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
            if user.get("role") != "admin" and projected_role not in {"auditor", "gerente"}:
                raise ValueError("El rol seleccionado no es válido.")

            update_user(user_id, username=username, password=password, role=role, is_active=is_active)
            flash("Usuario actualizado.", "success")
            return redirect(url_for("main.users_list"))
        except ValueError as exc:
            flash(str(exc), "error")

    return render_template("user_form.html", mode="edit", user=user)


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
    score_sum = 0.0
    has_critical_failure = False
    serialized_items = []

    photo_optional_reasons = {"olvido", "perdida"}
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
        non_compliance_reason = form_data.get(f"reason__{item['key']}", "").strip()
        notes = form_data.get(f"notes__{item['key']}", "").strip()
        file_photo = files.get(f"photo__{item['key']}")
        camera_photo = files.get(f"photo_camera__{item['key']}")
        if has_uploaded_file(file_photo):
            photo_file = file_photo
        elif has_uploaded_file(camera_photo):
            photo_file = camera_photo
        else:
            photo_file = None
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

        requires_photo = (
            evidence_required
            and status == "no_cumple"
            and non_compliance_reason not in photo_optional_reasons
        )
        if requires_photo and not has_uploaded_file(photo_file):
            raise ValueError(f"Debes adjuntar evidencia fotografica en: {item['label']}")

        if status != "no_aplica":
            valid_items += 1
            score_sum += status_scores.get(status, 0.0)

        if status in critical_failure_statuses and item["critical"]:
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
            }
        )

    compliance_ratio = 1 if valid_items == 0 else score_sum / valid_items
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

    snapshot_status_scores = {"ok": 1.0, "missing": 0.0, "not_checked": 0.5}
    serialized_weight = 5
    material_weight = 5
    serialized_stock_status = (form_data.get("serialized_stock_status") or "").strip()
    material_stock_status = (form_data.get("material_stock_status") or "").strip()
    total_score += serialized_weight * snapshot_status_scores.get(serialized_stock_status, 0.0)
    total_score += material_weight * snapshot_status_scores.get(material_stock_status, 0.0)

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


def cloudinary_enabled():
    raw = (current_app.config.get("CLOUDINARY_URL") or "").strip()
    return raw.startswith("cloudinary://")


def optimize_photo_bytes(content_bytes, extension, max_dim=1600):
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
        photo_file = item.pop("photo_file", None)
        if not photo_file:
            item["photo_path"] = None
            continue

        filename, extension = validate_photo_file(photo_file, item["item_label"])
        safe_stem = secure_filename(item["item_key"]) or "evidencia"
        generated_name = f"{datetime.utcnow().strftime('%Y%m%d%H%M%S')}_{safe_stem}_{uuid4().hex[:8]}"

        raw_bytes = photo_file.stream.read()
        if not raw_bytes:
            raise ValueError(f"La evidencia de {item['item_label']} no contiene datos validos.")

        optimized_bytes, optimized_extension = optimize_photo_bytes(raw_bytes, extension, max_dim=1600)
        if cloudinary_enabled():
            base_folder = (current_app.config.get("CLOUDINARY_FOLDER") or "atbb").strip().strip("/")
            folder = f"{base_folder}/audits/{date_folder}"
            uploaded_url = upload_image_to_cloudinary(optimized_bytes, folder=folder, public_id=generated_name)
            item["photo_path"] = uploaded_url
        else:
            generated_filename = f"{generated_name}.{optimized_extension}"
            saved_path = target_dir / generated_filename
            saved_path.write_bytes(optimized_bytes)
            item["photo_path"] = f"uploads/audits/{date_folder}/{generated_filename}".replace("\\", "/")


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
    generated_name = f"{datetime.utcnow().strftime('%Y%m%d%H%M%S')}_firma_auditor_{uuid4().hex[:8]}"
    if cloudinary_enabled():
        optimized_signature = optimize_signature_png_bytes(decoded_signature)
        base_folder = (current_app.config.get("CLOUDINARY_FOLDER") or "atbb").strip().strip("/")
        folder = f"{base_folder}/audits/signatures/{date_folder}"
        return upload_image_to_cloudinary(optimized_signature, folder=folder, public_id=generated_name)

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

    date_folder = datetime.fromisoformat(audit_date).strftime("%Y/%m")
    generated_name = f"{datetime.utcnow().strftime('%Y%m%d%H%M%S')}_firma_tecnico_{uuid4().hex[:8]}"
    if cloudinary_enabled():
        optimized_signature = optimize_signature_png_bytes(decoded_signature)
        base_folder = (current_app.config.get("CLOUDINARY_FOLDER") or "atbb").strip().strip("/")
        folder = f"{base_folder}/audits/signatures/{date_folder}"
        return upload_image_to_cloudinary(optimized_signature, folder=folder, public_id=generated_name)

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

    compliant_count = sum(1 for item in items if item["status"] in compliant_statuses)
    non_compliant_count = sum(1 for item in items if item["status"] in non_compliant_statuses)
    not_applicable_count = sum(1 for item in items if item["status"] == "no_aplica")
    applicable_count = compliant_count + non_compliant_count
    evidence_count = sum(1 for item in items if item.get("photo_path"))
    critical_findings = [
        item for item in items if item["status"] in non_compliant_statuses and item["is_critical"]
    ]
    findings = [item for item in items if item["status"] in non_compliant_statuses]

    compliance_rate = 0 if applicable_count == 0 else round((compliant_count / applicable_count) * 100)
    evidence_required_count = sum(1 for item in items if item["status"] == "no_cumple")
    evidence_with_photo_count = sum(
        1 for item in items if item["status"] == "no_cumple" and item.get("photo_path")
    )
    evidence_rate = (
        0
        if evidence_required_count == 0
        else round((evidence_with_photo_count / evidence_required_count) * 100)
    )

    sections = []
    grouped_items = build_grouped_audit_items(items)
    for section_title, section_items in grouped_items.items():
        section_compliant = sum(1 for item in section_items if item["status"] in compliant_statuses)
        section_non_compliant = sum(1 for item in section_items if item["status"] in non_compliant_statuses)
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
                    if item["status"] in non_compliant_statuses and item["is_critical"]
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
    user = current_user()
    auditor_user_id = user["id"] if user and user.get("role") == "auditor" else None
    recent_audits = fetch_recent_audits(auditor_user_id=auditor_user_id)
    stats = fetch_dashboard_stats(auditor_user_id=auditor_user_id)

    return render_template(
        "dashboard.html",
        recent_audits=recent_audits,
        total_audits=stats["total_audits"],
        approval_rate=stats["approval_rate"],
        critical_count=stats["critical_count"],
    )


@main.route("/tnps", methods=["GET", "POST"])
def tnps():
    if request.method == "POST" and not can_import():
        abort(403)

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
    }

    technician_id = None
    if filters["technician_id"]:
        try:
            technician_id = int(filters["technician_id"])
        except ValueError:
            flash("El tecnico seleccionado no es valido.", "error")
            filters["technician_id"] = ""

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

            locked_technician_id = None
            if audit_id is not None:
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
                comment=(request.form.get("comment") or "").strip(),
                customer_name=(request.form.get("customer_name") or "").strip(),
                technician_id=locked_technician_id,
                audit_id=audit_id,
            )
            flash("Respuesta tNPS registrada.", "success")
            if audit_id is not None:
                return redirect(url_for("main.audit_report", audit_id=audit_id))
            return redirect(url_for("main.tnps"))
        except (KeyError, ValueError) as exc:
            flash(str(exc), "error")

    technicians = fetch_technicians()
    stats = fetch_tnps_stats(query_filters)
    responses = fetch_tnps_responses(query_filters)

    return render_template(
        "tnps.html",
        filters=filters,
        technicians=technicians,
        stats=stats,
        responses=responses,
        audit_context=audit_context,
        today=datetime.now().date().isoformat(),
        page_class="page-wide",
    )


@main.route("/audits")
def audit_list():
    user = current_user()
    auditor_user_id = user["id"] if user and user.get("role") == "auditor" else None
    filters = {
        "from_date": request.args.get("from_date", "").strip(),
        "to_date": request.args.get("to_date", "").strip(),
        "status": request.args.get("status", "").strip(),
        "auditor": request.args.get("auditor", "").strip(),
    }

    if auditor_user_id is not None:
        filters["auditor"] = ""

    audits = fetch_all_audits(filters, auditor_user_id=auditor_user_id)
    filter_active = any(
        [
            filters["from_date"],
            filters["to_date"],
            filters["status"],
            filters["auditor"],
        ]
    )
    return render_template(
        "audits.html",
        audits=audits,
        filters=filters,
        filter_active=filter_active,
    )


@main.route("/audits/<int:audit_id>")
def audit_detail(audit_id):
    audit = fetch_audit_detail(audit_id)
    if not audit:
        abort(404)
    if is_auditor():
        user = current_user()
        if audit.get("auditor_user_id") != user["id"] and (audit.get("auditor_name") or "") != user["username"]:
            abort(404)

    items = fetch_audit_items(audit_id)
    grouped_items = build_grouped_audit_items(items)
    supply_requests = fetch_audit_supply_requests(audit_id)
    tnps_response = fetch_tnps_response_for_audit(audit_id)

    return render_template(
        "audit_detail.html",
        audit=audit,
        grouped_items=grouped_items,
        supply_requests=supply_requests,
        tnps_response=tnps_response,
    )


@main.route("/audits/<int:audit_id>/report")
def audit_report(audit_id):
    audit = fetch_audit_detail(audit_id)
    if not audit:
        abort(404)
    if is_auditor():
        user = current_user()
        if audit.get("auditor_user_id") != user["id"] and (audit.get("auditor_name") or "") != user["username"]:
            abort(404)

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
    return render_template(
        "audit_report.html",
        audit=audit,
        grouped_items=grouped_items_detail if detail_filter_active else grouped_items_all,
        report=report,
        tnps_response=tnps_response,
        supply_requests=supply_requests,
        print_mode=request.args.get("print") == "1",
        detail_filter_active=detail_filter_active,
        detail_filter=detail_filter,
    )


@main.route("/imports", methods=["GET", "POST"])
def imports():
    if not can_import():
        abort(403)
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
            selected_mobile = fetch_mobile_unit_by_id(mobile_unit_id)
            if not selected_mobile:
                raise ValueError("Debes seleccionar un movil tecnico valido.")

            technician_display_name = (
                selected_mobile.get("technician_name")
                or selected_mobile.get("user_name")
                or None
            )
            technician_employee_code = selected_mobile.get("employee_code") or None

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

            serialized_stock_notes = (request.form.get("serialized_stock_notes") or "").strip() or None
            if serialized_stock_status == "missing" and not serialized_stock_notes:
                raise ValueError("Si faltan serializados, debes detallar los faltantes.")

            material_stock_status = (request.form.get("material_stock_status") or "").strip()
            if not material_stock_status:
                raise ValueError(
                    "Debes indicar el estado del stock (Completo, Faltan o No revisado)."
                )
            if material_stock_status not in {"ok", "missing", "not_checked"}:
                raise ValueError("El estado del stock no es valido.")

            material_stock_notes = (request.form.get("material_stock_notes") or "").strip() or None
            if material_stock_status == "missing" and not material_stock_notes:
                raise ValueError("Si faltan materiales en stock, debes detallar los faltantes.")

            supply_requests = []
            indices = []
            for key in request.form.keys():
                if key.startswith("supply_request_type__"):
                    try:
                        indices.append(int(key.split("__", 1)[1]))
                    except (IndexError, ValueError):
                        continue

            if indices:
                if not material_index:
                    raise ValueError(
                        "No hay materiales importados para validar codigos. Importa Stock de materiales primero."
                    )

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
                material = fetch_material_by_code(material_code)
                if not material:
                    raise ValueError(
                        f"El codigo {material_code} no existe en materiales importados."
                    )

                quantity_raw = (request.form.get(f"supply_request_qty__{index}") or "").strip()
                quantity = None
                if quantity_raw:
                    try:
                        quantity = int(quantity_raw)
                    except ValueError:
                        raise ValueError("La cantidad solicitada no es valida.")

                notes = (request.form.get(f"supply_request_notes__{index}") or "").strip() or None
                related_item_key = (request.form.get(f"supply_request_item__{index}") or "").strip()
                related_label = herramientas_item_map.get(related_item_key)

                supply_requests.append(
                    {
                        "section_key": "herramientas",
                        "section_title": herramientas_title,
                        "item_key": related_item_key or f"material_{material_code}",
                        "item_label": related_label or material["material_name"],
                        "request_type": request_type,
                        "material_code": material_code,
                        "quantity": quantity,
                        "notes": notes,
                    }
                )

            auditor_name = request.form["auditor_name"].strip()
            if user and user.get("role") == "auditor":
                auditor_name = user["username"]

            audit_id = create_audit(
                {
                    "audit_date": audit_date,
                    "auditor_name": auditor_name,
                    "auditor_user_id": auditor_user_id,
                    "auditor_signature_path": auditor_signature_path,
                    "technician_signature_path": technician_signature_path,
                    "technician_display_name": technician_display_name,
                    "technician_employee_code": technician_employee_code,
                    "location": request.form["location"].strip(),
                    "installation_type": request.form["installation_type"].strip(),
                    "mobile_unit_id": mobile_unit_id,
                    "technician_id": selected_mobile.get("technician_id"),
                    "vehicle_id": int(vehicle_id_raw),
                    "total_score": total_score,
                    "result_status": result_status,
                    "general_notes": request.form.get("general_notes", "").strip() or None,
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
            checklist_sections=CHECKLIST_SECTIONS,
            mobile_units=mobile_units,
            vehicles=vehicles,
            material_index=material_index,
            herramientas_section=herramientas_section,
            hand_tools=hand_tools,
            today=datetime.today().strftime("%Y-%m-%d"),
        )
    )
    response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "0"
    return response
