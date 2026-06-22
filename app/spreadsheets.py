import csv
import io
import re
import unicodedata
import zipfile
import xml.etree.ElementTree as ET


XML_NAMESPACES = {
    "main": "http://schemas.openxmlformats.org/spreadsheetml/2006/main",
    "rel": "http://schemas.openxmlformats.org/package/2006/relationships",
}

COMMON_HEADER_KEYWORDS = {
    "employee_code",
    "codigo_empleado",
    "name",
    "nombre",
    "region",
    "phone",
    "telefono",
    "commune",
    "comuna",
    "team",
    "cuadrilla",
    "is_active",
    "activo",
    "plate",
    "patente",
    "dominio",
    "matricula",
    "brand",
    "marca",
    "model",
    "modelo",
    "year",
    "anio",
    "status",
    "estado",
    "assigned_employee_code",
    "odometer_km",
    "km",
    "kms",
    "kilometros",
    "kilometraje",
    "material",
    "codigo",
    "descripcion",
    "centro",
    "tipo_de_almacen",
    "almacen",
    "codigo_almacen",
    "codigo_material",
    "serial",
}


def parse_tabular_upload(uploaded_file):
    if not uploaded_file or not uploaded_file.filename:
        raise ValueError("Debes seleccionar un archivo para importar.")

    filename = uploaded_file.filename.lower()
    raw_content = uploaded_file.stream.read()
    if not raw_content:
        raise ValueError("El archivo seleccionado esta vacio.")

    if filename.endswith(".csv"):
        return parse_csv_bytes(raw_content)

    if filename.endswith(".xlsx"):
        return parse_xlsx_bytes(raw_content)

    if zipfile.is_zipfile(io.BytesIO(raw_content)):
        try:
            return parse_xlsx_bytes(raw_content)
        except Exception:
            pass

    try:
        return parse_csv_bytes(raw_content)
    except UnicodeDecodeError:
        pass

    raise ValueError(
        "Solo se permiten archivos .csv o .xlsx. "
        "Si tu archivo fue descargado con doble extension (por ejemplo .xlsx.xls), "
        "renombralo para que termine en .xlsx y vuelve a intentar."
    )


def parse_csv_bytes(raw_content):
    decoded_content = raw_content.decode("utf-8-sig")
    csv_stream = io.StringIO(decoded_content)
    sample = decoded_content[:2048]

    try:
        dialect = csv.Sniffer().sniff(sample, delimiters=",;")
    except csv.Error:
        dialect = csv.excel
        dialect.delimiter = ","

    reader = csv.DictReader(csv_stream, dialect=dialect)
    if not reader.fieldnames:
        raise ValueError("No se pudieron detectar las columnas del CSV.")

    normalized_fieldnames = [normalize_header(field) for field in reader.fieldnames if field]
    reader.fieldnames = normalized_fieldnames
    rows = [normalize_row(row) for row in reader]
    return normalized_fieldnames, rows


def parse_xlsx_bytes(raw_content):
    with zipfile.ZipFile(io.BytesIO(raw_content)) as workbook_zip:
        shared_strings = read_shared_strings(workbook_zip)
        workbook = ET.fromstring(workbook_zip.read("xl/workbook.xml"))
        relationships = ET.fromstring(workbook_zip.read("xl/_rels/workbook.xml.rels"))
        rel_map = {
            rel.attrib["Id"]: rel.attrib["Target"]
            for rel in relationships.findall("rel:Relationship", XML_NAMESPACES)
        }

        for sheet in workbook.findall("main:sheets/main:sheet", XML_NAMESPACES):
            rel_id = sheet.attrib[
                "{http://schemas.openxmlformats.org/officeDocument/2006/relationships}id"
            ]
            target = rel_map[rel_id]
            if not target.startswith("worksheets/"):
                target = "worksheets/" + target.split("/")[-1]

            fieldnames, rows = parse_xlsx_sheet(
                workbook_zip,
                "xl/" + target,
                shared_strings,
            )
            if fieldnames and rows:
                return fieldnames, rows

        raise ValueError("No se encontraron hojas con datos importables en el XLSX.")


def parse_xlsx_sheet(workbook_zip, sheet_path, shared_strings):
    sheet_root = ET.fromstring(workbook_zip.read(sheet_path))
    rows = sheet_root.findall("main:sheetData/main:row", XML_NAMESPACES)
    if not rows:
        return [], []

    parsed_rows = [parse_sheet_row(row, shared_strings) for row in rows]
    parsed_rows = [row for row in parsed_rows if any(cell.strip() for cell in row)]
    if not parsed_rows:
        return [], []

    header_index = detect_header_row_index(parsed_rows)
    fieldnames = [normalize_header(cell) for cell in parsed_rows[header_index]]
    data_rows = []
    for row in parsed_rows[header_index + 1 :]:
        if len(row) < len(fieldnames):
            row = row + [""] * (len(fieldnames) - len(row))
        data_rows.append(
            {
                fieldnames[index]: (row[index].strip() if index < len(row) else "")
                for index in range(len(fieldnames))
                if fieldnames[index]
            }
        )

    return fieldnames, data_rows


def parse_sheet_row(row_element, shared_strings):
    values_by_index = {}
    max_index = -1

    for cell in row_element.findall("main:c", XML_NAMESPACES):
        reference = cell.attrib.get("r", "")
        column_index = column_letters_to_index("".join(ch for ch in reference if ch.isalpha()))
        max_index = max(max_index, column_index)
        values_by_index[column_index] = extract_cell_value(cell, shared_strings)

    return [values_by_index.get(index, "") for index in range(max_index + 1)]


def extract_cell_value(cell, shared_strings):
    cell_type = cell.attrib.get("t")
    value_node = cell.find("main:v", XML_NAMESPACES)

    if cell_type == "inlineStr":
        return "".join(
            text.text or ""
            for text in cell.findall(".//main:t", XML_NAMESPACES)
        ).strip()

    if value_node is None:
        return ""

    value = value_node.text or ""
    if cell_type == "s":
        try:
            return shared_strings[int(value)].strip()
        except (IndexError, ValueError):
            return value.strip()

    return value.strip()


def read_shared_strings(workbook_zip):
    if "xl/sharedStrings.xml" not in workbook_zip.namelist():
        return []

    shared_root = ET.fromstring(workbook_zip.read("xl/sharedStrings.xml"))
    shared_strings = []
    for item in shared_root.findall("main:si", XML_NAMESPACES):
        shared_strings.append(
            "".join(text.text or "" for text in item.findall(".//main:t", XML_NAMESPACES))
        )
    return shared_strings


def column_letters_to_index(column_letters):
    if not column_letters:
        return 0

    index = 0
    for letter in column_letters.upper():
        index = index * 26 + (ord(letter) - ord("A") + 1)
    return index - 1


def normalize_header(value):
    cleaned_value = (value or "").replace("\ufeff", "").strip().lower()
    cleaned_value = unicodedata.normalize("NFKD", cleaned_value)
    cleaned_value = "".join(ch for ch in cleaned_value if not unicodedata.combining(ch))
    cleaned_value = re.sub(r"[^a-z0-9]+", "_", cleaned_value)
    return cleaned_value.strip("_")


def normalize_row(row):
    return {
        normalize_header(key): (value or "").strip()
        for key, value in row.items()
        if key
    }


def detect_header_row_index(parsed_rows):
    if not parsed_rows:
        return 0

    limit = min(len(parsed_rows), 30)
    best_index = 0
    best_score = (-1, -1, -1)

    for index in range(limit):
        normalized_cells = [normalize_header(cell) for cell in parsed_rows[index]]
        non_empty = sum(1 for cell in normalized_cells if cell)
        if non_empty < 2:
            continue
        keyword_hits = sum(1 for cell in normalized_cells if cell in COMMON_HEADER_KEYWORDS)
        unique_cells = len({cell for cell in normalized_cells if cell})
        score = (keyword_hits, non_empty, unique_cells)
        if score > best_score:
            best_score = score
            best_index = index

    if best_score[0] > 0:
        return best_index

    best_index = 0
    best_score = (-1, -1)
    for index in range(limit):
        normalized_cells = [normalize_header(cell) for cell in parsed_rows[index]]
        non_empty = sum(1 for cell in normalized_cells if cell)
        unique_cells = len({cell for cell in normalized_cells if cell})
        score = (non_empty, unique_cells)
        if score > best_score:
            best_score = score
            best_index = index
    return best_index
