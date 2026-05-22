import zipfile
import xml.etree.ElementTree as ET
from pathlib import Path

base_dir = Path(r'c:\Daniel Olate\Soft Berardi\archivo de datos')
files = [
    base_dir / 'ALMACENES.xlsx',
    base_dir / 'StockDeEquipos_21_5_2026.xlsx',
    base_dir / 'StockMateriales21_5_2026_10_53 a. m..xlsx',
    base_dir / 'StockMateriales21_5_2026_10_54 a. m..xlsx',
]

ns = {
    'main': 'http://schemas.openxmlformats.org/spreadsheetml/2006/main',
    'rel': 'http://schemas.openxmlformats.org/package/2006/relationships'
}

for xlsx_path in files:
    print(f'===== ARCHIVO: {xlsx_path.name} =====')
    with zipfile.ZipFile(xlsx_path) as zf:
        shared_strings = []
        if 'xl/sharedStrings.xml' in zf.namelist():
            root = ET.fromstring(zf.read('xl/sharedStrings.xml'))
            for si in root.findall('main:si', ns):
                text = ''.join(t.text or '' for t in si.findall('.//main:t', ns))
                shared_strings.append(text)

        workbook = ET.fromstring(zf.read('xl/workbook.xml'))
        rels = ET.fromstring(zf.read('xl/_rels/workbook.xml.rels'))
        rel_map = {rel.attrib['Id']: rel.attrib['Target'] for rel in rels.findall('rel:Relationship', ns)}

        for sheet in workbook.findall('main:sheets/main:sheet', ns):
            name = sheet.attrib['name']
            rel_id = sheet.attrib['{http://schemas.openxmlformats.org/officeDocument/2006/relationships}id']
            target = rel_map[rel_id]
            if not target.startswith('worksheets/'):
                target = 'worksheets/' + target.split('/')[-1]
            xml_path = 'xl/' + target
            sheet_root = ET.fromstring(zf.read(xml_path))
            print(f'--- HOJA: {name} ---')
            rows = sheet_root.findall('main:sheetData/main:row', ns)
            for row in rows[:8]:
                values = []
                for cell in row.findall('main:c', ns):
                    cell_type = cell.attrib.get('t')
                    value_node = cell.find('main:v', ns)
                    if value_node is None:
                        values.append('')
                        continue
                    value = value_node.text or ''
                    if cell_type == 's':
                        try:
                            value = shared_strings[int(value)]
                        except Exception:
                            pass
                    values.append(value)
                print(values)
            print()
