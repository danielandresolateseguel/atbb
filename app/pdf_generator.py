from io import BytesIO
from datetime import datetime

from reportlab.lib import colors
from reportlab.lib.enums import TA_LEFT, TA_CENTER, TA_RIGHT, TA_JUSTIFY
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import mm, cm
from reportlab.platypus import (
    BaseDocTemplate, Frame, PageTemplate, Paragraph, Spacer, Table, TableStyle,
    PageBreak, KeepTogether
)
from reportlab.pdfgen import canvas
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont

WIDTH, HEIGHT = A4
LEFT_MARGIN = 1.6 * cm
RIGHT_MARGIN = 1.6 * cm
TOP_MARGIN = 1.4 * cm
BOTTOM_MARGIN = 1.6 * cm

NAVY = colors.HexColor("#1E3A8A")
NAVY_SOFT = colors.HexColor("#DBEAFE")
GREY_50 = colors.HexColor("#F9FAFB")
GREY_200 = colors.HexColor("#E5E7EB")
GREY_600 = colors.HexColor("#4B5563")
GREY_800 = colors.HexColor("#111827")
OK = colors.HexColor("#065F46")
OK_BG = colors.HexColor("#D1FAE5")
BAD = colors.HexColor("#7F1D1D")
BAD_BG = colors.HexColor("#FEE2E2")
WARN = colors.HexColor("#78350F")
WARN_BG = colors.HexColor("#FEF3C7")

Q_BG = {1: OK_BG, 2: colors.HexColor("#ECFCCB"), 3: WARN_BG, 4: colors.HexColor("#FED7AA"), 5: BAD_BG}
Q_FG = {1: OK, 2: colors.HexColor("#3F6212"), 3: WARN, 4: colors.HexColor("#7C2D12"), 5: BAD}
Q_LABEL = {1: "Q1 · Top 20%", 2: "Q2 · Bueno", 3: "Q3 · Medio", 4: "Q4 · Bajo", 5: "Q5 · Alerta"}


def _try_register_fonts():
    candidates = [
        ("Helvetica", None, None),
    ]
    import os
    system_fonts = [
        ("Arial", r"C:\Windows\Fonts\arial.ttf", r"C:\Windows\Fonts\arialbd.ttf", r"C:\Windows\Fonts\ariali.ttf"),
        ("Arial", "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf", "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf", "/usr/share/fonts/truetype/dejavu/DejaVuSans-Oblique.ttf"),
    ]
    for name, p_r, p_b, p_i in system_fonts:
        try:
            if p_r and os.path.isfile(p_r):
                pdfmetrics.registerFont(TTFont(name, p_r))
                if p_b and os.path.isfile(p_b):
                    pdfmetrics.registerFont(TTFont(name + "-Bold", p_b))
                if p_i and os.path.isfile(p_i):
                    pdfmetrics.registerFont(TTFont(name + "-Oblique", p_i))
                candidates = [(name, name + "-Bold" if p_b and os.path.isfile(p_b) else name, name + "-Oblique" if p_i and os.path.isfile(p_i) else name)]
                break
        except Exception:
            continue
    return candidates[0]


_FONT_NAME, _FONT_BOLD, _FONT_ITALIC = _try_register_fonts()


def _styles():
    s = getSampleStyleSheet()
    def mk(name, base="Normal", **kw):
        p = ParagraphStyle(name, parent=s[base])
        p.fontName = kw.get("fontName", _FONT_NAME)
        p.fontSize = kw.get("fontSize", 10)
        p.leading = kw.get("leading", 13)
        p.alignment = kw.get("alignment", TA_LEFT)
        p.textColor = kw.get("textColor", GREY_800)
        p.spaceAfter = kw.get("spaceAfter", 0)
        p.spaceBefore = kw.get("spaceBefore", 0)
        p.leftIndent = kw.get("leftIndent", 0)
        p.rightIndent = kw.get("rightIndent", 0)
        p.backColor = kw.get("backColor", None)
        p.borderPadding = kw.get("borderPadding", 0)
        p.firstLineIndent = kw.get("firstLineIndent", 0)
        return p
    return {
        "title": mk("P_Title", fontSize=20, leading=24, fontName=_FONT_BOLD, textColor=NAVY, alignment=TA_LEFT, spaceAfter=4),
        "subtitle": mk("P_Subtitle", fontSize=11, leading=14, textColor=GREY_600, spaceAfter=10),
        "h2": mk("P_H2", fontSize=13, leading=17, fontName=_FONT_BOLD, textColor=NAVY, spaceBefore=10, spaceAfter=6),
        "h3": mk("P_H3", fontSize=11, leading=14, fontName=_FONT_BOLD, textColor=GREY_800, spaceBefore=6, spaceAfter=4),
        "body": mk("P_Body", fontSize=9.5, leading=12.5, spaceAfter=3),
        "body_s": mk("P_BodyS", fontSize=8.5, leading=11, spaceAfter=2),
        "meta": mk("P_Meta", fontSize=8, leading=10, textColor=GREY_600, spaceAfter=2),
        "kpi_val": mk("P_KpiVal", fontSize=14, leading=18, fontName=_FONT_BOLD, textColor=GREY_800, alignment=TA_CENTER),
        "kpi_val_s": mk("P_KpiValS", fontSize=11, leading=14, fontName=_FONT_BOLD, textColor=GREY_800, alignment=TA_CENTER),
        "kpi_label": mk("P_KpiLabel", fontSize=7.8, leading=10, textColor=GREY_600, alignment=TA_CENTER, spaceAfter=1),
        "td": mk("P_Td", fontSize=8.4, leading=10.5),
        "tdb": mk("P_TdB", fontSize=8.4, leading=10.5, fontName=_FONT_BOLD),
        "tdr": mk("P_TdR", fontSize=8.4, leading=10.5, alignment=TA_RIGHT),
        "tdbr": mk("P_TdBR", fontSize=8.4, leading=10.5, fontName=_FONT_BOLD, alignment=TA_RIGHT),
        "tdc": mk("P_TdC", fontSize=8.4, leading=10.5, alignment=TA_CENTER),
        "th": mk("P_Th", fontSize=8.2, leading=10, fontName=_FONT_BOLD, textColor=colors.white),
        "empty": mk("P_Empty", fontSize=9, leading=12, textColor=GREY_600, alignment=TA_LEFT, spaceAfter=4),
    }


def _p(text, style):
    safe = str(text) if text is not None else ""
    safe = (
        safe.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    )
    return Paragraph(safe, style)


def _fmt_num(v, nd=1):
    try:
        if v is None or v == "":
            return "-"
        f = float(v)
        if nd == 0:
            return f"{int(round(f)):d}"
        return f"{f:.{nd}f}"
    except Exception:
        return str(v)


def _fmt_pct(v, nd=1):
    if v is None or v == "":
        return "-"
    try:
        return f"{float(v):.{nd}f}%"
    except Exception:
        return str(v)


def _fmt_delta(v, kind="num", nd=1):
    if v is None:
        return "-"
    try:
        f = float(v)
        sign = "▲" if f > 0 else ("▼" if f < 0 else "=")
        unit = "%" if kind == "pct" else ""
        if f == 0:
            return f"= 0{unit}"
        absv = abs(f)
        return f"{sign} {absv:.{nd}f}{unit}"
    except Exception:
        return str(v)


def _quintile_badge(q):
    try:
        qn = int(q)
    except Exception:
        qn = None
    if qn not in Q_LABEL:
        return _p("-", _styles()["tdc"])
    sty = ParagraphStyle(
        "Qbadge",
        parent=_styles()["tdc"],
        backColor=Q_BG.get(qn, GREY_200),
        textColor=Q_FG.get(qn, GREY_800),
        fontName=_FONT_BOLD,
        borderPadding=(3, 5, 3, 5),
        alignment=TA_CENTER,
    )
    return Paragraph(Q_LABEL.get(qn, "-"), sty)


def _trend_badge(trend, st):
    if trend == "up":
        lab = "🔴 Empeora"
    elif trend == "down":
        lab = "🟢 Mejora"
    else:
        lab = "🟡 Estable"
    return _p(lab, st["tdc"])


def _kpi_card(label, value, styles, highlight=None):
    data = [[_p(label, styles["kpi_label"])], [_p(value, styles["kpi_val_s"])]]
    t = Table(data, colWidths=[4.2*cm], rowHeights=[None, None])
    col = GREY_50 if not highlight else (OK_BG if highlight == "ok" else (BAD_BG if highlight == "bad" else WARN_BG))
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), col),
        ("BOX", (0, 0), (-1, -1), 0.5, GREY_200),
        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("LEFTPADDING", (0, 0), (-1, -1), 4),
        ("RIGHTPADDING", (0, 0), (-1, -1), 4),
        ("TOPPADDING", (0, 0), (-1, 0), 5),
        ("BOTTOMPADDING", (0, -1), (-1, -1), 5),
    ]))
    return t


def _tech_get(t, key, default=""):
    try:
        if isinstance(t, dict):
            v = t.get(key)
        else:
            v = getattr(t, key, None)
        if v is None or str(v).strip() == "":
            return default
        return v
    except Exception:
        return default


class TechnProfilePdf:

    def __init__(self, data, emitter_label=""):
        self.data = data or {}
        self.emitter = emitter_label or "Sistema Auditorías Integrales"
        self.tech = (self.data.get("technician") or {})
        self.styles = _styles()
        self._summary_range_labels()

    def _summary_range_labels(self):
        f = self.data.get("filters") or {}
        from_date = f.get("from_date") or ""
        to_date = f.get("to_date") or ""
        all_time = bool(f.get("all_time"))
        if all_time or (not from_date and not to_date):
            self.range_label = "Todo el histórico"
        else:
            self.range_label = f"{from_date or '…'} → {to_date or '…'}"
        self.emitted_at = datetime.now().strftime("%Y-%m-%d %H:%M")
        leg = _tech_get(self.tech, "employee_code")
        safe_leg = "".join(ch if ch.isalnum() else "_" for ch in str(leg or "sin_legajo"))
        self.filename = f"Perfil_Tecnico_{safe_leg}_{datetime.now().strftime('%Y%m%d')}.pdf"

    def _canvas_header_footer(self, c, doc):
        c.saveState()
        c.setFillColor(NAVY)
        c.rect(LEFT_MARGIN, HEIGHT - TOP_MARGIN + 0.3*cm, WIDTH - LEFT_MARGIN - RIGHT_MARGIN, 0.18*cm, fill=1, stroke=0)
        c.setFont(_FONT_BOLD, 8)
        c.setFillColor(NAVY)
        c.drawString(LEFT_MARGIN, HEIGHT - TOP_MARGIN + 0.45*cm, "PERFIL TÉCNICO INDIVIDUAL · INFORME EJECUTIVO")
        c.setFillColor(GREY_600)
        c.setFont(_FONT_NAME, 7.5)
        c.drawRightString(WIDTH - RIGHT_MARGIN, HEIGHT - TOP_MARGIN + 0.45*cm, f"Emitido: {self.emitted_at}")
        c.setStrokeColor(GREY_200)
        c.setLineWidth(0.4)
        c.line(LEFT_MARGIN, BOTTOM_MARGIN - 0.35*cm, WIDTH - RIGHT_MARGIN, BOTTOM_MARGIN - 0.35*cm)
        c.setFillColor(GREY_600)
        c.setFont(_FONT_NAME, 7.5)
        c.drawString(LEFT_MARGIN, BOTTOM_MARGIN - 0.55*cm, self.emitter)
        full_name = f"{_tech_get(self.tech,'name','')} · Leg. {_tech_get(self.tech,'employee_code','-')}"
        c.drawCentredString((LEFT_MARGIN + WIDTH - RIGHT_MARGIN) / 2.0, BOTTOM_MARGIN - 0.55*cm, full_name)
        c.drawRightString(WIDTH - RIGHT_MARGIN, BOTTOM_MARGIN - 0.55*cm, f"Página {doc.page}")
        c.restoreState()

    def _section_cover_and_hero(self):
        S = self.styles
        story = []
        # Carátula
        name = _tech_get(self.tech, "name", "Técnico sin datos")
        legajo = _tech_get(self.tech, "employee_code", "-")
        sindicato = _tech_get(self.tech, "union_name", "-")
        estado = "Activo" if _tech_get(self.tech, "is_active", True) else "Inactivo"
        telefono = _tech_get(self.tech, "phone", "-")
        comuna = _tech_get(self.tech, "commune", "-")
        region = _tech_get(self.tech, "region", "-")
        supervisor = _tech_get(self.tech, "supervisor_name", "-")
        centro = _tech_get(self.tech, "center_name", "-")
        empresa = _tech_get(self.tech, "company_name", "-")
        ult_act = self.data.get("last_activity") or (self.data.get("historic") or {}).get("age", {}).get("last", "-")

        story.append(_p("Perfil Técnico Individual", S["title"]))
        story.append(_p(f"Informe Ejecutivo · Rango analizado: {self.range_label}", S["subtitle"]))

        # Tabla carátula datos básicos
        rows = [
            ["Nombre completo", _p(name, S["tdb"]), "Legajo", _p(str(legajo), S["tdb"])],
            ["Sindicato", _p(str(sindicato), S["td"]), "Estado", _p(str(estado), S["td"])],
            ["Teléfono", _p(str(telefono), S["td"]), "Comuna", _p(str(comuna), S["td"])],
            ["Región", _p(str(region), S["td"]), "Últ. actividad", _p(str(ult_act or "-"), S["td"])],
            ["Supervisor", _p(str(supervisor), S["td"]), "Centro", _p(str(centro), S["td"])],
            ["Empresa", _p(str(empresa), S["td"]), "Equipo / Flota", _p(str(_tech_get(self.tech, "team", "-")), S["td"])],
        ]
        # Vehículo
        veh = self.data.get("vehicle") or {}
        if veh.get("plate") or veh.get("truck_number"):
            vn = veh.get("truck_number") or "-"
            vp = veh.get("plate") or "-"
            rows.append(["N° Camioneta", _p(str(vn), S["tdb"]), "Patente", _p(str(vp), S["tdb"])])
        t0 = Table(rows, colWidths=[3.2*cm, 6.3*cm, 2.8*cm, 5.1*cm])
        t0.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (0, -1), NAVY_SOFT),
            ("BACKGROUND", (2, 0), (2, -1), NAVY_SOFT),
            ("FONTNAME", (0, 0), (0, -1), _FONT_BOLD),
            ("FONTNAME", (2, 0), (2, -1), _FONT_BOLD),
            ("FONTSIZE", (0, 0), (-1, -1), 9),
            ("TEXTCOLOR", (0, 0), (-1, -1), GREY_800),
            ("ALIGN", (0, 0), (0, -1), "LEFT"),
            ("ALIGN", (2, 0), (2, -1), "LEFT"),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("GRID", (0, 0), (-1, -1), 0.4, GREY_200),
            ("LEFTPADDING", (0, 0), (-1, -1), 6),
            ("RIGHTPADDING", (0, 0), (-1, -1), 6),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ]))
        story.append(t0)
        story.append(Spacer(1, 6))

        # Hero 4 cajas rango actual
        story.append(_p("Resumen Ejecutivo · Rango seleccionado", S["h2"]))
        summary = self.data.get("summary") or {}
        audits_cnt = summary.get("audits_count") or 0
        qc_cnt = summary.get("qc_count") or 0
        svc_cnt = summary.get("service_count") or 0
        nps_cnt = summary.get("nps_count") or 0
        audit_score = _fmt_pct(summary.get("audit_avg_score"))
        audit_approval = _fmt_pct(summary.get("audit_approval_rate"))
        qc_score = _fmt_pct(summary.get("qc_avg_score"))
        qc_approval = _fmt_pct(summary.get("qc_approval_rate"))
        svc_score = _fmt_num(summary.get("service_avg_score"))
        nps_score = _fmt_num(summary.get("avg_nps"))
        hero_cells = [
            _kpi_card(f"AUDITORÍAS · {audits_cnt}", f"Score {audit_score} · Aprob. {audit_approval}", S),
            _kpi_card(f"QC · {qc_cnt}", f"Score {qc_score} · Aprob. {qc_approval}", S),
            _kpi_card(f"SERVICE · {svc_cnt}", f"Score {svc_score}", S),
            _kpi_card(f"NPS · {nps_cnt}", f"Prom. {nps_score}", S),
        ]
        hero_grid = Table([hero_cells], colWidths=[4.2*cm, 4.2*cm, 4.2*cm, 4.2*cm])
        hero_grid.setStyle(TableStyle([
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("LEFTPADDING", (0, 0), (-1, -1), 0),
            ("RIGHTPADDING", (0, 0), (-1, -1), 4),
            ("TOPPADDING", (0, 0), (-1, -1), 0),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 0),
        ]))
        story.append(hero_grid)
        return story

    def _section_historic(self):
        S = self.styles
        story = [_p("Histórico Consolidado", S["h2"])]
        hist = self.data.get("historic") or {}
        age = hist.get("age") or {}
        vols = hist.get("volumes") or {}
        q = hist.get("quality") or {}
        peaks = hist.get("peaks") or {}
        streaks = hist.get("streaks") or {}

        # Antigüedad
        first = age.get("first") or "-"
        last = age.get("last") or "-"
        years = age.get("years")
        months = age.get("months")
        if years is not None and months is not None:
            ant = f"{int(years)}a {int(months)}m"
        else:
            ant = age.get("label") or "-"
        row1 = [
            ["Primera actividad", _p(str(first), S["tdb"]), "Última actividad", _p(str(last), S["tdb"]), "Antigüedad", _p(ant, S["tdb"])],
        ]
        t_ant = Table(row1, colWidths=[2.8*cm, 4.5*cm, 2.8*cm, 3.2*cm, 2.4*cm, 2.0*cm])
        t_ant.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (0, 0), NAVY_SOFT),
            ("BACKGROUND", (2, 0), (2, 0), NAVY_SOFT),
            ("BACKGROUND", (4, 0), (4, 0), NAVY_SOFT),
            ("FONTNAME", (0, 0), (0, -1), _FONT_BOLD),
            ("FONTNAME", (2, 0), (2, -1), _FONT_BOLD),
            ("FONTNAME", (4, 0), (4, -1), _FONT_BOLD),
            ("GRID", (0, 0), (-1, -1), 0.4, GREY_200),
            ("LEFTPADDING", (0, 0), (-1, -1), 6),
            ("RIGHTPADDING", (0, 0), (-1, -1), 6),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ]))
        story.append(t_ant)
        story.append(Spacer(1, 5))

        # Volúmenes históricos
        story.append(_p("Volúmenes · Todo histórico", S["h3"]))
        def _vol(label, key_val, avg_key):
            total = vols.get(key_val) or 0
            avg = (vols.get("avg_per_month") or {}).get(avg_key) or 0
            return [
                _p(label, S["tdb"]),
                _p(_fmt_num(total, 0), S["tdbr"]),
                _p(f"Prom/mes: {_fmt_num(avg)}", S["tdr"]),
            ]
        rows_vol = [
            [_p("Indicador", S["th"]), _p("Total", S["th"]), _p("Promedio / mes", S["th"])],
            _vol("Auditorías", "audits_total", "audits"),
            _vol("QC", "qc_total", "qc"),
            _vol("Service", "service_total", "service"),
            _vol("NPS (respuestas)", "nps_total", "nps"),
        ]
        tv = Table(rows_vol, colWidths=[5.2*cm, 3.2*cm, 5.2*cm])
        tv.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), NAVY),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("GRID", (0, 0), (-1, -1), 0.4, GREY_200),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, GREY_50]),
            ("LEFTPADDING", (0, 0), (-1, -1), 6),
            ("RIGHTPADDING", (0, 0), (-1, -1), 6),
            ("TOPPADDING", (0, 0), (-1, -1), 3),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ]))
        story.append(tv)
        story.append(Spacer(1, 4))

        story.append(_p("Calidad · Promedios históricos", S["h3"]))
        def _kv(lab, val, unit_pct=True):
            return [_p(lab, S["tdb"]), _p((_fmt_pct(val) if unit_pct else _fmt_num(val)), S["tdr"])]
        rows_q = [
            [_p("KPI", S["th"]), _p("Valor", S["th"])],
            _kv("Score Audit promedio", q.get("audit_avg_score")),
            _kv("% Aprobación Audit", q.get("audit_approval_rate")),
            _kv("Score QC promedio", q.get("qc_avg_score")),
            _kv("% Aprobación QC", q.get("qc_approval_rate")),
            _kv("Score Service promedio", q.get("service_avg_score"), False),
            _kv("NPS promedio", q.get("avg_nps"), False),
            _kv("Críticas Audit (total)", q.get("audit_critical_count"), False),
            _kv("% Críticas Audit", q.get("audit_critical_rate")),
        ]
        tq = Table(rows_q, colWidths=[6.2*cm, 4.2*cm])
        tq.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), NAVY),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("GRID", (0, 0), (-1, -1), 0.4, GREY_200),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, GREY_50]),
            ("LEFTPADDING", (0, 0), (-1, -1), 6),
            ("RIGHTPADDING", (0, 0), (-1, -1), 6),
            ("TOPPADDING", (0, 0), (-1, -1), 3),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
        ]))
        story.append(tq)
        story.append(Spacer(1, 3))

        # Picos + Rachas
        story.append(_p("Picos y rachas", S["h3"]))
        def _peak(v):
            if not v:
                return "-"
            try:
                return f"{v.get('month')}: {v.get('count')}"
            except Exception:
                return str(v)
        rows_pr = [
            [_p("Pico Auditorías mes", S["tdb"]), _p(_peak(peaks.get("audit")), S["td"]),
             _p("Racha sin actividad (días)", S["tdb"]), _p(_fmt_num(streaks.get("days_since_last_activity"), 0), S["td"])],
            [_p("Pico QC mes", S["tdb"]), _p(_peak(peaks.get("qc")), S["td"]),
             _p("Días desde últ. Auditoría", S["tdb"]), _p(_fmt_num(streaks.get("days_since_last_audit"), 0), S["td"])],
            [_p("Pico Service mes", S["tdb"]), _p(_peak(peaks.get("service")), S["td"]),
             _p("Días desde últ. QC", S["tdb"]), _p(_fmt_num(streaks.get("days_since_last_qc"), 0), S["td"])],
        ]
        tpr = Table(rows_pr, colWidths=[3.6*cm, 4.2*cm, 3.6*cm, 4.6*cm])
        tpr.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (0, -1), NAVY_SOFT),
            ("BACKGROUND", (2, 0), (2, -1), NAVY_SOFT),
            ("GRID", (0, 0), (-1, -1), 0.4, GREY_200),
            ("LEFTPADDING", (0, 0), (-1, -1), 6),
            ("RIGHTPADDING", (0, 0), (-1, -1), 6),
            ("TOPPADDING", (0, 0), (-1, -1), 3),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
        ]))
        story.append(tpr)
        return story

    def _section_monthly_and_pvp(self):
        S = self.styles
        story = [_p("Serie mensual · 18 meses máximo", S["h2"])]
        series = self.data.get("monthly_series") or []
        if not series:
            story.append(_p("Sin datos de serie mensual para este rango.", S["empty"]))
        else:
            header = [
                _p("Mes", S["th"]), _p("Audit", S["th"]), _p("Audit score%", S["th"]), _p("QC", S["th"]),
                _p("QC score%", S["th"]), _p("Svc", S["th"]), _p("NPS", S["th"])
            ]
            rows = [header]
            for s in series[-12:]:
                rows.append([
                    _p(str(s.get("period_key") or ""), S["td"]),
                    _p(_fmt_num(s.get("audits_count") or 0, 0), S["tdr"]),
                    _p(_fmt_pct(s.get("audit_avg_score")), S["tdr"]),
                    _p(_fmt_num(s.get("qc_count") or 0, 0), S["tdr"]),
                    _p(_fmt_pct(s.get("qc_avg_score")), S["tdr"]),
                    _p(_fmt_num(s.get("service_count") or 0, 0), S["tdr"]),
                    _p(_fmt_num(s.get("avg_nps")), S["tdr"]),
                ])
            tms = Table(rows, colWidths=[2.4*cm, 1.5*cm, 2.3*cm, 1.3*cm, 2.2*cm, 1.3*cm, 2.0*cm])
            tms.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), NAVY),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("GRID", (0, 0), (-1, -1), 0.4, GREY_200),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, GREY_50]),
                ("LEFTPADDING", (0, 0), (-1, -1), 4),
                ("RIGHTPADDING", (0, 0), (-1, -1), 4),
                ("TOPPADDING", (0, 0), (-1, -1), 3),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
            ]))
            story.append(tms)

        story.append(Spacer(1, 4))
        pvp = self.data.get("pvp") or {}
        story.append(_p(f"Comparativa período · {pvp.get('current_range_label') or 'Actual'} vs. {pvp.get('previous_range_label') or 'Anterior'}", S["h2"]))
        rows_pvp = [[
            _p("KPI", S["th"]), _p("Actual", S["th"]), _p("Anterior", S["th"]),
            _p("Δ abs", S["th"]), _p("Δ %", S["th"])
        ]]
        for r in (pvp.get("rows") or []):
            try:
                kind = r.get("kind") or "num"
                pct = kind in ("pct", "score_pct", "approval")
                av = _fmt_pct(r.get("current_value")) if pct else _fmt_num(r.get("current_value"))
                bv = _fmt_pct(r.get("previous_value")) if pct else _fmt_num(r.get("previous_value"))
                d_abs = r.get("delta")
                d_abs_s = _fmt_delta(d_abs, kind=("pct" if pct else "num"))
                d_rel = r.get("delta_pct")
                try:
                    if d_rel is None:
                        d_rel_s = "-"
                    else:
                        sign = "▲" if float(d_rel) > 0 else ("▼" if float(d_rel) < 0 else "=")
                        d_rel_s = f"{sign} {abs(float(d_rel)):.1f}%"
                except Exception:
                    d_rel_s = "-"
                highlight_ok = (d_abs is not None and (r.get("higher_is_better", True) and float(d_abs) > 0) or (not r.get("higher_is_better", True) and float(d_abs) < 0)) if d_abs not in (None, 0) else False
                highlight_bad = (d_abs is not None and (r.get("higher_is_better", True) and float(d_abs) < 0) or (not r.get("higher_is_better", True) and float(d_abs) > 0)) if d_abs not in (None, 0) else False
                rows_pvp.append([
                    _p(str(r.get("label") or ""), S["tdb"]),
                    _p(av, S["tdr"]),
                    _p(bv, S["tdr"]),
                    _p(d_abs_s, S["tdr"]),
                    _p(d_rel_s, S["tdr"]),
                ])
            except Exception:
                continue
        if len(rows_pvp) <= 1:
            story.append(_p("Sin comparativa PvP para este rango (solo hay 1 período).", S["empty"]))
        else:
            tpvp = Table(rows_pvp, colWidths=[4.2*cm, 2.5*cm, 2.5*cm, 2.5*cm, 2.5*cm])
            tpvp.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), NAVY),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("GRID", (0, 0), (-1, -1), 0.4, GREY_200),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, GREY_50]),
                ("LEFTPADDING", (0, 0), (-1, -1), 5),
                ("RIGHTPADDING", (0, 0), (-1, -1), 5),
                ("TOPPADDING", (0, 0), (-1, -1), 3),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
            ]))
            story.append(tpvp)
        return story

    def _section_distribution(self):
        S = self.styles
        story = [_p("Distribución · Posicionamiento vs grupo (4 scopes × 3 KPIs)", S["h2"])]
        rows_d = (self.data.get("distribution") or {}).get("scope_rows") or []
        if not rows_d:
            story.append(_p("Sin datos suficientes para comparar.", S["empty"]))
            return story
        header = [
            _p("Scope", S["th"]), _p("Valor", S["th"]), _p("KPI", S["th"]),
            _p("Tech", S["th"]), _p("Peer avg", S["th"]), _p("Δ", S["th"]),
            _p("Rank", S["th"]), _p("Quintil", S["th"]),
        ]
        data = [header]
        for r in rows_d:
            pct_k = (r.get("kpi_key") or "") in ("audit_avg_score", "qc_avg_score", "audit_approval_rate", "qc_approval_rate")
            tv = _fmt_pct(r.get("technician_value")) if pct_k else _fmt_num(r.get("technician_value"))
            pv = _fmt_pct(r.get("peer_avg")) if pct_k else _fmt_num(r.get("peer_avg"))
            dv = _fmt_delta(r.get("delta"), kind=("pct" if pct_k else "num"))
            rank_s = f"#{r.get('rank')}·{r.get('total_peers')}" if r.get("rank") and r.get("total_peers") else "-"
            data.append([
                _p(f"{r.get('scope_label') or ''}: {r.get('scope_value') or ''}", S["td"]),
                _p("", S["td"]),  # placeholder merged
                _p(str(r.get("kpi_label") or ""), S["tdb"]),
                _p(tv, S["tdr"]),
                _p(pv, S["tdr"]),
                _p(dv, S["tdr"]),
                _p(rank_s, S["tdr"]),
                _quintile_badge(r.get("quintile")),
            ])
        td = Table(data, colWidths=[4.4*cm, 1.3*cm, 3.0*cm, 1.8*cm, 1.8*cm, 1.8*cm, 1.5*cm, 3.6*cm])
        style_list = [
            ("BACKGROUND", (0, 0), (-1, 0), NAVY),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("GRID", (0, 0), (-1, -1), 0.4, GREY_200),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, GREY_50]),
            ("LEFTPADDING", (0, 0), (-1, -1), 4),
            ("RIGHTPADDING", (0, 0), (-1, -1), 4),
            ("TOPPADDING", (0, 0), (-1, -1), 3),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
            ("SPAN", (0, 1), (1, -1)),  # merge scope col 0 y placeholder col1 (mantengo scope en col0 sólo)
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ]
        # Corregir SPAN anterior: el span (0,1)-(1,-1) no quería mergear scope, lo quito manualmente y hago merge correcto
        style_list.pop()
        for i in range(1, len(data)):
            # Merge column 0 y 1 = scope + placeholder → dejar solo scope column
            style_list.append(("SPAN", (0, i), (1, i)))
        td.setStyle(TableStyle(style_list))
        story.append(td)
        return story

    def _section_findings(self):
        S = self.styles
        story = [_p("Hallazgos · Tendencia últimos 6 meses", S["h2"])]
        ft = self.data.get("findings_trend") or {}
        months = ft.get("months") or []
        story.append(_p(f"Meses analizados: {' · '.join([str(m) for m in months]) if months else '-'}", S["meta"]))
        story.append(Spacer(1, 2))
        for section_title, items, danger in (
            ("Auditoría · No cumple", ft.get("audit_findings") or [], False),
            ("QC · NC Mayor", ft.get("qc_findings") or [], True),
        ):
            story.append(_p(section_title, S["h3"]))
            if not items:
                story.append(_p(f"Sin ítems de {section_title.lower()} en este rango.", S["empty"]))
                continue
            header = [_p("Ítem", S["th"]), _p("T", S["th"]), _p("Pico", S["th"])]
            for m in months:
                header.append(_p(str(m), S["th"]))
            header.append(_p("Semáforo", S["th"]))
            data = [header]
            for f in items[:30]:
                row = [
                    _p(str(f.get("item") or ""), S["td"]),
                    _p(_fmt_num(f.get("total") or 0, 0), S["tdr"]),
                    _p(_fmt_num(f.get("max_count") or 0, 0), S["tdr"]),
                ]
                counts = (f.get("series_counts") or [])
                # Pad a len(months) with 0
                padded = list(counts) + [0] * max(0, len(months) - len(counts))
                counts = padded[:len(months)]
                max_c = max(counts) if counts else 0
                for c in counts:
                    cell_txt = _fmt_num(c, 0)
                    sty = S["tdc"]
                    if c > 0:
                        sty2 = ParagraphStyle(
                            f"ff{c}_{danger}_{f.get('item','')[:10]}",
                            parent=S["tdc"],
                            backColor=BAD_BG if danger else WARN_BG,
                            textColor=BAD if danger else WARN,
                            fontName=_FONT_BOLD,
                            borderPadding=(2, 2, 2, 2),
                        )
                        row.append(Paragraph(cell_txt, sty2))
                    else:
                        row.append(Paragraph("0", S["tdc"]))
                row.append(_trend_badge(f.get("trend"), S))
                data.append(row)
            col_widths = [6.2*cm, 0.9*cm, 1.1*cm]
            for _ in months:
                col_widths.append(1.2*cm)
            col_widths.append(2.6*cm)
            tf = Table(data, colWidths=col_widths, repeatRows=1)
            styles_l = [
                ("BACKGROUND", (0, 0), (-1, 0), NAVY),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("GRID", (0, 0), (-1, -1), 0.35, GREY_200),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, GREY_50]),
                ("LEFTPADDING", (0, 0), (-1, -1), 3),
                ("RIGHTPADDING", (0, 0), (-1, -1), 3),
                ("TOPPADDING", (0, 0), (-1, -1), 2),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 2),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ]
            tf.setStyle(TableStyle(styles_l))
            story.append(tf)
            story.append(Spacer(1, 4))
        return story

    def build(self, buf):
        doc = BaseDocTemplate(
            buf,
            pagesize=A4,
            leftMargin=LEFT_MARGIN,
            rightMargin=RIGHT_MARGIN,
            topMargin=TOP_MARGIN,
            bottomMargin=BOTTOM_MARGIN,
            title=f"Perfil Técnico {_tech_get(self.tech,'name','')}",
            author=self.emitter,
        )
        frame = Frame(
            doc.leftMargin, doc.bottomMargin,
            doc.width, doc.height,
            id="main",
        )
        pt = PageTemplate(id="normal", frames=[frame], onPage=self._canvas_header_footer)
        doc.addPageTemplates([pt])

        story = []
        story.extend(self._section_cover_and_hero())
        story.append(PageBreak())
        story.extend(self._section_historic())
        story.append(PageBreak())
        story.extend(self._section_monthly_and_pvp())
        story.append(PageBreak())
        story.extend(self._section_distribution())
        story.append(PageBreak())
        story.extend(self._section_findings())
        doc.build(story)
        return doc


def build_technician_pdf(data, emitter_label=""):
    builder = TechnProfilePdf(data, emitter_label=emitter_label)
    buf = BytesIO()
    builder.build(buf)
    buf.seek(0)
    return buf, builder.filename
