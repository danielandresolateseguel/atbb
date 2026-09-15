import json
import os
import time
import urllib.parse
import urllib.request
from datetime import date, datetime, timedelta, timezone

from flask import current_app

_WEATHER_CACHE_TTL_SECONDS_DEFAULT = 1800
_WEATHER_ERROR_TTL_SECONDS_DEFAULT = 3600
_ARG_TZ_OFFSET = timezone(timedelta(hours=-3), name="America/Argentina/Buenos_Aires")

def _now_arg():
    return datetime.now(tz=_ARG_TZ_OFFSET)

def _today_arg_iso():
    return _now_arg().date().isoformat()


_WEATHER_CACHE_TTL_SECONDS_DEFAULT = 1800

_WEATHER_CODE_LABELS = {
    0: "Despejado",
    1: "Principalmente despejado",
    2: "Parcialmente nublado",
    3: "Nublado",
    45: "Niebla",
    48: "Escarcha",
    51: "Llovizna leve",
    53: "Llovizna",
    55: "Llovizna intensa",
    56: "Llovizna congelada leve",
    57: "Llovizna congelada intensa",
    61: "Lluvia leve",
    63: "Lluvia",
    65: "Lluvia fuerte",
    66: "Lluvia congelada leve",
    67: "Lluvia congelada fuerte",
    71: "Nieve leve",
    73: "Nieve",
    75: "Nieve fuerte",
    77: "Granizo",
    80: "Chubascos leves",
    81: "Chubascos",
    82: "Chubascos violentos",
    85: "Chubascos de nieve leves",
    86: "Chubascos de nieve fuertes",
    95: "Tormenta",
    96: "Tormenta con granizo leve",
    99: "Tormenta con granizo fuerte",
}

_WEATHER_CODE_ICON = {
    0: "☀️",
    1: "🌤️",
    2: "⛅",
    3: "☁️",
    45: "🌫️",
    48: "🌫️",
    51: "🌦️",
    53: "🌦️",
    55: "🌧️",
    56: "🌧️",
    57: "🌧️",
    61: "🌧️",
    63: "🌧️",
    65: "🌧️",
    66: "🌨️",
    67: "🌨️",
    71: "🌨️",
    73: "🌨️",
    75: "❄️",
    77: "❄️",
    80: "🌦️",
    81: "🌧️",
    82: "⛈️",
    85: "🌨️",
    86: "❄️",
    95: "⛈️",
    96: "⛈️",
    99: "⛈️",
}

_CENTER_COORDINATES_OVERRIDE = None

_DEFAULT_CENTER_COORDINATES = {
    "MENDOZA": {"lat": -32.8894586, "lng": -68.8458386, "region": "Mendoza"},
    "SAN RAFAEL MENDOZA": {"lat": -34.6120431, "lng": -68.3307015, "region": "Mendoza"},
    "SAN MARTIN MENDOZA": {"lat": -33.0813757, "lng": -68.8444769, "region": "Mendoza"},
    "GODOY CRUZ MENDOZA": {"lat": -32.9177778, "lng": -68.8513889, "region": "Mendoza"},
    "LAS HERAS MENDOZA": {"lat": -32.8458333, "lng": -68.8488889, "region": "Mendoza"},
    "MAIPU MENDOZA": {"lat": -33.0166667, "lng": -68.8333333, "region": "Mendoza"},
    "GUAYMALLEN MENDOZA": {"lat": -32.8833333, "lng": -68.7833333, "region": "Mendoza"},
    "LUJAN DE CUYO MENDOZA": {"lat": -33.5519444, "lng": -68.9822222, "region": "Mendoza"},
    "TUNUYAN MENDOZA": {"lat": -33.5833333, "lng": -69.0166667, "region": "Mendoza"},
    "RIVADAVIA MENDOZA": {"lat": -33.1950888, "lng": -68.455097, "region": "Mendoza"},
    "JUNIN MENDOZA": {"lat": -33.205, "lng": -68.5538889, "region": "Mendoza"},
    "SAN CARLOS MENDOZA": {"lat": -33.8, "lng": -69.05, "region": "Mendoza"},
    "CAPITAL MENDOZA": {"lat": -32.8894586, "lng": -68.8458386, "region": "Mendoza"},
    "NEUQUEN": {"lat": -38.9516389, "lng": -68.0591111, "region": "Neuquén"},
    "CIPOLLETTI": {"lat": -38.9368924, "lng": -67.9928917, "region": "Río Negro"},
    "ROCA RIO NEGRO": {"lat": -39.0327946, "lng": -67.5766424, "region": "Río Negro"},
    "BARILOCHE": {"lat": -41.1455662, "lng": -71.3486899, "region": "Río Negro"},
    "TRELEW": {"lat": -43.25, "lng": -65.3166667, "region": "Chubut"},
    "RAWSON": {"lat": -43.3, "lng": -65.1, "region": "Chubut"},
    "COMODORO RIVADAVIA": {"lat": -45.8653339, "lng": -67.4867952, "region": "Chubut"},
    "PUERTO MADRYN": {"lat": -42.7692758, "lng": -65.038575, "region": "Chubut"},
    "SANTA ROSA": {"lat": -36.6202566, "lng": -64.2905985, "region": "La Pampa"},
    "GENERAL PICO": {"lat": -35.661985, "lng": -63.7553249, "region": "La Pampa"},
    "SAN LUIS": {"lat": -33.2995689, "lng": -66.3371074, "region": "San Luis"},
    "MERLO SAN LUIS": {"lat": -32.3419892, "lng": -65.0062899, "region": "San Luis"},
    "LA RIOJA": {"lat": -29.4134639, "lng": -66.855968, "region": "La Rioja"},
    "CHILECITO LA RIOJA": {"lat": -29.1666667, "lng": -67.4833333, "region": "La Rioja"},
    "SAN JUAN": {"lat": -31.5375004, "lng": -68.5363805, "region": "San Juan"},
    "SAN JUAN CAPITAL": {"lat": -31.5375004, "lng": -68.5363805, "region": "San Juan"},
    "RIVADAVIA SAN JUAN": {"lat": -31.2363889, "lng": -68.4805556, "region": "San Juan"},
    "CHIMBAS SAN JUAN": {"lat": -31.5183333, "lng": -68.5319444, "region": "San Juan"},
    "CATAMARCA": {"lat": -28.4695855, "lng": -65.7795619, "region": "Catamarca"},
    "TUCUMAN": {"lat": -26.8082853, "lng": -65.2175909, "region": "Tucumán"},
    "SAN MIGUEL DE TUCUMAN": {"lat": -26.8082853, "lng": -65.2175909, "region": "Tucumán"},
    "YERBA BUENA TUCUMAN": {"lat": -26.8183333, "lng": -65.31, "region": "Tucumán"},
    "CONCEPCION TUCUMAN": {"lat": -27.3333333, "lng": -65.6, "region": "Tucumán"},
    "SALTA": {"lat": -24.7821193, "lng": -65.423177, "region": "Salta"},
    "CAPITAL SALTA": {"lat": -24.7821193, "lng": -65.423177, "region": "Salta"},
    "SAN RAMON SALTA": {"lat": -24.55, "lng": -64.8, "region": "Salta"},
    "ORAN SALTA": {"lat": -23.1333333, "lng": -64.3166667, "region": "Salta"},
    "TARTAGAL SALTA": {"lat": -22.5166667, "lng": -63.8166667, "region": "Salta"},
    "JUJUY": {"lat": -24.1857742, "lng": -65.2994834, "region": "Jujuy"},
    "SAN SALVADOR DE JUJUY": {"lat": -24.1857742, "lng": -65.2994834, "region": "Jujuy"},
    "PALPALA JUJUY": {"lat": -24.25, "lng": -65.2166667, "region": "Jujuy"},
    "LIBERTADOR JUJUY": {"lat": -23.795, "lng": -64.8019444, "region": "Jujuy"},
    "LA QUIACA JUJUY": {"lat": -22.1072222, "lng": -65.5983333, "region": "Jujuy"},
    "CORDOBA": {"lat": -31.4173391, "lng": -64.183319, "region": "Córdoba"},
    "CAPITAL CORDOBA": {"lat": -31.4173391, "lng": -64.183319, "region": "Córdoba"},
    "RIO CUARTO CORDOBA": {"lat": -33.123007, "lng": -64.3493414, "region": "Córdoba"},
    "VILLA MARIA CORDOBA": {"lat": -32.4166667, "lng": -63.2333333, "region": "Córdoba"},
    "VILLA CARLOS PAZ CORDOBA": {"lat": -31.4208333, "lng": -64.4997222, "region": "Córdoba"},
    "SAN FRANCISCO CORDOBA": {"lat": -31.4333333, "lng": -62.0833333, "region": "Córdoba"},
    "ARGUELLO CORDOBA": {"lat": -31.35, "lng": -64.2833333, "region": "Córdoba"},
    "ALTA GRACIA CORDOBA": {"lat": -31.658, "lng": -64.4215, "region": "Córdoba"},
    "ALTA GRACIA": {"lat": -31.658, "lng": -64.4215, "region": "Córdoba"},
    "DEAN FUNES CORDOBA": {"lat": -30.3093, "lng": -64.2597, "region": "Córdoba"},
    "DEAN FUNES": {"lat": -30.3093, "lng": -64.2597, "region": "Córdoba"},
    "RIO SEGUNDO CORDOBA": {"lat": -33.1066, "lng": -64.36, "region": "Córdoba"},
    "RIO SEGUNDO": {"lat": -33.1066, "lng": -64.36, "region": "Córdoba"},
    "VILLA DOLORES CORDOBA": {"lat": -31.9489, "lng": -65.1911, "region": "Córdoba"},
    "VILLA DOLORES": {"lat": -31.9489, "lng": -65.1911, "region": "Córdoba"},
    "SANTIAGO DEL ESTERO": {"lat": -27.7845904, "lng": -64.2652899, "region": "Santiago del Estero"},
    "CAPITAL SANTIAGO DEL ESTERO": {"lat": -27.7845904, "lng": -64.2652899, "region": "Santiago del Estero"},
    "TERMAS DE RIO HONDO": {"lat": -27.5, "lng": -64.9166667, "region": "Santiago del Estero"},
    "LA BANDA": {"lat": -27.7333333, "lng": -64.25, "region": "Santiago del Estero"},
    "SANTA FE": {"lat": -31.6107185, "lng": -60.6968792, "region": "Santa Fe"},
    "CAPITAL SANTA FE": {"lat": -31.6107185, "lng": -60.6968792, "region": "Santa Fe"},
    "ROSARIO": {"lat": -32.9468198, "lng": -60.6393196, "region": "Santa Fe"},
    "RAFAELA SANTA FE": {"lat": -31.25, "lng": -61.4833333, "region": "Santa Fe"},
    "VENADO TUERTO": {"lat": -33.745201, "lng": -61.9688982, "region": "Santa Fe"},
    "ENTRE RIOS": {"lat": -31.7556691, "lng": -60.5199235, "region": "Entre Ríos"},
    "PARANA": {"lat": -31.7556691, "lng": -60.5199235, "region": "Entre Ríos"},
    "CONCORDIA ENTRE RIOS": {"lat": -31.393288, "lng": -58.0082738, "region": "Entre Ríos"},
    "GUALEGUAYCHU": {"lat": -33.0102858, "lng": -58.5077038, "region": "Entre Ríos"},
    "CORRIENTES": {"lat": -27.480602, "lng": -58.8341105, "region": "Corrientes"},
    "CAPITAL CORRIENTES": {"lat": -27.480602, "lng": -58.8341105, "region": "Corrientes"},
    "PASO DE LOS LIBRES": {"lat": -29.7202269, "lng": -57.087853, "region": "Corrientes"},
    "MISIONES": {"lat": -27.3653663, "lng": -55.8981402, "region": "Misiones"},
    "POSADAS": {"lat": -27.3653663, "lng": -55.8981402, "region": "Misiones"},
    "OBERA MISIONES": {"lat": -27.4833333, "lng": -55.1166667, "region": "Misiones"},
    "ELDORADO MISIONES": {"lat": -26.4166667, "lng": -54.7, "region": "Misiones"},
    "CHACO": {"lat": -27.4605597, "lng": -58.9838943, "region": "Chaco"},
    "RESISTENCIA": {"lat": -27.4605597, "lng": -58.9838943, "region": "Chaco"},
    "PRESIDENTE ROQUE SAENZ PENA": {"lat": -26.7916667, "lng": -60.4383333, "region": "Chaco"},
    "BARRANQUERAS CHACO": {"lat": -27.4763889, "lng": -58.9427778, "region": "Chaco"},
    "FORMOSA": {"lat": -26.184277, "lng": -58.173338, "region": "Formosa"},
    "CAPITAL FORMOSA": {"lat": -26.184277, "lng": -58.173338, "region": "Formosa"},
    "CLORINDA FORMOSA": {"lat": -25.2852778, "lng": -57.7183333, "region": "Formosa"},
    "EL COLORADO FORMOSA": {"lat": -26.3333333, "lng": -58.2, "region": "Formosa"},
    "CIUDAD AUTONOMA DE BUENOS AIRES": {"lat": -34.6075682, "lng": -58.4370894, "region": "CABA"},
    "CABA": {"lat": -34.6075682, "lng": -58.4370894, "region": "CABA"},
    "CAPITAL FEDERAL": {"lat": -34.6075682, "lng": -58.4370894, "region": "CABA"},
    "BUENOS AIRES": {"lat": -34.6075682, "lng": -58.4370894, "region": "Provincia de Buenos Aires"},
    "LA PLATA": {"lat": -34.9214489, "lng": -57.9545285, "region": "Provincia de Buenos Aires"},
    "MAR DEL PLATA": {"lat": -38.0053195, "lng": -57.5425928, "region": "Provincia de Buenos Aires"},
    "BAHIA BLANCA": {"lat": -38.7195917, "lng": -62.2724192, "region": "Provincia de Buenos Aires"},
    "QUILMES": {"lat": -34.723264, "lng": -58.254342, "region": "Provincia de Buenos Aires"},
    "LANUS": {"lat": -34.702409, "lng": -58.395958, "region": "Provincia de Buenos Aires"},
    "MORON": {"lat": -34.6546536, "lng": -58.6188118, "region": "Provincia de Buenos Aires"},
    "MERLO BUENOS AIRES": {"lat": -34.6689, "lng": -58.7296, "region": "Provincia de Buenos Aires"},
    "LA MATANZA": {"lat": -34.7713889, "lng": -58.6313889, "region": "Provincia de Buenos Aires"},
    "TIGRE": {"lat": -34.4247689, "lng": -58.5795481, "region": "Provincia de Buenos Aires"},
    "PILAR BUENOS AIRES": {"lat": -34.458786, "lng": -58.914277, "region": "Provincia de Buenos Aires"},
    "ZARATE": {"lat": -34.0991658, "lng": -59.0249699, "region": "Provincia de Buenos Aires"},
    "CAMPANA BUENOS AIRES": {"lat": -34.1633333, "lng": -58.9580556, "region": "Provincia de Buenos Aires"},
    "LOMAS DE ZAMORA": {"lat": -34.7577778, "lng": -58.4013889, "region": "Provincia de Buenos Aires"},
    "AVELLANEDA": {"lat": -34.6633333, "lng": -58.3647222, "region": "Provincia de Buenos Aires"},
    "SAN NICOLAS": {"lat": -33.3353373, "lng": -60.2132639, "region": "Provincia de Buenos Aires"},
    "CORONEL SUAREZ": {"lat": -37.4538889, "lng": -61.9297222, "region": "Provincia de Buenos Aires"},
    "OLAVARRIA": {"lat": -36.8940991, "lng": -60.3225525, "region": "Provincia de Buenos Aires"},
    "TANDIL": {"lat": -37.328878, "lng": -59.1377745, "region": "Provincia de Buenos Aires"},
    "NECOCHEA": {"lat": -38.5465746, "lng": -58.7403149, "region": "Provincia de Buenos Aires"},
    "SALADILLO": {"lat": -35.6437355, "lng": -59.7751255, "region": "Provincia de Buenos Aires"},
    "9 DE JULIO": {"lat": -35.445, "lng": -60.8847222, "region": "Provincia de Buenos Aires"},
    "PERGAMINO": {"lat": -33.89, "lng": -60.5725, "region": "Provincia de Buenos Aires"},
    "CHASCOMUS": {"lat": -35.5788889, "lng": -58.0136111, "region": "Provincia de Buenos Aires"},
    "SAN PEDRO BUENOS AIRES": {"lat": -33.6755556, "lng": -59.665, "region": "Provincia de Buenos Aires"},
    "AZUL": {"lat": -36.7775, "lng": -59.86, "region": "Provincia de Buenos Aires"},
    "SANTIAGO DEL ESTERO CAPITAL": {"lat": -27.7845904, "lng": -64.2652899, "region": "Santiago del Estero"},
    "RIO GALLEGOS": {"lat": -51.6235707, "lng": -69.215687, "region": "Santa Cruz"},
    "CALETA OLIVIA": {"lat": -46.4405556, "lng": -67.5216667, "region": "Santa Cruz"},
    "PUERTO SANTA CRUZ": {"lat": -50.0, "lng": -68.95, "region": "Santa Cruz"},
    "USHUAIA": {"lat": -54.806913, "lng": -68.308948, "region": "Tierra del Fuego"},
    "RIO GRANDE TIERRA DEL FUEGO": {"lat": -53.7833333, "lng": -67.7, "region": "Tierra del Fuego"},
    "VILLA GESELL": {"lat": -37.2627778, "lng": -56.9638889, "region": "Provincia de Buenos Aires"},
    "PINAMAR": {"lat": -37.1069444, "lng": -56.8575, "region": "Provincia de Buenos Aires"},
    "MIRAMAR": {"lat": -38.2772222, "lng": -57.8338889, "region": "Provincia de Buenos Aires"},
}

_ZONDA_REGIONES = {"SAN JUAN", "LA RIOJA", "SAN LUIS", "MENDOZA", "NEUQUÉN", "NEUQUEN", "RÍO NEGRO", "RIO NEGRO"}


def _env_int(name, default):
    raw = os.environ.get(name)
    if raw is None:
        return int(default)
    try:
        return int(str(raw).strip())
    except (ValueError, TypeError):
        return int(default)


def _get_config(name, default=None):
    try:
        return current_app.config.get(name, default)
    except Exception:
        return default


def _get_ttl_seconds():
    return int(_get_config("WEATHER_CACHE_TTL_SECONDS") or
               _env_int("WEATHER_CACHE_TTL_SECONDS", _WEATHER_CACHE_TTL_SECONDS_DEFAULT))


def get_center_coordinates(center_name):
    """Retorna {lat, lng, region} para un centro. Busca primero override por ENV/Config,
    luego catálogo hardcodeado normalizado, y finalmente None si no encuentra."""
    raw = (center_name or "").strip()
    if not raw:
        return None

    def _norm(s):
        s = (s or "").upper()
        s = s.replace(".", "").replace(",", " ")
        s = s.replace("-", " ").replace("_", " ").replace("–", " ").replace("—", " ")
        s = s.replace("Á", "A").replace("É", "E").replace("Í", "I").replace("Ó", "O").replace("Ú", "U")
        s = s.replace("Ñ", "N")
        tokens = []
        for t in s.split():
            if t == "MZA":
                tokens.append("MENDOZA")
            elif t == "CORDOBA":
                tokens.append("CORDOBA")
                tokens.append("CAPITAL")
            elif t == "TUCUMAN":
                tokens.append("TUCUMAN")
            else:
                tokens.append(t)
        return " ".join(tokens)

    normalized = _norm(raw)
    norm_tokens = [t for t in normalized.split() if t not in {"DE", "EL", "LA", "LOS", "LAS", "DEL", "E", "Y", "AL", "UN"}]

    override = _CENTER_COORDINATES_OVERRIDE or _get_config("WEATHER_CENTER_COORDINATES") or {}
    if isinstance(override, dict):
        if normalized in override:
            return override[normalized]
        for key, val in override.items():
            if _norm(key) == normalized and isinstance(val, dict):
                return val

    if normalized in _DEFAULT_CENTER_COORDINATES:
        return _DEFAULT_CENTER_COORDINATES[normalized]

    for key, val in _DEFAULT_CENTER_COORDINATES.items():
        if key == normalized:
            return val
        key_norm = _norm(key)
        if key_norm == normalized:
            return val
        if set(key_norm.split()) == set(norm_tokens):
            return val
        if norm_tokens and all(t in key_norm.split() for t in norm_tokens):
            return val
        if key_norm and all(t in norm_tokens for t in key_norm.split()):
            return val
        if key in raw.upper() or raw.upper() in key:
            return val

    return None


def set_center_coordinates_override(override_dict):
    """Permite cargar coordenadas desde imports en runtime sin modificar este archivo."""
    global _CENTER_COORDINATES_OVERRIDE
    _CENTER_COORDINATES_OVERRIDE = dict(override_dict or {})


def weather_label(code):
    c = int(code or 0)
    return _WEATHER_CODE_LABELS.get(c, _WEATHER_CODE_LABELS.get(0, "Desconocido"))


def weather_icon(code):
    c = int(code or 0)
    return _WEATHER_CODE_ICON.get(c, "🌡️")


def _is_zonda_candidate(region_name):
    if not region_name:
        return False
    norm = " ".join(str(region_name).upper().replace("Í", "I").replace("Ó", "O").split())
    return norm in _ZONDA_REGIONES or any(z in norm for z in _ZONDA_REGIONES)


def _evaluate_risk(current, region_name=None, zonda_wind_threshold_kmh=None):
    """Recibe un dict 'current' con keys al estilo open-meteo current:
       temperature_2m, relative_humidity_2m, precipitation, weather_code, wind_speed_10m
    Retorna dict {risk_level, risk_label, blocks_installation, reasons:[], temp_c, humidity, precip_mm, wind_kmh, weather_label, weather_icon}
    """
    thresholds = {
        "precip_moderate_mm": float(_get_config("WEATHER_PRECIP_MODERATE_MM") or _env_int("WEATHER_PRECIP_MODERATE_MM", 3)),
        "precip_block_mm": float(_get_config("WEATHER_PRECIP_BLOCK_MM") or _env_int("WEATHER_PRECIP_BLOCK_MM", 8)),
        "snow_block_cm": float(_get_config("WEATHER_SNOW_BLOCK_CM") or _env_int("WEATHER_SNOW_BLOCK_CM", 3)),
        "wind_block_kmh": float(_get_config("WEATHER_WIND_BLOCK_KMH") or _env_int("WEATHER_WIND_BLOCK_KMH", 70)),
        "zonda_wind_block_kmh": float(zonda_wind_threshold_kmh or _get_config("WEATHER_ZONDA_WIND_BLOCK_KMH") or _env_int("WEATHER_ZONDA_WIND_BLOCK_KMH", 50)),
    }
    current = current or {}

    def _f(v, default=0.0):
        try:
            if v is None:
                return default
            fv = float(v)
            if fv != fv:  # NaN
                return default
            return fv
        except (TypeError, ValueError):
            return default

    temp_raw = current.get("temperature_2m")
    humidity_raw = current.get("relative_humidity_2m")
    temp_c = None if temp_raw is None else float(temp_raw)
    humidity = None if humidity_raw is None else int(round(float(humidity_raw)))
    precip_mm = _f(current.get("precipitation"))
    snow_cm = _f(current.get("snowfall"))
    wind_kmh = _f(current.get("wind_speed_10m"))
    try:
        code = current.get("weather_code")
        if code is None:
            code = 0
        else:
            code = int(code)
    except (TypeError, ValueError):
        code = 0

    reasons = []
    risk_points = 0
    blocks_installation = False

    wlabel = weather_label(code)
    wicon = weather_icon(code)

    snow_codes = {71, 73, 75, 77, 85, 86}
    storm_codes = {95, 96, 99}
    heavy_rain_codes = {65, 67, 82}
    moderate_rain_codes = {55, 57, 63, 81}

    if code in storm_codes:
        risk_points += 5
        blocks_installation = True
        reasons.append("Tormenta eléctrica o granizo")
    if code in heavy_rain_codes or precip_mm >= thresholds["precip_block_mm"]:
        risk_points += 4
        blocks_installation = True
        reasons.append(f"Lluvia intensa ({precip_mm:.1f}mm)")
    if code in snow_codes or snow_cm >= thresholds["snow_block_cm"]:
        risk_points += 5
        blocks_installation = True
        reasons.append(f"Nevada ({snow_cm:.1f}cm)")
    if precip_mm >= thresholds["precip_moderate_mm"] and not blocks_installation:
        risk_points += 3
        reasons.append(f"Lluvia moderada ({precip_mm:.1f}mm)")
    if code in moderate_rain_codes and risk_points < 3:
        risk_points = max(risk_points, 2)

    is_zonda_region = _is_zonda_candidate(region_name)
    if is_zonda_region and wind_kmh >= thresholds["zonda_wind_block_kmh"]:
        risk_points += 5
        blocks_installation = True
        reasons.append(f"Viento Zonda fuerte ({wind_kmh:.0f} km/h)")
    elif wind_kmh >= thresholds["wind_block_kmh"]:
        risk_points += 4
        blocks_installation = True
        reasons.append(f"Viento muy fuerte ({wind_kmh:.0f} km/h)")
    elif is_zonda_region and wind_kmh >= (thresholds["zonda_wind_block_kmh"] * 0.7):
        risk_points = max(risk_points, 3)
        reasons.append(f"Alerta Viento Zonda ({wind_kmh:.0f} km/h)")

    if blocks_installation:
        risk_level = "critico"
        risk_label = "Critico"
    elif risk_points >= 5:
        risk_level = "critico"
        risk_label = "Critico"
    elif risk_points >= 3:
        risk_level = "medio"
        risk_label = "Precaucion"
    else:
        risk_level = "bajo"
        risk_label = "Operativo"

    return {
        "risk_level": risk_level,
        "risk_label": risk_label,
        "blocks_installation": bool(blocks_installation),
        "reasons": reasons,
        "temp_c": round(temp_c, 1) if temp_c is not None else None,
        "humidity": int(round(humidity)) if humidity is not None else None,
        "precip_mm": round(precip_mm, 1),
        "snow_cm": round(snow_cm, 1),
        "wind_kmh": int(round(wind_kmh)),
        "weather_code": code,
        "weather_label": wlabel,
        "weather_icon": wicon,
        "is_zonda_region": is_zonda_region,
    }


def _fetch_open_meteo(lat, lng, forecast_days=4):
    """Llama a Open-Meteo SINGLE location (compat). Para multi-location usar _fetch_open_meteo_batch."""
    out = _fetch_open_meteo_batch([(lat, lng)], forecast_days=forecast_days)
    if not out:
        raise RuntimeError("Empty batch response from Open-Meteo")
    return out


def _fetch_weatherapi_single_or_batch(locations, forecast_days=4):
    """WeatherAPI.com adapter: devuelve LISTA de [{current,daily,timezone}] en formato COMPATIBLE Open-Meteo
       para que luego el pipeline comun (normalization, _evaluate_risk, build_forecast_daily) procese igual.
    - Locations: [(lat, lng), ...]
    - Si WEATHERAPI_COM_KEY no existe -> lanza RuntimeError para que el caller haga fallback al Open-Meteo.
    - Por cada location hace 1 request GET current+forecast (FREE tier permite 1M/mes).
    """
    import os as _os
    api_key = None
    try:
        from flask import current_app
        api_key = (current_app.config.get("WEATHERAPI_COM_KEY") if current_app else None)
    except Exception:
        api_key = None
    if not api_key:
        try:
            api_key = _os.getenv("WEATHERAPI_COM_KEY") or None
        except Exception:
            api_key = None
    if not api_key:
        raise RuntimeError("WEATHERAPI_COM_KEY not configured; fallback to Open-Meteo")
    fd = max(1, min(7, int(forecast_days)))
    out = []
    headers = {"User-Agent": "SoftBerardi-Weather/1.3 (+https://atbb.onrender.com)",
               "Accept": "application/json"}
    last_exc = None
    for (lat, lng) in locations:
        params = urllib.parse.urlencode({
            "key": api_key,
            "q": f"{float(lat):.5f},{float(lng):.5f}",
            "days": fd,
            "aqi": "no",
            "alerts": "no",
        })
        url = f"https://api.weatherapi.com/v1/forecast.json?{params}"
        try:
            raw = _http_get_json(url, headers, timeout=20)
        except Exception as e:
            last_exc = e
            out.append({"current": {}, "daily": {}, "timezone": None})
            continue
        if not isinstance(raw, dict):
            out.append({"current": {}, "daily": {}, "timezone": None})
            continue
        cur = raw.get("current") if isinstance(raw.get("current"), dict) else {}
        fc = raw.get("forecast") if isinstance(raw.get("forecast"), dict) else {}
        fcdays = fc.get("forecastday") if isinstance(fc.get("forecastday"), list) else []
        loc = raw.get("location") if isinstance(raw.get("location"), dict) else {}
        tz = loc.get("tz_id") if isinstance(loc, dict) else None

        def _cp(v, default=None):
            return v if v is not None else default

        weather_code_om = 0
        weather_label = ""
        if isinstance(cur.get("condition"), dict):
            condition = cur["condition"]
            code_wa = int(condition.get("code") or 0)
            text_wa = str(condition.get("text") or "")
            weather_label = text_wa
            weather_code_om = _weatherapi_code_to_om(code_wa, text_wa)
        precip_mm = _cp(cur.get("precip_mm"), 0.0)
        snow_cm = 0.0
        wind_kmh = _cp(cur.get("wind_kph"), 0.0)
        temp_c = _cp(cur.get("temp_c"), 0.0)
        humidity = _cp(cur.get("humidity"), 0)
        current_om = {
            "temperature_2m": float(temp_c),
            "relative_humidity_2m": float(humidity),
            "precipitation": float(precip_mm),
            "snowfall": float(snow_cm),
            "weather_code": int(weather_code_om),
            "wind_speed_10m": float(wind_kmh),
        }
        daily_om = {
            "time": [],
            "weather_code": [],
            "temperature_2m_max": [],
            "temperature_2m_min": [],
            "precipitation_sum": [],
            "snowfall_sum": [],
            "wind_speed_10m_max": [],
            "precipitation_probability_max": [],
        }
        for d in fcdays:
            if not isinstance(d, dict): continue
            daily_om["time"].append(d.get("date") or "")
            day = d.get("day") if isinstance(d.get("day"), dict) else {}
            dcond = day.get("condition") if isinstance(day.get("condition"), dict) else {}
            code_wa_d = int((dcond or {}).get("code") or 0)
            text_wa_d = str((dcond or {}).get("text") or "")
            daily_om["weather_code"].append(int(_weatherapi_code_to_om(code_wa_d, text_wa_d)))
            daily_om["temperature_2m_max"].append(float(day.get("maxtemp_c") or 0.0))
            daily_om["temperature_2m_min"].append(float(day.get("mintemp_c") or 0.0))
            daily_om["precipitation_sum"].append(float(day.get("totalprecip_mm") or 0.0))
            daily_om["snowfall_sum"].append(float(day.get("totalsnow_cm") or 0.0))
            daily_om["wind_speed_10m_max"].append(float(day.get("maxwind_kph") or 0.0))
            daily_om["precipitation_probability_max"].append(int(day.get("daily_chance_of_rain") or 0))
        out.append({"current": current_om, "daily": daily_om, "timezone": tz,
                    "_wa_weather_label": weather_label})
    if not out and last_exc:
        raise last_exc
    return out


def _weatherapi_code_to_om(wa_code, wa_text=""):
    """Mapeo WeatherAPI condition code -> WMO-like Open-Meteo weather code
       (para que la regla _evaluate_risk detecte bloqueos por WMO 95+ tormenta etc).
    """
    # Tormenta fuerte / con truenos / granizo -> 95/96/99
    if wa_code in (1087, 1273, 1276, 1279, 1282):
        return 95 if wa_code in (1087, 1273) else 99
    # Nieve fuerte -> 86/88
    if wa_code in (1066, 1210, 1213, 1216, 1219, 1222, 1225, 1255, 1258, 1261, 1264):
        return 86 if wa_code in (1210, 1213, 1066) else 88
    # Lluvia pesada / chubascos fuertes -> 65/67/82
    if wa_code in (1153, 1180, 1183, 1186, 1189, 1192, 1195, 1198, 1201, 1204, 1207, 1240, 1243, 1246, 1249, 1252):
        if wa_code in (1195, 1246, 1201):
            return 65
        if wa_code in (1243, 1189, 1192):
            return 82
        return 61
    # Niebla / neblina -> 45/48
    if wa_code in (1003, 1006, 1009, 1030, 1135, 1147):
        return 45 if wa_code in (1030, 1135) else 48
    # Nubes / parcial nublado -> 1/2/3
    if wa_code == 1000:
        return 0
    if wa_code == 1003:
        return 1
    if wa_code == 1006:
        return 2
    if wa_code == 1009:
        return 3
    # Llovizna / lluvia ligera -> 51/53/55 / 61
    if wa_code in (1063, 1072, 1150, 1153, 1168, 1171, 1180, 1183, 1186, 1189):
        return 51 if wa_code in (1150, 1072) else 61
    # lluvia muy ligera o frizzling -> 51
    # Por ultimo text heuristica
    t = (wa_text or "").lower()
    if any(k in t for k in ("tormenta", "thunder", "storm")): return 95
    if any(k in t for k in ("nieve", "snow")): return 86
    if any(k in t for k in ("lluvia fuerte", "heavy rain", "downpour")): return 65
    if any(k in t for k in ("lluvia", "rain", "shower")): return 61
    if any(k in t for k in ("niebla", "fog", "mist")): return 45
    if any(k in t for k in ("nublado", "cloud")): return 2
    if any(k in t for k in ("soleado", "sunny", "clear")): return 0
    return 3


def _fetch_open_meteo_batch(locations, forecast_days=4):
    """Llama a Open-Meteo BATCH endpoint (una sola HTTP call para N locations <=100).
    locations: [(lat, lng), ...]
    Retorna list[dict] en el mismo orden, cada uno con keys 'current' y 'daily' igual que el endpoint single.
    """
    if not locations:
        return []
    locations = list(locations)
    if len(locations) > 100:
        chunked = []
        for i in range(0, len(locations), 100):
            chunked.extend(_fetch_open_meteo_batch(locations[i:i+100], forecast_days=forecast_days))
        return chunked

    lats_str = ",".join([f"{float(lat):.5f}" for lat, _ in locations])
    lngs_str = ",".join([f"{float(lng):.5f}" for _, lng in locations])
    fd = max(1, min(7, int(forecast_days)))
    params_dict = {
        "latitude": lats_str,
        "longitude": lngs_str,
        "current": ",".join([
            "temperature_2m",
            "relative_humidity_2m",
            "precipitation",
            "weather_code",
            "wind_speed_10m",
            "snowfall",
        ]),
        "daily": ",".join([
            "weather_code",
            "temperature_2m_max",
            "temperature_2m_min",
            "precipitation_sum",
            "snowfall_sum",
            "wind_speed_10m_max",
            "precipitation_probability_max",
        ]),
        "timezone": "auto",
        "forecast_days": fd,
    }
    api_key = None
    try:
        from flask import current_app
        api_key = current_app.config.get("WEATHER_OPEN_METEO_API_KEY") if current_app else None
    except Exception:
        api_key = None
    if not api_key:
        try:
            import os as _os
            api_key = _os.getenv("WEATHER_OPEN_METEO_API_KEY") or None
        except Exception:
            api_key = None
    if api_key:
        params_dict["apikey"] = api_key
        base_host = "customer-api.open-meteo.com"
    else:
        base_host = "api.open-meteo.com"
    params = urllib.parse.urlencode(params_dict)
    url = f"https://{base_host}/v1/forecast?{params}"
    headers = {"User-Agent": "SoftBerardi-Weather/1.2 (+https://atbb.onrender.com)",
               "Accept": "application/json"}

    last_exc = None
    for attempt in range(2):
        try:
            raw = _http_get_json(url, headers, timeout=20)
            if not raw:
                raise RuntimeError("Empty response from Open-Meteo")
            break
        except urllib.error.HTTPError as he:
            last_exc = he
            # NO HACER time.sleep() aqui: Gunicorn/Render tiene timeout 30s y
            # cualquier sleep largo mata el worker (WORKER TIMEOUT -> 500).
            # Los reintentos pasan por TTL cache de errores (5 min) en el
            # proximo request del usuario.
            if he.code == 429 and attempt == 0:
                try:
                    current_app.logger.info(
                        f"weather: 429 attempt {attempt+1}; retry inline quick without sleep, "
                        "then defer next retry to next request via error cache TTL."
                    )
                except Exception:
                    pass
                continue
            raise
        except Exception as e:
            last_exc = e
            if attempt == 0:
                continue
            raise
    else:
        raise last_exc if last_exc else RuntimeError("Open-Meteo batch fetch failed")

    n = len(locations)
    out = []
    for idx in range(n):
        if not isinstance(raw, dict):
            out.append({"current": {}, "daily": {}, "timezone": None})
            continue
        current = raw.get("current") if isinstance(raw.get("current"), dict) else {}
        daily = raw.get("daily") if isinstance(raw.get("daily"), dict) else {}
        is_batch = isinstance(current.get("temperature_2m"), list) if current else False
        if is_batch:
            cur_single = {}
            for k, v in current.items():
                cur_single[k] = v[idx] if isinstance(v, list) and len(v) > idx else None
            daily_single = {}
            for k, v in daily.items():
                if isinstance(v, list):
                    if len(v) == 0:
                        daily_single[k] = []
                    elif isinstance(v[0], list):
                        daily_single[k] = v[idx] if len(v) > idx else []
                    else:
                        daily_single[k] = v
                else:
                    daily_single[k] = v
            tz = raw.get("timezone")
            if isinstance(tz, list):
                tz = tz[idx] if len(tz) > idx else None
            out.append({"current": cur_single, "daily": daily_single, "timezone": tz})
        else:
            tz = raw.get("timezone")
            if isinstance(tz, list):
                tz = tz[idx] if len(tz) > idx else None
            out.append({"current": current, "daily": daily, "timezone": tz})
    return out


def _http_get_json(url, headers, timeout=25):
    """Primero urllib, fallback requests si está disponible."""
    last_exc = None
    # 1) urllib stdlib
    try:
        req = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            code = getattr(resp, "status", None) or resp.getcode() or 200
            if code >= 400:
                raise urllib.error.HTTPError(url, code, "", resp.headers, None)
            raw_bytes = resp.read()
        return json.loads(raw_bytes.decode("utf-8"))
    except Exception as exc:
        last_exc = exc
    # 2) fallback requests opcional
    try:
        import requests  # noqa: WPS433
        r = requests.get(url, headers=headers, timeout=timeout)
        r.raise_for_status()
        return r.json()
    except Exception:
        pass
    raise last_exc


_WEATHER_TABLE_ENSURED_KEY = "__center_weather_cache_ensured__"


def _ensure_center_weather_cache_table():
    """Garantiza que center_weather_cache exista, sin depender de init_db().
    Idempotente: chequea app_ctx globals para no correr en cada request.
    """
    try:
        from flask import g as flask_g
    except Exception:
        flask_g = None
    try:
        from app.models import get_db, is_postgres
    except Exception:
        return False
    if flask_g is not None:
        already = getattr(flask_g, _WEATHER_TABLE_ENSURED_KEY, False)
        if already:
            return True
    try:
        db = get_db()
        if is_postgres():
            try:
                db.execute("ROLLBACK")
            except Exception:
                pass
            cur = db.execute(
                """
                SELECT EXISTS (
                    SELECT 1 FROM information_schema.tables
                    WHERE table_schema = 'public' AND table_name = 'center_weather_cache'
                ) AS exists_
                """
            )
            row = cur.fetchone()
            exists = bool(row and (row.get("exists_") or row[0] if isinstance(row, (list, tuple)) else row.get("exists_")))
            if not exists:
                db.execute(
                    """
                    CREATE TABLE IF NOT EXISTS center_weather_cache (
                        id SERIAL PRIMARY KEY,
                        center_name TEXT NOT NULL,
                        region TEXT,
                        weather_date DATE NOT NULL,
                        raw_json TEXT NOT NULL,
                        updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                        UNIQUE(center_name, weather_date)
                    )
                    """
                )
                try:
                    db.commit()
                except Exception:
                    try: db.execute("ROLLBACK")
                    except Exception: pass
        else:
            db.execute(
                """
                CREATE TABLE IF NOT EXISTS center_weather_cache (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    center_name TEXT NOT NULL,
                    region TEXT,
                    weather_date TEXT NOT NULL,
                    raw_json TEXT NOT NULL,
                    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    UNIQUE(center_name, weather_date)
                )
                """
            )
            try:
                db.commit()
            except Exception:
                pass
        if flask_g is not None:
            setattr(flask_g, _WEATHER_TABLE_ENSURED_KEY, True)
        return True
    except Exception:
        try:
            current_app.logger.exception("weather: _ensure_center_weather_cache_table failed")
        except Exception:
            pass
        return False


def build_forecast_daily(raw_daily, region_name=None):
    if not raw_daily or not isinstance(raw_daily, dict):
        return []
    times = raw_daily.get("time") or []
    codes = raw_daily.get("weather_code") or []
    tmax = raw_daily.get("temperature_2m_max") or []
    tmin = raw_daily.get("temperature_2m_min") or []
    precip = raw_daily.get("precipitation_sum") or []
    snow = raw_daily.get("snowfall_sum") or []
    wind_max = raw_daily.get("wind_speed_10m_max") or []
    prob = raw_daily.get("precipitation_probability_max") or []
    out = []
    for idx in range(len(times)):
        synthetic_current = {
            "temperature_2m": ((tmax[idx] if idx < len(tmax) else 0) + (tmin[idx] if idx < len(tmin) else 0)) / 2.0,
            "relative_humidity_2m": None,
            "precipitation": precip[idx] if idx < len(precip) else 0,
            "snowfall": snow[idx] if idx < len(snow) else 0,
            "weather_code": codes[idx] if idx < len(codes) else 0,
            "wind_speed_10m": wind_max[idx] if idx < len(wind_max) else 0,
        }
        risk = _evaluate_risk(synthetic_current, region_name=region_name)
        out.append({
            "date": times[idx] if idx < len(times) else None,
            "risk_level": risk["risk_level"],
            "risk_label": risk["risk_label"],
            "blocks_installation": risk["blocks_installation"],
            "weather_code": risk["weather_code"],
            "weather_label": risk["weather_label"],
            "weather_icon": risk["weather_icon"],
            "temp_max_c": round(tmax[idx], 1) if idx < len(tmax) and tmax[idx] is not None else None,
            "temp_min_c": round(tmin[idx], 1) if idx < len(tmin) and tmin[idx] is not None else None,
            "precip_sum_mm": round(precip[idx], 1) if idx < len(precip) and precip[idx] is not None else 0,
            "snow_sum_cm": round(snow[idx], 1) if idx < len(snow) and snow[idx] is not None else 0,
            "wind_max_kmh": int(round(wind_max[idx])) if idx < len(wind_max) and wind_max[idx] is not None else 0,
            "precip_prob_pct": int(round(prob[idx])) if idx < len(prob) and prob[idx] is not None else None,
            "reasons": risk["reasons"],
        })
    return out


def _load_cached_report(center_name, weather_date, ttl_seconds, log_suffix=""):
    """Lee cache DB.

    ttl_seconds: si el payload es OK usa este; si es ERROR usa el effective_ttl
    calculado internamente (WEATHER_ERROR_TTL_SECONDS).
    """
    try:
        from app.models import get_db, is_postgres
    except Exception:
        return None
    _ensure_center_weather_cache_table()
    try:
        placeholder = "%s" if is_postgres() else "?"
        db = get_db()
        if is_postgres():
            try:
                db.execute("ROLLBACK")
            except Exception:
                pass
        rows = db.execute(
            f"""
            SELECT id, center_name, region, weather_date, raw_json, updated_at
            FROM center_weather_cache
            WHERE center_name = {placeholder} AND weather_date = {placeholder}
            ORDER BY updated_at DESC
            LIMIT 1
            """,
            (center_name, weather_date),
        ).fetchall()
        if not rows:
            return None
        row = rows[0]
        updated_at_raw = row["updated_at"]
        if not updated_at_raw:
            return None
        updated_ts = None
        try:
            if hasattr(updated_at_raw, "timestamp"):
                dt_aware = updated_at_raw if getattr(updated_at_raw, "tzinfo", None) else updated_at_raw.replace(tzinfo=timezone.utc)
                updated_ts = float(dt_aware.astimezone(timezone.utc).timestamp())
            else:
                s = str(updated_at_raw).strip()
                s_norm = s.replace("Z", "+00:00")
                if s_norm.endswith("+00:00") is False and "+" not in s_norm[10:] and "-" not in s_norm[10:]:
                    s_norm = s_norm + "+00:00"
                dt = datetime.fromisoformat(s_norm)
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=timezone.utc)
                updated_ts = float(dt.astimezone(timezone.utc).timestamp())
        except Exception:
            updated_ts = None
        if updated_ts is None:
            return None
        payload = None
        try:
            raw = row["raw_json"]
            if isinstance(raw, str):
                payload = json.loads(raw)
            else:
                payload = raw
        except Exception:
            return None
        configured_ok_ttl = int(ttl_seconds or _WEATHER_CACHE_TTL_SECONDS_DEFAULT)
        configured_error_ttl = int(
            _get_config("WEATHER_ERROR_TTL_SECONDS") or
            _env_int("WEATHER_ERROR_TTL_SECONDS", _WEATHER_ERROR_TTL_SECONDS_DEFAULT)
        )
        is_error_payload = bool(payload and payload.get("error"))
        effective_ttl = configured_error_ttl if is_error_payload else configured_ok_ttl
        if is_error_payload:
            effective_ttl = int(payload.get("_error_ttl_seconds") or configured_error_ttl)
        age = time.time() - updated_ts
        is_expired = age > effective_ttl
        if is_expired:
            try:
                current_app.logger.info(
                    "weather cache EXPIRED center=%s age=%.1fs ttl=%ds error=%s%s",
                    center_name, age, effective_ttl, is_error_payload, log_suffix,
                )
            except Exception:
                pass
            return None
        return payload
    except Exception:
        try:
            current_app.logger.exception("weather: no se pudo leer cache")
        except Exception:
            pass
        return None


def _save_cached_report(center_name, region, weather_date, payload, ttl_seconds=None):
    try:
        from app.models import get_db, is_postgres
    except Exception:
        return None
    _ensure_center_weather_cache_table()
    try:
        payload_json = json.dumps(payload, ensure_ascii=False)
        db = get_db()
        if is_postgres():
            try:
                db.execute("ROLLBACK")
            except Exception:
                pass
        if is_postgres():
            cur = db.execute(
                """
                INSERT INTO center_weather_cache
                    (center_name, region, weather_date, raw_json, updated_at)
                VALUES (%s,%s,%s,%s,NOW())
                ON CONFLICT (center_name, weather_date)
                DO UPDATE SET
                    region = EXCLUDED.region,
                    raw_json = EXCLUDED.raw_json,
                    updated_at = NOW()
                RETURNING id
                """,
                (center_name, region, weather_date, payload_json),
            )
            try:
                db.commit()
            except Exception:
                try:
                    db.execute("ROLLBACK")
                except Exception:
                    pass
                raise
            try:
                return cur.fetchone()["id"]
            except Exception:
                return None
        else:
            db.execute(
                """
                INSERT OR REPLACE INTO center_weather_cache
                    (center_name, region, weather_date, raw_json, updated_at)
                VALUES (?,?,?,?,CURRENT_TIMESTAMP)
                """,
                (center_name, region, weather_date, payload_json),
            )
            db.commit()
    except Exception:
        try:
            current_app.logger.exception("weather: no se pudo guardar cache")
        except Exception:
            pass
        return None


def get_center_weather_report(center_name, supervisor_scope_names=None, force_refresh=False):
    """Retorna el reporte climático para un centro.
    Cache:
      - DB (center_weather_cache) TTL configurable.
      - Fallback: llamada HTTP a Open-Meteo.
    Si supervisor_scope_names está definido: sólo evalúa centros cuyo supervisor esté en el scope.
    """
    coords = get_center_coordinates(center_name)
    if not coords:
        return None

    region = coords.get("region")
    lat = coords["lat"]
    lng = coords["lng"]

    today = _today_arg_iso()
    ttl = _get_ttl_seconds()
    cached = None if force_refresh else _load_cached_report(center_name, today, ttl)
    if cached and not cached.get("error"):
        return cached

    fallback_on_error = cached and cached.get("error") is None

    payload = {
        "center_name": center_name,
        "region": region,
        "weather_date": today,
        "latitude": lat,
        "longitude": lng,
        "fetched_at_epoch": int(time.time()),
        "current": None,
        "forecast_daily": [],
        "error": None,
    }
    error_ttl = int(_get_config("WEATHER_ERROR_TTL_SECONDS") or
               _env_int("WEATHER_ERROR_TTL_SECONDS", _WEATHER_ERROR_TTL_SECONDS_DEFAULT))
    try:
        raw = _fetch_open_meteo(lat, lng, forecast_days=4)
        current_raw = raw.get("current") or {}
        daily_raw = raw.get("daily") or {}
        if not current_raw and fallback_on_error:
            return cached
        current_eval = _evaluate_risk(current_raw, region_name=region)
        payload["current"] = current_eval
        payload["forecast_daily"] = build_forecast_daily(daily_raw, region_name=region)
        payload["timezone"] = raw.get("timezone")
    except Exception as exc:
        try:
            current_app.logger.warning(f"weather: error fetching open-meteo for {center_name}: {exc}")
        except Exception:
            pass
        payload["error"] = f"API indisponible: {exc}"
        payload["_error_ttl_seconds"] = error_ttl
        if fallback_on_error:
            return cached

    if payload.get("error"):
        _save_cached_report(center_name, region, today, payload, ttl_seconds=error_ttl)
    else:
        _save_cached_report(center_name, region, today, payload, ttl_seconds=ttl)
    return payload


def summarize_centers_weather(center_names, supervisor_scope_names=None):
    """Recibe una lista de nombres de centros. Retorna dict con:
      - critically_blocked: lista de reportes con blocks_installation=True
      - caution: lista con risk_level='medio'
      - operative: lista con risk_level='bajo'
      - totals: {critico, medio, bajo}
      - unresolved_centers: centros sin coordenadas en el catálogo

    Optimizacion clave: SOLO hace 1 SOLA llamada HTTP (batch) para los centros
    que NO tienen cache valido. Nunca N llamadas HTTP simultaneas (evita 429).
    """
    critical = []
    caution = []
    operative = []
    unresolved = []
    today = _today_arg_iso()
    ttl_ok = _get_ttl_seconds()
    error_ttl = int(_get_config("WEATHER_ERROR_TTL_SECONDS") or
               _env_int("WEATHER_ERROR_TTL_SECONDS", _WEATHER_ERROR_TTL_SECONDS_DEFAULT))

    seen = {}
    todo_fetch = []
    seen_order = []

    for name in center_names:
        n = " ".join((name or "").strip().split())
        if not n or n in seen:
            continue
        seen[n] = None
        seen_order.append(n)
        coords = get_center_coordinates(n)
        if not coords:
            unresolved.append(n)
            continue
        region = coords.get("region")
        lat, lng = coords["lat"], coords["lng"]
        cached = _load_cached_report(n, today, ttl_ok)
        if cached is not None:
            if not cached.get("error"):
                seen[n] = cached
                continue
            if cached.get("error"):
                seen[n] = cached
                continue
        todo_fetch.append((n, name, region, lat, lng))

    n_total_centers = len(seen_order)
    n_cached_ok_err = sum(
        1 for n in seen_order
        if isinstance(seen.get(n), dict) and (
            (seen[n].get("current") and not seen[n].get("error")) or
            seen[n].get("error")
        )
    )

    batch_allowed = True
    if todo_fetch and n_total_centers >= 5:
        already_cached_ratio = (n_cached_ok_err + (n_total_centers - (n_cached_ok_err + len(todo_fetch) + len(unresolved)))) / max(1, n_total_centers)
        if already_cached_ratio >= 0.5 and len(todo_fetch) > 0:
            try:
                current_app.logger.info(
                    "weather: skipping HTTP batch por doppelganger guard (cached_ratio=%.2f todo_fetch=%d total=%d). Usamos cached_error existente.",
                    already_cached_ratio, len(todo_fetch), n_total_centers,
                )
            except Exception:
                pass
            batch_allowed = False

    batch_exception_logged = False
    if todo_fetch and batch_allowed:
        locations = [(lat, lng) for (_, _, _, lat, lng) in todo_fetch]
        batch_raws = []
        batch_err = None
        try:
            try:
                batch_raws = _fetch_weatherapi_single_or_batch(locations, forecast_days=4)
                try:
                    current_app.logger.info(f"weather: provider=weatherapi.com OK {len(batch_raws)} centers fetch success.")
                except Exception:
                    pass
            except RuntimeError:
                # WEATHERAPI_COM_KEY no configurado: fallback al pipeline Open-Meteo.
                try:
                    from flask import current_app as _capp
                    om_key = _capp.config.get("WEATHER_OPEN_METEO_API_KEY") if _capp else None
                except Exception:
                    om_key = None
                try:
                    import os as _os
                    if not om_key:
                        om_key = _os.getenv("WEATHER_OPEN_METEO_API_KEY") or None
                except Exception:
                    pass
                if om_key:
                    try:
                        current_app.logger.info("weather: provider=open-meteo-customer via apikey")
                    except Exception:
                        pass
                else:
                    try:
                        current_app.logger.info("weather: provider=open-meteo-anonymous (sujeto a ban Render IP)")
                    except Exception:
                        pass
                batch_raws = _fetch_open_meteo_batch(locations, forecast_days=4)
        except Exception as exc:
            try:
                if not batch_exception_logged:
                    current_app.logger.warning(f"weather: batch fetch fail for {len(locations)} centers: {exc}")
                    batch_exception_logged = True
            except Exception:
                pass
            batch_err = f"API indisponible: {exc}"
    else:
        batch_err = "Skipped por cache TTL / doppelganger guard; reintento en proximo request."
        batch_raws = None

    if todo_fetch and not batch_allowed:
        for (norm_name, orig_name, region, lat, lng) in todo_fetch:
            payload = {
                "center_name": orig_name,
                "region": region,
                "weather_date": today,
                "latitude": lat,
                "longitude": lng,
                "fetched_at_epoch": int(time.time()),
                "current": None,
                "forecast_daily": [],
                "error": batch_err,
                "_error_ttl_seconds": error_ttl,
            }
            seen[norm_name] = payload
            _save_cached_report(norm_name, region, today, payload, ttl_seconds=error_ttl)
        todo_fetch = []

    for idx, (norm_name, orig_name, region, lat, lng) in enumerate(todo_fetch):
        payload = {
            "center_name": orig_name,
            "region": region,
            "weather_date": today,
            "latitude": lat,
            "longitude": lng,
            "fetched_at_epoch": int(time.time()),
            "current": None,
            "forecast_daily": [],
            "error": None,
        }
        parse_fail = False
        if batch_err is None and batch_raws is not None and idx < len(batch_raws):
            try:
                raw = batch_raws[idx]
                if not isinstance(raw, dict):
                    parse_fail = True
                    raise ValueError(f"batch_raws[{idx}] no es dict: {type(raw).__name__} -> {raw!r}")
                current_raw = raw.get("current") if isinstance(raw.get("current"), dict) else {}
                daily_raw = raw.get("daily") if isinstance(raw.get("daily"), dict) else {}
                tz_raw = raw.get("timezone")
                current_eval = _evaluate_risk(current_raw, region_name=region)
                wa_label = raw.get("_wa_weather_label")
                if wa_label and isinstance(current_eval, dict) and not current_eval.get("weather_label"):
                    current_eval["weather_label"] = wa_label
                payload["current"] = current_eval
                payload["forecast_daily"] = build_forecast_daily(daily_raw, region_name=region)
                payload["timezone"] = tz_raw
                if isinstance(payload["current"], dict) and not payload["current"].get("blocks_installation"):
                    ok_keys = {"temperature_c", "humidity_pct", "precip_mm", "wind_kmh", "weather_code", "weather_label"}
                    if not any(k in payload["current"] for k in ok_keys) and not payload["current"].get("reasons"):
                        parse_fail = True
            except Exception as inner:
                try:
                    current_app.logger.warning(
                        "weather: parseo batch_raws[%d] (%s) falla: %s -> fallback error payload",
                        idx, orig_name, str(inner), exc_info=False,
                    )
                except Exception:
                    pass
                parse_fail = True
        if parse_fail:
            payload["error"] = "Datos meteorológicos inválidos; reintento en próxima hora."
            payload["_error_ttl_seconds"] = error_ttl
        elif batch_err is not None:
            payload["error"] = batch_err or "Sin datos meteorológicos"
            payload["_error_ttl_seconds"] = error_ttl
        if payload.get("error"):
            _save_cached_report(norm_name, region, today, payload, ttl_seconds=error_ttl)
        else:
            _save_cached_report(norm_name, region, today, payload, ttl_seconds=ttl_ok)
        seen[norm_name] = payload

    for n in seen_order:
        val = seen.get(n)
        if not isinstance(val, dict):
            continue
        cur = val.get("current") or {}
        if val.get("error"):
            operative.append(val)
        elif cur.get("blocks_installation"):
            critical.append(val)
        elif cur.get("risk_level") == "medio":
            caution.append(val)
        else:
            operative.append(val)

    def _sort_key(r):
        cur = r.get("current") or {}
        reasons_penalty = -len(cur.get("reasons", []))
        wind = cur.get("wind_kmh") or 0
        precip = cur.get("precip_mm") or 0
        return (reasons_penalty, -(wind + precip))

    critical.sort(key=_sort_key)
    caution.sort(key=_sort_key)
    operative.sort(key=lambda r: (r.get("region") or "", r.get("center_name") or ""))

    return {
        "critically_blocked": critical,
        "caution": caution,
        "operative": operative,
        "totals": {
            "critico": len(critical),
            "medio": len(caution),
            "bajo": len(operative),
            "total": len(critical) + len(caution) + len(operative),
        },
        "unresolved_centers": unresolved,
        "generated_at": _now_arg().strftime("%H:%M hs."),
    }
