CHECKLIST_SECTIONS = [
    {
        "key": "seguridad",
        "title": "Elementos de Seguridad (EPP y Entorno)",
        "weight": 40,
        "items": [
            {"key": "casco", "label": "Uso de casco de seguridad", "critical": True},
            {"key": "guantes", "label": "Uso de guantes adecuados", "critical": True},
            {"key": "lentes", "label": "Uso de lentes de proteccion", "critical": False},
            {"key": "chaleco", "label": "Uso de chaleco reflectante", "critical": True},
            {"key": "botas", "label": "Uso de botas de seguridad", "critical": True},
            {"key": "senalizacion", "label": "Senalizacion del area de trabajo", "critical": True},
            {"key": "orden_entorno", "label": "Orden y limpieza del entorno", "critical": False},
        ],
    },
    {
        "key": "herramientas",
        "title": "Estado de Herramientas (Kit de Fibra Optica)",
        "weight": 35,
        "items": [
            {"key": "fusionadora", "label": "Fusionadora operativa", "critical": True},
            {"key": "cortadora", "label": "Cortadora de precision en buen estado", "critical": True},
            {"key": "peladora", "label": "Peladora de fibra funcional", "critical": False},
            {"key": "medidor", "label": "Medidor de potencia disponible", "critical": True},
            {"key": "limpieza", "label": "Kit de limpieza completo", "critical": False},
            {"key": "baterias", "label": "Baterias cargadas", "critical": False},
            {"key": "orden_kit", "label": "Maletin ordenado y completo", "critical": False},
            {
                "key": "cartuchera_herramientas",
                "label": "Cartuchera porta herramientas",
                "critical": False,
            },
            {
                "key": "cartuchera_destornilladores_mini",
                "label": "Cartuchera para destornilladores mini",
                "critical": False,
            },
        ],
    },
    {
        "key": "herramientas_mano",
        "title": "Herramientas de mano",
        "weight": 0,
        "items": [
            {
                "key": "mano_alicate_chico_aislado",
                "label": "280300103 - Alicate chico aislado a 1000V",
                "critical": False,
                "hand_tool": True,
                "material_code": "280300103",
                "evidence_required": False,
            },
            {
                "key": "mano_destornillador_ph_aislado",
                "label": "281300012 - Destornillador PH aislado Ø6x100mm",
                "critical": False,
                "hand_tool": True,
                "material_code": "281300012",
                "evidence_required": False,
            },
            {
                "key": "mano_destornillador_pl_aislado",
                "label": "281300013 - Destornillador PL aislado Ø6.5x150mm",
                "critical": False,
                "hand_tool": True,
                "material_code": "281300013",
                "evidence_required": False,
            },
            {
                "key": "mano_martillo_bolita_500",
                "label": "280700022 - Martillo de 500 grs bolita",
                "critical": False,
                "hand_tool": True,
                "material_code": "280700022",
                "evidence_required": False,
            },
            {
                "key": "mano_pinza_punta_aislada",
                "label": "280300101 - Pinza de punta aislada a 1000V",
                "critical": False,
                "hand_tool": True,
                "material_code": "280300101",
                "evidence_required": False,
            },
            {
                "key": "mano_pinza_peladora_claus",
                "label": "280300208 - Pinza peladora Claus CFS2",
                "critical": False,
                "hand_tool": True,
                "material_code": "280300208",
                "evidence_required": False,
            },
            {
                "key": "mano_pinza_universal_aislada",
                "label": "280300100 - Pinza universal aislada a 1000V",
                "critical": False,
                "hand_tool": True,
                "material_code": "280300100",
                "evidence_required": False,
            },
        ],
    },
    {
        "key": "vehiculo",
        "title": "Estado del Vehiculo",
        "weight": 25,
        "items": [
            {"key": "documentacion", "label": "Documentacion vigente", "critical": True},
            {"key": "oblea_gnc", "label": "Oblea de GNC vigente", "critical": True},
            {"key": "rto", "label": "RTO vigente", "critical": True},
            {"key": "neumaticos", "label": "Neumaticos en buen estado", "critical": True},
            {"key": "luces", "label": "Luces operativas", "critical": True},
            {"key": "extintor", "label": "Extintor vigente", "critical": True},
            {"key": "botiquin", "label": "Botiquin disponible", "critical": False},
            {"key": "elementos_emergencia", "label": "Elementos de emergencia disponibles", "critical": True},
            {"key": "carga_segura", "label": "Escalera y herramientas aseguradas", "critical": True},
            {
                "key": "escalera_aluminio_extensible",
                "label": "Escalera de aluminio extensible (11/13 peldaños) en buen estado (zapatas)",
                "critical": True,
            },
            {
                "key": "escalera_fibra_tijera_doble",
                "label": "Escalera de fibra de vidrio tipo tijera doble en buen estado (zapatas antideslizantes)",
                "critical": True,
            },
        ],
    },
]


TOOL_MATCH_RULES = {
    "fusionadora": {
        "label": "Fusionadora",
        "keywords": ["fusionadora", "sumitomo", "fitel", "fsm"],
    },
    "cortadora": {
        "label": "Cortadora de precision",
        "keywords": ["cortadora", "cleaver", "ct-30", "fc-6", "precision"],
    },
    "peladora": {
        "label": "Peladora de fibra",
        "keywords": ["peladora", "stripper", "pelador", "pela fibra"],
    },
    "medidor": {
        "label": "Medidor de potencia",
        "keywords": ["medidor", "power meter", "powermeter", "medidor de potencia", "otdr"],
    },
    "limpieza": {
        "label": "Kit de limpieza",
        "keywords": ["limpieza", "alcohol", "isoprop", "cletop", "cleaner", "toall", "pano"],
    },
    "baterias": {
        "label": "Baterias o cargadores",
        "keywords": ["bateria", "baterias", "cargador", "charger"],
    },
    "cartuchera_herramientas": {
        "label": "Cartuchera porta herramientas",
        "keywords": ["cartuchera", "porta herramientas", "porta-herramientas", "cinturon", "cinturón"],
    },
    "cartuchera_destornilladores_mini": {
        "label": "Cartuchera destornilladores mini",
        "keywords": ["cartuchera", "destornillador", "destornilladores", "mini", "precision", "precisión"],
    },
}
