"""
Icon sets for Wiz CI/CD Reports.

Provides three icon styles for console and HTML output:
- ascii: Safe for all terminals including Windows (default)
- unicode: Nicer icons for terminals with Unicode support
- html: HTML entities for dashboard generation
"""

# Icon set definitions
ICON_SETS = {
    'ascii': {
        # Console status
        'ok': '[OK]',
        # Scan types
        'container': '[C]',
        'directory': '[D]',
        'iac': '[I]',
        'vm_image': '[V]',
        'vm': '[M]',
        'unknown': '[?]',
        # Navigation
        'arrow_down': 'v',
        'arrow_left': '<',
        'arrow_right': '>',
        # Math
        'multiply': '*',
    },
    'unicode': {
        # Console status
        'ok': '\u2713',  # checkmark
        # Scan types
        'container': '\U0001F433',  # whale
        'directory': '\U0001F4C1',  # folder
        'iac': '\u2601\uFE0F',  # cloud
        'vm_image': '\U0001F4BF',  # disc
        'vm': '\U0001F5A5\uFE0F',  # desktop
        'unknown': '\U0001F4C4',  # document
        # Navigation
        'arrow_down': '\u25BC',  # triangle down
        'arrow_left': '\u25C0',  # triangle left
        'arrow_right': '\u25B6',  # triangle right
        # Math
        'multiply': '\u00D7',  # multiplication sign
    },
    'html': {
        # Console status (fallback to ascii for console)
        'ok': '[OK]',
        # Scan types (HTML entities)
        'container': '&#128051;',  # whale
        'directory': '&#128193;',  # folder
        'iac': '&#9729;',  # cloud
        'vm_image': '&#128191;',  # disc
        'vm': '&#128421;',  # desktop
        'unknown': '&#128196;',  # document
        # Navigation
        'arrow_down': '&#9660;',  # triangle down
        'arrow_left': '&#9664;',  # triangle left
        'arrow_right': '&#9654;',  # triangle right
        # Math
        'multiply': '&times;',
    }
}

# Map scan type strings to icon keys
SCAN_TYPE_MAP = {
    'CONTAINER_IMAGE': 'container',
    'DIRECTORY': 'directory',
    'IAC': 'iac',
    'VIRTUAL_MACHINE_IMAGE': 'vm_image',
    'VIRTUAL_MACHINE': 'vm',
}


def get_icons(style='ascii'):
    """
    Get the icon set for the specified style.

    Args:
        style: One of 'ascii', 'unicode', or 'html'. Defaults to 'ascii'.

    Returns:
        dict: Icon mappings for the specified style.
    """
    return ICON_SETS.get(style, ICON_SETS['ascii'])


def get_console_icon(key, style='ascii'):
    """
    Get a single icon for console output.
    Falls back to ascii for 'html' style since HTML entities don't render in console.

    Args:
        key: The icon key (e.g., 'ok', 'container')
        style: One of 'ascii', 'unicode', or 'html'. Defaults to 'ascii'.

    Returns:
        str: The icon character(s).
    """
    # HTML style falls back to ascii for console output
    effective_style = 'ascii' if style == 'html' else style
    icons = get_icons(effective_style)
    return icons.get(key, icons.get('unknown', '?'))


def get_scan_type_icon(scan_type, style='ascii'):
    """
    Get the icon for a scan type.

    Args:
        scan_type: The scan type string (e.g., 'CONTAINER_IMAGE')
        style: One of 'ascii', 'unicode', or 'html'. Defaults to 'ascii'.

    Returns:
        str: The icon for the scan type.
    """
    icon_key = SCAN_TYPE_MAP.get(scan_type, 'unknown')
    return get_icons(style).get(icon_key, get_icons(style)['unknown'])


def get_js_icon_object(style='ascii'):
    """
    Generate a JavaScript object literal for scan type icons.
    Used in HTML dashboard generation.

    Args:
        style: One of 'ascii', 'unicode', or 'html'. Defaults to 'ascii'.

    Returns:
        str: JavaScript object literal string.
    """
    icons = get_icons(style)
    return f"""{{
                'CONTAINER_IMAGE': '{icons['container']}',
                'DIRECTORY': '{icons['directory']}',
                'IAC': '{icons['iac']}',
                'VIRTUAL_MACHINE_IMAGE': '{icons['vm_image']}',
                'VIRTUAL_MACHINE': '{icons['vm']}'
            }}"""
