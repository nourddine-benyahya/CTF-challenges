import re

FORBIDDEN_PATTERNS = [
    r'\b(rm|cat|chmod|chown|mv|cp|dd|shred|git|apt|apt-get|yum|dnf|pacman|curl|wget|nc|netcat|socat|ssh|scp)\b',
    r'\$(\(|\{)[^}]*\)?',
    r'`.*?`',
    r'\b(echo\s+>|>>|<\s*)\S+',
    r'(\/|\~|\.\.)\/',
    r'(;|\|\||&&)',
    r'(python|ruby|perl|php|node)\s',
    r'(sudo|su|doas)\b',
    r'\/dev\/',
    r'\b(mkfs|fdisk|mount|umount)\b'
]

def validate_script(filepath):
    try:
        with open(filepath, 'r') as f:
            content = f.read().lower()
        
        for pattern in FORBIDDEN_PATTERNS:
            if re.search(pattern, content):
                return False, f"Forbidden pattern detected: {pattern}"
                
        return True, "Validation passed"
    except Exception as e:
        return False, f"Validation error: {str(e)}"