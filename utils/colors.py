"""
utils/colors.py — ANSI terminal color helpers
NuRichter · CySec Arsenal
"""

class C:
    RESET   = "\033[0m"
    BOLD    = "\033[1m"
    DIM     = "\033[2m"

    # NuRichter palette
    RED     = "\033[38;5;196m"
    ORANGE  = "\033[38;5;208m"
    YELLOW  = "\033[38;5;220m"
    GREEN   = "\033[38;5;82m"
    CYAN    = "\033[38;5;87m"
    BLUE    = "\033[38;5;63m"
    PURPLE  = "\033[38;5;135m"
    GRAY    = "\033[38;5;245m"
    WHITE   = "\033[97m"

    # Semantic
    OK      = GREEN
    WARN    = YELLOW
    ERR     = RED
    INFO    = CYAN
    FOUND   = ORANGE


def ok(msg: str)   -> str: return f"{C.OK}[+]{C.RESET} {msg}"
def warn(msg: str) -> str: return f"{C.WARN}[!]{C.RESET} {msg}"
def err(msg: str)  -> str: return f"{C.ERR}[-]{C.RESET} {msg}"
def info(msg: str) -> str: return f"{C.INFO}[*]{C.RESET} {msg}"
def found(msg: str)-> str: return f"{C.FOUND}[>]{C.RESET} {C.BOLD}{msg}{C.RESET}"
