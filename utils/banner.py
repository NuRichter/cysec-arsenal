"""
utils/banner.py — ASCII banner renderer
NuRichter · CySec Arsenal
"""
from utils.colors import C

BANNER = f"""
{C.RED}
  ██████╗██╗   ██╗███████╗███████╗ ██████╗
 ██╔════╝╚██╗ ██╔╝██╔════╝██╔════╝██╔════╝
 ██║      ╚████╔╝ ███████╗█████╗  ██║
 ██║       ╚██╔╝  ╚════██║██╔══╝  ██║
 ╚██████╗   ██║   ███████║███████╗╚██████╗
  ╚═════╝   ╚═╝   ╚══════╝╚══════╝ ╚═════╝{C.RESET}
{C.PURPLE}  ░░ ARSENAL ░░  NuRichter Workspace  ░░ EST. 2020 ░░{C.RESET}
{C.GRAY}  Richterize The Infinity ∞{C.RESET}
"""

MODULE_BANNERS = {
    "recon":     f"{C.CYAN}[RECON]{C.RESET}    Reconnaissance & OSINT Engine",
    "web":       f"{C.GREEN}[WEB]{C.RESET}      Web Application Exploit Scanner",
    "network":   f"{C.BLUE}[NETWORK]{C.RESET}  Packet Analysis & ARP Detection",
    "crypto":    f"{C.YELLOW}[CRYPTO]{C.RESET}   Hash Cracker & Cipher Tools",
    "forensics": f"{C.ORANGE}[FORENSICS]{C.RESET} Metadata & File Carving",
    "pwn":       f"{C.RED}[PWN]{C.RESET}      Binary Exploitation Toolkit",
}


def print_banner(module: str = ""):
    print(BANNER)
    if module and module in MODULE_BANNERS:
        print(f"  {MODULE_BANNERS[module]}\n")
