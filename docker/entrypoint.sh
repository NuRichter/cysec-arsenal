#!/usr/bin/env bash
# docker/entrypoint.sh
echo ""
echo "  ╔═══════════════════════════════════════╗"
echo "  ║  CySec Arsenal — Lab Container        ║"
echo "  ║  NuRichter Workspace · CTF Edition    ║"
echo "  ╚═══════════════════════════════════════╝"
echo ""
echo "  Binaries : pscan subenum wfuzz hcrack cipher fcarve osint ropx dbust"
echo "  Scripts  : ./scripts/*.sh"
echo "  Docs     : docs/cheatsheet.md"
echo ""
exec "$@"
