#!/bin/sh
# Copyright (C) 2020 Michel Stam <michel@reverze.net>
#
# This file is part of uacme.
#
# uacme is free software: you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# uacme is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

# Commands
DIG=dig
RNDC=rndc
NSUPDATE=nsupdate

# Files
# RNDC_KEY
#   if you wish to specify an RDC key for TSIG transactions, do so
#   here. If you do, also make sure /etc/named.conf specifies the
#   key "KEYNAME"; in the zone that must be updated (and disallow
#   all others for safety) 
RNDC_KEY=

# Arguments
METHOD=$1
TYPE=$2
IDENT=$3
TOKEN=$4
AUTH=$5

ns_getdomain()
{
    local fqhn="$1"
    local idx
    local ret=''
    OLDIFS="$IFS"
    IFS=.
 
    set -- $fqhn
    idx=$#

    if [ $idx -gt 1 ]; then
        eval ret="\$$idx"
        idx=$((idx-1))
        eval ret="\$$idx.\$ret"
    fi

    IFS="$OLDIFS"
    echo $ret
}

ns_gethostname()
{
    local fqhn="$1"
    local ret=''
    local idx=1
 
    OLDIFS="${IFS}"
    IFS='.'
    set -- ${fqhn}
    IFS="${OLDIFS}"

    if [ $# -ge 2 ]; then
        max=$(( $# - 2 ))
    else
        max=1
    fi

    while [ $idx -le $max ]; do
        eval ret="$ret.\$$idx"
        idx=$((idx + 1))
    done

    echo ${ret:1}
}


ns_getprimary()
{
    local domain=$1

    [ -n "$domain" ] || return
    set -- $($DIG ${RNDC_KEY:+-k ${RNDC_KEY}} +short "$domain" SOA 2>/dev/null)

    echo $1
}
    
ns_getall()
{
    local domain=$1

    [ -n "$domain" ] || return 1

    $DIG ${RNDC_KEY:+-k ${RNDC_KEY}} +short "$domain" NS 2>/dev/null
}

ns_ispresent()
{
    local fqhn="$1"
    local expect="$2"
    local domain=$(ns_getdomain "$fqhn")
    local nameservers=$(ns_getall "$domain")
    local res
    local ret

    for NS in $nameservers; do
        res=$($DIG ${RNDC_KEY:+-k ${RNDC_KEY}} +short "@$NS" "$fqhn" TXT 2>/dev/null)
        res="${res//\"/}"
        [ "$res" == "$expect" ] || return 1
    done

    return 0
}

ns_doupdate()
{
    local fqhn="$1"
    local challenge="$2"
    local ttl=600
    local domain=$(ns_getdomain "$fqhn")
    local nameserver=$(ns_getprimary "$domain")
    local action=

    [ -n "$nameserver" ] || return

    if [ -n "${challenge}" ]; then
            action="update add ${fqhn}. ${ttl} IN TXT ${challenge}"
    else
            action="update del ${fqhn}."
    fi

    $NSUPDATE ${RNDC_KEY:+-k ${RNDC_KEY}} -v <<-EOF
            server ${nameserver}
            ${action}
            send
EOF

    return $?
}

ns_update()
{
    local fqhn="$1"
    local challenge="$2"
    local count=0
    local res

    res=1
    while [ $res -ne 0 ]; do
        if [ $count -eq 0 ]; then
            ns_doupdate "$fqhn" "$challenge"
            res=$?
            [ $res -eq 0 ] || break
        else
            sleep 1
        fi

        count=$(((count + 1) % 5))
        ns_ispresent "$fqhn" "$challenge"
        res=$?
    done

    return $?
}

ARGS=5
E_BADARGS=85

if [ $# -ne "$ARGS" ]; then
    echo "Usage: $(basename "$0") method type ident token auth" 1>&2
    exit $E_BADARGS
fi

case "$METHOD" in
    "begin")
        case "$TYPE" in
            dns-01)
                ns_update "_acme-challenge.$IDENT" "$AUTH"
                exit $?
                ;;
            *)
                exit 1
                ;;
        esac
        ;;

    "done"|"failed")
        case "$TYPE" in
            dns-01)
                ns_update "_acme-challenge.$IDENT"
                exit $?
                ;;
            *)
                exit 1
                ;;
        esac
        ;;

    *)
        echo "$0: invalid method" 1>&2
        exit 1
esac
