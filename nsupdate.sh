#!/bin/sh
# Copyright (C) 2020 Michel Stam <michel@reverze.net>
# Copyright (C) 2023 Michal Roszkowski
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
DIG="${UACME_DIG_CMD:-dig}"
NSUPDATE="${UACME_NSUPDATE_CMD:-nsupdate}"

# Server to which updates will be sent. If not specified it will
# be obtained from MNAME in the SOA record.
NSUPDATE_SERVER="${UACME_NSUPDATE_SERVER:-}"

# Files
# {NSUPDATE,DIG}_KEY
#   If you wish to sign transactions using TSIG, specify the keyfile
#   here. If you do, also make sure named.conf specifies the
#   key "KEYNAME"; in the zone that must be updated (and disallow
#   all others for safety)
NSUPDATE_KEY="${UACME_NSUPDATE_KEY:-}"
DIG_KEY="${UACME_DIG_KEY:-}"

ARGS=5
E_BADARGS=85

if [ $# -ne "$ARGS" ]; then
    echo "Usage: $(basename "$0") method type ident token auth" 1>&2
    exit $E_BADARGS
fi

METHOD=$1
TYPE=$2
IDENT=$3
TOKEN=$4
AUTH=$5

ns_getns()
{
    local zone=$1
    local answer

    [ -n "$zone" ] && answer=$($DIG ${DIG_KEY:+-k ${DIG_KEY}} +noall +nottl +noclass +answer "$zone" NS) || return

    local owner
    local type
    local rdata
    while read -r owner type rdata; do
        [ "$type" = NS ] && echo $rdata
    done <<-EOF
	$answer
	EOF
}

ns_getall()
{
    local name=$1
    local answer
    local zone
    local primary

    [ -n "$name" ] && answer=$($DIG ${DIG_KEY:+-k ${DIG_KEY}} +noall +nottl +noclass +answer +authority "$name" SOA) || return

    name=${name%.}.

    local owner
    local type
    local rdata
    while read -r owner type rdata; do
        case "$type" in
            CNAME)
                name=$rdata
                ;;
            DNAME)
                name=${name%$owner}$rdata
                ;;
            SOA)
                zone=$owner
                set -- $rdata && primary=$1
                ;;
        esac
    done <<-EOF
	$answer
	EOF

    echo $name $zone $primary
}

ns_ispresent()
{
    local challenge=$2
    set -- $(ns_getall "$1")
    local name=$1
    local nameservers=$(ns_getns "$2")
    local answer
    local target
    local rc=1

    local ns
    for ns in $nameservers; do
        answer=$($DIG ${DIG_KEY:+-k ${DIG_KEY}} +noall +nottl +noclass +answer "@$ns" "$name" TXT) || continue
        target=

        local owner
        local type
        local rdata
        while read -r owner type rdata; do
            case "$type" in
                CNAME)
                    target=$rdata
                    ;;
                DNAME)
                    [ -n "$target" ] && target=${target%$owner}$rdata || target=${name%$owner}$rdata
                    ;;
                TXT)
                    [ "$rdata" = \"$challenge\" ] && rc=0 && continue 2
                    target=
                    ;;
            esac
        done <<-EOF
		$answer
		EOF

        [ -n "$target" ] && ns_ispresent "$target" "$challenge" && rc=0 || return 1
    done

    return $rc
}

ns_doupdate()
{
    local action=$1
    local challenge=$3
    set -- $(ns_getall "$2")
    local name=$1
    local zone=$2
    local server=${NSUPDATE_SERVER:-$3}
    local ttl=300

    [ -n "$server" ] && [ -n "$zone" ] && [ -n "$name" ] && [ -n "$challenge" ] || return 1

    $NSUPDATE ${NSUPDATE_KEY:+-k ${NSUPDATE_KEY}} -v <<-EOF
	server ${server}
	zone ${zone}
	update ${action} ${name} ${ttl} IN TXT ${challenge}
	send
	EOF

    return $?
}

ns_update()
{
    local action=$1
    local name=$2
    local challenge=$3
    local retries=5
    local delay=5
    local count=0

    ns_doupdate "$action" "$name" "$challenge" || return 1

    while sleep $delay; do
        case "$action" in
            add)
                ns_ispresent "$name" "$challenge" && break
                ;;
            del)
                ns_ispresent "$name" "$challenge" || break
                ;;
            *)
                return 1
        esac
        [ $count -lt $retries ] || return 1
        count=$((count + 1))
    done

    return 0
}

case "$METHOD" in
    "begin")
        case "$TYPE" in
            dns-01)
                ns_update add "_acme-challenge.$IDENT" "$AUTH"
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
                ns_update del "_acme-challenge.$IDENT" "$AUTH"
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
