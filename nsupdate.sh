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
DIG=dig
NSUPDATE=nsupdate

# Server to which updates will be sent. If not specified it will
# be obtained from MNAME in the SOA record.
NSUPDATE_SERVER=

# Files
# {NSUPDATE,DIG}_KEY
#   If you wish to sign transactions using TSIG, specify the keyfile
#   here. If you do, also make sure /etc/named.conf specifies the
#   key "KEYNAME"; in the zone that must be updated (and disallow
#   all others for safety)
NSUPDATE_KEY=
DIG_KEY=

# Arguments
METHOD=$1
TYPE=$2
IDENT=$3
TOKEN=$4
AUTH=$5

ns_getdomain()
{
    local name=$1
    local answer
    local domain

    [ -n "$name" ] && answer=$($DIG ${DIG_KEY:+-k ${DIG_KEY}} +noall +nottl +noclass +answer +authority "$name" SOA) || return

    while read -r record type value; do
        [ "$type" = SOA ] && domain=$record
    done <<-EOF
	$answer
	EOF

    echo $domain
}

ns_getns()
{
    local domain=$1
    local answer

    [ -n "$domain" ] && answer=$($DIG ${DIG_KEY:+-k ${DIG_KEY}} +short "$domain" NS) || return

    echo $answer
}

ns_getall()
{
    local domain=$1
    local answer
    local cname
    local primary

    [ -n "$domain" ] && answer=$($DIG ${DIG_KEY:+-k ${DIG_KEY}} +noall +nottl +noclass +answer +authority "$domain" SOA) || return

    while read -r record type value; do
        case "$type" in
            CNAME)
                cname=$value
                ;;
            SOA)
                set -- $value && primary=$1
                ;;
        esac
    done <<-EOF
	$answer
	EOF

    echo ${cname:-$domain} $primary
}

ns_ispresent()
{
    local name=$1
    local challenge=$2
    local nameservers=$(ns_getns $(ns_getdomain "$name"))
    local answer
    local cname
    local rc=1

    for ns in $nameservers; do
        answer=$($DIG ${DIG_KEY:+-k ${DIG_KEY}} +noall +nottl +noclass +answer "@$ns" "$name" TXT) || continue
        cname=

        while read -r record type value; do
            case "$type" in
                CNAME)
                    cname=$value
                    ;;
                TXT)
                    [ "$value" = \"$challenge\" ] && rc=0 && continue 2
                    cname=
                    ;;
            esac
        done <<-EOF
		$answer
		EOF

        [ -n "$cname" ] && ns_ispresent "$cname" "$challenge" && rc=0 || return 1
    done

    return $rc
}

ns_doupdate()
{
    local action=$1
    local challenge=$3
    set -- $(ns_getall "$2")
    local name=$1
    local server=${NSUPDATE_SERVER:-$2}
    local ttl=300

    [ -n "$server" ] && [ -n "$name" ] && [ -n "$challenge" ] || return 1

    $NSUPDATE ${NSUPDATE_KEY:+-k ${NSUPDATE_KEY}} -v <<-EOF
	server ${server}
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
