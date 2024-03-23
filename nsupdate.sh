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
#   here. If you do, also make sure named.conf specifies the
#   key "KEYNAME"; in the zone that must be updated (and disallow
#   all others for safety)
NSUPDATE_KEY=
DIG_KEY=

ARGS=5
E_BADARGS=85

if [ $# -ne "$ARGS" ]; then
	echo "Usage: $(basename "$0") method type ident token auth" 1>&2
	exit $E_BADARGS
fi

readonly METHOD=$1
readonly TYPE=$2
readonly IDENT=$3
readonly TOKEN=$4
readonly AUTH=$5

name=_acme-challenge.${IDENT#.}

ns_ispresent()
{
	rc=1

	for ns in $nameservers; do
		answer=$($DIG ${DIG_KEY:+-k ${DIG_KEY}} +noall +nottl +noclass +answer "@$ns" "$name" TXT) || continue

		while read -r owner type rdata; do
			[ "$type" = TXT ] && [ "$rdata" = \"$AUTH\" ] && rc=0 && continue 2
		done <<-EOF
			$answer
			EOF

		return 1
	done

	return $rc
}

ns_update()
{
	readonly action=$1

	unset zone primary
	answer=$($DIG ${DIG_KEY:+-k ${DIG_KEY}} +noall +nottl +noclass +answer +authority "$name" SOA) || return 1

	name=${name%.}.
	while read -r owner type rdata; do
		case "$type" in
		CNAME)
			name=$rdata
			;;
		DNAME)
			[ "$rdata" = . ] && name=${name%$owner} || name=${name%$owner}$rdata
			;;
		SOA)
			zone=$owner
			set -- $rdata && primary=$1
			;;
		esac
	done <<-EOF
		$answer
		EOF

	readonly server=${NSUPDATE_SERVER:-$primary}
	readonly ttl=300

	[ -n "$server" ] && [ -n "$zone" ] || return 1

	$NSUPDATE ${NSUPDATE_KEY:+-k ${NSUPDATE_KEY}} -v <<-EOF || return 1
		server ${server}
		zone ${zone}
		update ${action} ${name} ${ttl} IN TXT ${AUTH}
		send
		EOF

	unset nameservers
	answer=$($DIG ${DIG_KEY:+-k ${DIG_KEY}} +noall +nottl +noclass +answer "$zone" NS) || return 1

	while read -r owner type rdata; do
		[ "$type" = NS ] && nameservers="$nameservers $rdata"
	done <<-EOF
	$answer
	EOF

	readonly retries=5
	readonly delay=5
	count=0
	while sleep $delay; do
		case "$action" in
		add)
			ns_ispresent && break
			;;
		del)
			ns_ispresent || break
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
		ns_update add
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
		ns_update del
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
