#!/usr/bin/env bash
# mail.core.io RBL check script written in simple bash. Written to run as
# cronjob only.

set -e
set -o pipefail

##
## Arguments
##
verbose=0
case ${1:-} in
	-v|--verbose)
		verbose=1
		;;
	-h|--help)
		echo "Usage: $(basename "$0") [-v|--verbose] [-h|--help]"
		echo ""
		echo "  -v, --verbose   Show all results including passed checks"
		echo "  -h, --help      Show this help message"
		exit 0
		;;
	'') ;;
	*)
		echo "Unknown option: ${1}" >&2
		echo "Usage: $(basename "$0") [-v|--verbose] [-h|--help]" >&2
		exit 1
		;;
esac

##
## Configuration
##
BLACKLISTS=(
# ZEN is the combination of all Spamhaus IP-based DNSBLs into one single
# powerful and comprehensive blocklist to make querying faster and simpler.
# It contains the SBL, SBLCSS, XBL and PBL blocklists.
zen.spamhaus.org
# SpamCop is the premier service for reporting spam. SpamCop determines the
# origin of unwanted email and reports it to the relevant Internet service
# providers.
bl.spamcop.net
# The BRBL is open to public and can be used within reason. Barracuda Networks
# is currently making this service available free of charge and we hope to keep
# it that way.
b.barracudacentral.org
# PSBL is an easy-on, easy-off blacklist that does not rely on testing and
# should reduce false positives because any user can remove their ISP's mail
# server from the list.
psbl.surriel.com
# Woody's SMTP Blacklist
blacklist.woody.ch
# The traditional IPv4 bogon prefixes; Martian (reserved) prefixes plus those /8
# networks not allocated to an RIR by IANA.
bogons.cymru.com
# The CBL only lists IPs exhibiting characteristics which are specific to
# open proxies of various sorts (HTTP, socks, AnalogX, wingate, Bagle call-back
# proxies etc) and dedicated Spam BOTs (such as Cutwail, Rustock, Lethic, Kelihos,
# Necurs etc) which have been abused to send spam, worms/viruses that do their
# own direct mail transmission, or some types of trojan-horse or "stealth"
# spamware, dictionary mail harvesters etc.
cbl.abuseat.org
# Combined DNSBL listing IPs with Hacking activities, Hijacked webserver,
# Referer spam.
combined.abuse.ch
# UCEPROTECT Network, Level 1 lists single IP's only; Level 2 escalates within;
# allocation; Level 3 lists IP Space of the worst ASN's.
dnsbl-1.uceprotect.net
dnsbl-2.uceprotect.net
dnsbl-3.uceprotect.net
ips.backscatterer.org
# Synopsis of recent activity in DroneBL. DroneBL is a realtime monitor of
# abusable IPs, which has the goal of stopping abuse of infected machines.
dnsbl.dronebl.org
## Spam Rats!
# Conform to a naming convention that is indicative of a home connection or
# dynamic address space.
dyna.spamrats.com
# Have no reverse DNS, a technique often used by bots and spammers.
noptr.spamrats.com
# IP Addresses that do not conform to more commonly known threats. This is
# usually because of compromised servers, hosts, or open relays.
spam.spamrats.com
# ImproWare AG, DNSRBL / URIBL
dnsrbl.swinog.ch
uribl.swinog.ch
# South Korean Network Blocking List
korea.services.net
# GBUdb stands for Good, Bad, Ugly database. GBUdb is a real-time collaborative
# IP reputation system. This system is built into Message Sniffer where it can
# accurately learn about the kind of content that is sent by email sources on
# the Internet.
truncate.gbudb.net
)
DNS_TRIES=4
DNS_DURATION=4

# Hostname and default IPs
HOSTNAME=$(hostname)

DIG="dig +noall +time=${DNS_DURATION} +tries=${DNS_TRIES}"
IPV4=$(${DIG} +short A "${HOSTNAME}")
IPV6=$(${DIG} +short AAAA "${HOSTNAME}")

##
## Functions
##
dns_status_lookup() {
	local record=${1}
	local query=${2}
	local dig_output
	local -i dig_rc=0

	# Capture output and exit code separately; avoids unreachable PIPESTATUS
	# check under set -e + set -o pipefail.
	dig_output=$(${DIG} +comments +answer "${record}" "${query}" 2>/dev/null) || dig_rc=$?

	if (( dig_rc > 0 )); then
		echo 'TIMEOUT'
		return
	fi

	echo "${dig_output}" | \
		sed -n 's/;.*status: \([A-Z]*\),.*/\1/p; s/.*IN[[:space:]]*A[[:space:]]*\(.*\)/\1/p'
}

dns_txt_lookup() {
	local query=${1}
	${DIG} +short TXT "${query}" | sed -e ':a' -e 'N' -e '$!ba' -e 's/\n/;/g'
}

print_table() {
	local header=${1}
	local -n table=${2}
	local upper_header="${header^^}"
	local row

	if (( ${#table[@]} )); then
		for row in "${table[@]}"; do
			echo "${upper_header}|${row}"
		done | \
		awk -F \| '{ printf "%-8s %-38s %-30s %-20s %-30s\n", $1, $2, $3, $4, $5 }' | \
		sed 's/[[:blank:]]*$//'
	fi
}


##
## Main
##
# Declare arrays
declare -a rbl_timeout=()
declare -a rbl_invalid=()
declare -a rbl_passed=()
declare -a rbl_listed=()
declare -a IP_LIST=()

# Create IP address list
IP_LIST_IN="${IPV4} ${IPV6}"
for ip in ${IP_LIST_IN}; do
	if [[ ${ip} =~ ^([0-9a-fA-F]{0,4}:){1,7}[0-9a-fA-F]{0,4}$ ]]; then
		# IPv6
		IP_LIST+=( "${ip}|$(${DIG} +question -x "${ip}" | sed -n 's/;\(.*\)\.ip6.arpa.*/\1/p')" )
	elif [[ ${ip} =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
		IP_LIST+=( "${ip}|$(echo "${ip}" | awk -F. '{ print $4"."$3"."$2"."$1 }')" )
	else
		echo 'IP address is not valid and could not be used'
		exit 1
	fi
done

# Lookup Blacklists
for ip_list in "${IP_LIST[@]}"; do
	ip=${ip_list%%|*}
	ip_reverse=${ip_list##*|}
	for blacklist in "${BLACKLISTS[@]}"; do
		query=${ip_reverse}.${blacklist}.
		logtxt="${ip}|${blacklist}"

		# Status lookup — mapfile keeps each output line as a separate array
		# element without word-splitting side effects.
		mapfile -t state < <(dns_status_lookup A "${query}")

		case ${state[0]} in
			TIMEOUT)
				# Lookup to blacklist not possible
				rbl_timeout+=( "${logtxt}" )
				;;
			NXDOMAIN)
				# STATUS: NXDOMAIN = ( blacklist not working || not blacklisted )
				bl_domain=$(echo "${blacklist}" | awk -F. '{ print $(NF-1)"."$NF }')
				ns1=$(dns_status_lookup NS "${blacklist}." | head -1)
				ns2=$(dns_status_lookup A  "${blacklist}." | head -1)
				ns3=$(dns_status_lookup A  "${bl_domain}"  | head -1)

				if [[ ${ns1} != 'NOERROR' && ${ns2} != 'NOERROR' && ${ns3} != 'NOERROR' ]]; then
					# STATUS: NXDOMAIN = blacklist not working
					rbl_invalid+=( "${logtxt}|_|DNS-lookup-failed" )
				else
					# STATUS: NXDOMAIN = not blacklisted
					rbl_passed+=( "${logtxt}" )
				fi
				;;
			NOERROR)
				# STATUS: NOERROR = potentially blacklisted
				for return_a in "${state[@]:1}"; do
					if [[ ${return_a} =~ ^127\.0 ]]; then
						# A: starts with 127.0 = blacklisted, state information
						extra_info=$(dns_txt_lookup "${query}")
						rbl_listed+=( "${logtxt}|${return_a}|${extra_info}" )
					else
						# A: not 127.0 = invalid response from blacklist
						rbl_invalid+=( "${logtxt}|${return_a}" )
					fi
				done
				;;
		esac
	done
done


##
## OUTPUT
##
if (( verbose || ${#rbl_listed[@]} )); then
	printf "%-8s %-38s %-30s %-20s %-30s\n" Status IP List Return Extra
	printf "%-8s %-38s %-30s %-20s %-30s\n" ------ -- ---- ------ -----
	print_table "Listed " rbl_listed
	print_table "Passed " rbl_passed
	print_table "Invalid" rbl_invalid
	print_table "Timeout" rbl_timeout
else
	if (( ${#rbl_invalid[@]} )); then
		print_table "Invalid" rbl_invalid
	fi
	if (( ${#rbl_timeout[@]} )); then
		print_table "Timeout" rbl_timeout
	fi
fi
