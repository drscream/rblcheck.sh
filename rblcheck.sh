#!/usr/bin/env bash
# mail.core.io RBL check script written in simple bash. Written to run as
# cronjob only.

set -e
set -o pipefail

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
# SORBS:
## Open SMTP/Proxies, Spammed WWW Servers, Dynamic IP ranges
dnsbl.sorbs.net
# List of domain names where the A or MX records point to bad address space or
# the owners have indicated no email should ever originate from these domains.
rhsbl.sorbs.net
# List of hosts that have been noted as sending spam/UCE/UBE to the admins of
# SORBS at any time, and not subsequently resolving the matter and/or requesting
# a delisting. (Includes both old.spam.dnsbl.sorbs.net and
# escalations.dnsbl.sorbs.net).
spam.dnsbl.sorbs.net
# 510 SOFTWARE GROUP, blacklist
blackholes.five-ten-sg.com
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
# WPBL is a private block list consisting of IP addresses which connect to
# members' systems and deliver unsolicited bulk mail (spam)
db.wpbl.info
# UCEPROTECT Network, Level 1 lists single IP's only; Level 2 escalates within;
# allocation; Level 3 lists IP Space of the worst ASN's.
dnsbl-1.uceprotect.net
dnsbl-2.uceprotect.net
dnsbl-3.uceprotect.net
ips.backscatterer.org
# Synopsis of recent activity in DroneBL. DroneBL is a realtime monitor of
# abusable IPs, which has the goal of stopping abuse of infected machines.
dnsbl.dronebl.org
# ANTISPAM-UFRJ: Realtime Spammers Blacklist, Open-Relays Verify Engine
# Database List
rsbl.aupads.org
orvedb.aupads.org
## Spam Rats!
# Conform to a naming convention that is indicative of a home connection or
# dynamic address space.
dyna.spamrats.com
# Have no reverse DNS, a technique often used by bots and spammers.
noptr.spamrats.com
# IP Addresses that do not conform to more commonly known threats. This is
# usually because of compromised servers, hosts, or open relays.
spam.spamrats.com
# DNSBL (DNS-based blacklist) of NiX Spam
ix.dnsbl.manitu.net
# ImproWare AG, DNSRBL / URIBL
dnsrbl.swinog.ch
uribl.swinog.ch
# South Korean Network Blocking List
korea.services.net
# Provided by www.kisarbl.or.kr
spamlist.or.kr
)
DNS_TRIES=2
DNS_DURATION=3

# Hostname and default IPs
HOSTNAME=$(hostname)

DIG="dig +noall +time=${DNS_DURATION} +tries=${DNS_TRIES}"
# TODO: timeout check (return code)
IPV4=$(${DIG} +short A ${HOSTNAME})
IPV6=$(${DIG} +short AAAA ${HOSTNAME})

##
## Functions
##
dns_status_lookup() {
	local record=${1}
	local query=${2}

	${DIG} +comments +answer ${record} ${query} | \
		sed -n 's/;.*status: \([A-Z]*\),.*/\1/p; s/.*IN[[:space:]]*A[[:space:]]*\(.*\)/\1/p'
	if (( ${PIPESTATUS[0]} > 0 )); then
		echo 'TIMEOUT'
	fi
}

dns_txt_lookup() {
	local query=${1}
	${DIG} +short TXT ${query} | sed -e ':a' -e 'N' -e '$!ba' -e 's/\n/;/g'
}

print_table() {
	header=${1}
	local -n table=${2}

	if (( ${#table[@]} )); then
		(
		IFS=$'\n'
		for row in ${table[@]}; do
			echo "${header^^}|${row}"
		done
		) |\
		awk -F \| '{ printf "%-8s %-38s %-30s %-20s %-30s\n", $1, $2, $3, $4, $5 }' |\
		sed 's/[[:blank:]]*$//'
	fi
}


##
## Main
##
# Declare arrays
rbl_timeout=()
rbl_invalid=()
rbl_passed=()
rbl_listed=()
state=()

# Create IP address list
IP_LIST_IN="${IPV4} ${IPV6}"
IP_LIST_REV=()
for ip in ${IP_LIST_IN}; do
	if [[ ${ip} =~ ^([0-9a-fA-F]{0,4}:){1,7}[0-9a-fA-F]{0,4}$ ]]; then
		# IPv6
		IP_LIST+=( "${ip}|$(${DIG} +question -x ${ip} | sed -n 's/;\(.*\)\.ip6.arpa.*/\1/p')" )
	elif [[ ${ip} =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
		IP_LIST+=( "${ip}|$(echo ${ip} | awk -F. '{ print $4"."$3"."$2"."$1 }')" )
	else
		echo 'IP address is not valid and could not be used'
		exit 1
	fi
done

# Lookup Blacklists
for ip_list in ${IP_LIST[@]}; do
	ip=${ip_list/|*}
	ip_reverse=${ip_list/*|}
	for blacklist in ${BLACKLISTS[@]}; do
		query=${ip_reverse}.${blacklist}.
		logtxt="${ip}|${blacklist}"
		return_a=''

		# Status lookup
		state=( $(dns_status_lookup A ${query}) )

		case ${state[0]} in
			TIMEOUT)
				# Lookup to blacklist not possible
				rbl_timeout+=( "${logtxt}" )
				;;
			NXDOMAIN)
				# STATUS: NXDOMAIN = ( blacklist not working || not blacklisted )
				bl_domain=$(echo ${blacklist} | awk -F. '{ print $(NF-1)"."$NF }')
				ns_state=( $(dns_status_lookup NS ${blacklist}.) $(dns_status_lookup A ${blacklist}.) $(dns_status_lookup A ${bl_domain}))

				if [[ ${ns_state[0]} != 'NOERROR' && ${ns_state[1]} != 'NOERROR' && ${ns_state[2]} != 'NOERROR' ]]; then
					# STATUS: NXDOMAIN = blacklist not working
					rbl_invalid+=( "${logtxt}|_|DNS-lookup-failed" )
				else
					# STATUS: NXDOMAIN = not blacklisted
					rbl_passed+=( "${logtxt}" )
				fi
				;;
			NOERROR)
				# STATUS: NOERROR = potentially blacklisted
				for return_a in ${state[@]:1}; do
					if [[ ${return_a} =~ ^127.0 ]]; then
						# A: starts with 127.0 = blacklisted, state information
						extra_info=$(dns_txt_lookup ${query})
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
# Options
verbose=0
case ${1} in
	-v|--verbose)
		verbose=1
		;;
esac

if (( ${verbose} || ${#rbl_listed[@]} )); then
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
