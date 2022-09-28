#!/bin/bash

dashsep="----------------"
user=$(whoami)
outputFolder="/home/$user/.NAES/Results"
binFolder="./bin"

#PORT NUMBERS
http="80"
https="443"
althttp="8080"
dns="53"
kerb="88"
ldap="389"

#COLOURS
C=$(printf '\033')
RED="${C}[1;31m"
GREEN="${C}[1;32m"
YELLOW="${C}[1;33m"
BLUE="${C}[1;34m"
URL="${C}[1;34m${C}[4m"
ITALIC_BLUE="${C}[1;34m${C}[3m"
LIGHT_MAGENTA="${C}[1;95m"
SED_LIGHT_MAGENTA="${C}[1;95m&${C}[0m"
LIGHT_CYAN="${C}[1;96m"
SED_LIGHT_CYAN="${C}[1;96m&${C}[0m"
LG="${C}[1;37m" #LightGray
SED_LG="${C}[1;37m&${C}[0m"
DG="${C}[1;90m" #DarkGray
SED_DG="${C}[1;90m&${C}[0m"
PLAIN="${C}[0m"
UNDERLINED="${C}[5m"
ITALIC="${C}[3m"


Help() {
	# Display Help
	echo "Add description of the script functions here."
	echo
	echo "Syntax: naes.sh [-t|h]"
	echo "options:"
	echo "-t [target-ip]     Enumerate a target."
	echo "-h     Print this help."
	echo
}

ExploitLDAP() {
	target=$1
	resultsFolder="$outputFolder/$target"
	FILE="$resultsFolder/$target.nmap.simple"
	if test -f "$FILE"; then
		ldapResults="$resultsFolder/ldap"
		mkdir -p "$ldapResults"
		dn=$(grep <"$FILE" 'Base dn' | awk -F ': ' '{print $2}')
		domain=$(grep <"$FILE" 'Domain name:' | awk -F ': ' '{print $2}')
		ldapsearch=$("$binFolder"/ldapsearch -x -b "$dn" -h "$target" -p 389 | tee "$ldapResults"/ldapsearch.txt)
		windapsearch=$("$binFolder"/ldap/windapsearch -m users -d "$domain" --dc "$target" -U | tee "$ldapResults"/windapsearch.txt)
		users=$(echo "$windapsearch" | grep 'userPrincipalName' | awk -F ': ' '{print $2}' | tee "$ldapResults"/identifiedUsers.txt)
		ou=$(echo "$windapsearch" | grep "OU=" | awk -F 'OU=' '{$1=""; print $0}' | awk -F 'DC=' '{print $1}' | sed s/,$// | awk -F ',' '{print $1; print $2; print $3;}' | awk '!seen[$0]++' | tee "$resultsFolder"/OU.txt)
		objectClass=$("$binFolder"/ldap/windapsearch -m custom --filter="(objectClass=*)" -d "$domain" --dc "$target" -U >"$ldapResults"/objectClasses.txt)
		cn=$(grep <"$ldapResults"/objectClasses.txt -a 'CN=' | awk -F ': ' '{print $2}' | awk -F [=,] '{print $2}' | awk '!seen[$0]++' | tee "$ldapResults"/CN.txt)
	else
		Analyse_Results "$resultsFolder"/"$target".nmap
		ExploitLDAP "$target"
	fi
}

Exploit() {
	protocol=$1
	echo "What is your target IP address?"
	read -r ip
	case $protocol in
	ldap)
		ExploitLDAP "$ip"
		;;
	*)
		echo "Not a (currently) supported protocol"
		;;
	esac
}

Analyse_Results() {
	resultsFolder=$1
	resultsFile=$2
	target=$3
	filename="allports.txt"
	results=$(cat "$resultsFolder"/"$filename")
	echo $dashsep
	if grep <"$resultsFolder"/"$filename" -iq 'ldap'; then
		printf "${GREEN}LDAP${PLAIN}  --> ${URL}https://book.hacktricks.xyz/network-services-pentesting/pentesting-ldap${PLAIN} "
		printf "\n%s\n" $dashsep
	fi
	if grep <"$resultsFolder"/"$filename" -iq 'ssh'; then
		printf "${GREEN}SSH${PLAIN}  --> ${URL}https://book.hacktricks.xyz/network-services-pentesting/pentesting-ssh${PLAIN} "
		printf "\n%s\n" $dashsep
	fi
	if grep <"$resultsFolder"/"$filename" -iq 'http\|https\|http-alt'; then
		printf "${GREEN}WEB${PLAIN} --> ${URL}https://book.hacktricks.xyz/network-services-pentesting/pentesting-web${PLAIN} \n"
		printf "Subdomain Bruteforce:\n\t"
		printf "wfuzz -c -w /path/to/SecLists/Discovery/DNS/bitquark-subdomains-top100000.txt --sc 200 -H 'Host:FUZZ.boxname.htb' -u %s -t 10" "$target"
		printf "\n%s\n" $dashsep
	fi
	if grep <"$resultsFolder"/"$filename" -iq 'dns\|domain'; then
		printf "${GREEN}DNS${PLAIN} --> ${URL}https://book.hacktricks.xyz/network-services-pentesting/pentesting-dns${PLAIN} "
		printf "\n%s\n" $dashsep
	fi
	if grep <"$resultsFolder"/"$filename" -iq 'smb\|microsoft-ds\|netbios'; then
		printf "${GREEN}SMB${PLAIN} --> ${URL}https://book.hacktricks.xyz/network-services-pentesting/pentesting-smb \n${PLAIN} "
		printf "Try listing shares:\n\tsmbclient --no-pass -L //%s" "$target"
		printf "\n%s\n" $dashsep
	fi
	if grep <"$resultsFolder"/"$filename" -iq 'kerberos'; then
		printf "${GREEN}Kerberos${PLAIN} --> ${URL}https://book.hacktricks.xyz/network-services-pentesting/pentesting-kerberos-88${PLAIN} "
		printf "\n%s\n" $dashsep
	fi
	if grep <"$resultsFolder"/"$filename" -iq 'snmp'; then
		printf "${GREEN}SNMP${PLAIN} --> ${URL}https://book.hacktricks.xyz/network-services-pentesting/pentesting-snmp${PLAIN} "
		printf "\n%s\n" $dashsep
	fi
	domainName=$(grep <"$resultsFile" -i 'Domain name:\|Domain:')
	FQDN=$(grep <"$resultsFile" -i 'FQDN')
	varsFile="$resultsFile.simple"
	if [[ $domainName != "" ]]; then
		dname=$(echo "$domainName" | awk -F : '{print $2}' | awk -F , '{print $1}' | awk '{ gsub(/ /,""); print }')
		printf "Domain name: %s \n" "$dname" | tee "$varsFile"
		dn=$(echo "$dname" | awk -F '.' '{print "dc=" $1 ",dc=" $2}')
		printf "Base dn: %s \n" "$dn" | tee -a "$varsFile"
	fi
	if [[ $FQDN != "" ]]; then
		FQDN=$(echo "$FQDN" | awk -F : '{print $2}' | awk '{ gsub(/ /,""); print }')
		printf "FQDN: %s \n" "$FQDN" | tee -a "$varsFile"
	fi
	echo "=== End of Results ===" | tee -a "$varsFile"
	printf "Full results can be found in ${YELLOW} %s${PLAIN}\n" "$resultsFolder"
}

Full_Scan() {
	target=$1
	ports=$2
	resultsPath=$3
	echo "Enumerating open ports..."
	results=$(nmap -sC -sV -Pn -p"$ports" -oA "$resultsPath"/"$target" "$target")
	resultsFile=$resultsPath/$target.nmap
	Analyse_Results "$resultsPath" "$resultsFile" "$target"
}

Get_Open_Ports() {
	target=$1
	resultsPath="$outputFolder/$target"
	mkdir -p "$resultsPath"
	FILE=$resultsPath/$target.nmap
	if test -f "$FILE"; then
		read -rp "Existing scan exists for this target. Overwrite? [y/N]" yn
		case $yn in
		[yY])
			printf "Overwriting existing results for %s \n" "$target"
			;;
		*)
			read -rp "Analyse results? [Y/n]" yn
			case $yn in
			[nN]) exit ;;
			*)
				Analyse_Results "$resultsPath" "$FILE" "$target"
				exit
				;;
			esac
			exit
			;;
		esac
	fi
	echo "Checking common ports..."
	top_ports_nmap=$(nmap -sT --top-ports 1000 -Pn -T4 "$target")
	top_ports=$(echo "$top_ports_nmap" | grep "^[0-9]" | cut -d '/' -f 1,3)
	top_ports_formatted=$(echo "$top_ports_nmap" | grep "^[0-9]" | awk -F '/tcp' '{print $1 " " $2}' | awk '{print $1 " " $3}')
	echo "Out of the top 1000 ports, the following responded as OPEN. Investigate these ports further:"
	echo "$top_ports_formatted" | tee "$resultsPath"/top1000.txt
	echo "$dashsep"
	echo "Initial analysis:"
	if [[ "$top_ports" == *"$http"* || "$top_ports" == *"$https"* || "$top_ports" == *"$althttp"* ]]; then
		printf "* There's something running on one of the standard HTTP ports, so have a look for a website. \n "
		if [[ "$top_ports" == *"$http"* ]]; then
			printf "\t Port 80 is open --> Check http://%s \n" "$target"
		fi
		if [[ "$top_ports" == *"$https"* ]]; then
			printf "\t Port 443 is open --> Check https://%s \n" "$target"
		fi
		if [[ "$top_ports" == *"$althttp"* ]]; then
			printf "\t Port 8080 is open --> Check http://%s:8080 \n" "$target"
		fi
	fi
	if [[ "$top_ports" == *"$dns"* && "$top_ports" == *"$kerb"* && "$top_ports" == *"$ldap"* ]]; then
		printf "* %s could be a Domain Controller. \n Port 88 (Kerberos), 53 (DNS) and 389 (LDAP) are open on the host.\n" "$target"
	fi
	echo "$dashsep"
	echo "Checking for more ports..."
	all_ports_nmap=$(nmap -sT -p- -Pn -T4 "$target")
	all_ports=$(echo "$all_ports_nmap" | grep "^[0-9]" | cut -d '/' -f 1,3)
	all_ports_formatted=$(echo "$all_ports_nmap" | grep "^[0-9]" | awk -F '/tcp' '{print $1 " " $2}' | awk '{print $1 " " $3}')
	if [[ "$top_ports" == "$all_ports" ]]; then
		printf "${RED}No new ports found${PLAIN}\n"
		cp "$resultsPath"/top1000.txt "$resultsPath"/allports.txt
	else
		printf "${GREEN}More ports found!${PLAIN}\n"
		echo "The following ports responded as OPEN"
		echo "$all_ports_formatted" | tee "$resultsPath"/allports.txt
	fi

	listofports=$(echo "$all_ports" | tr '\n' ',' | sed s/,$//)
	Full_Scan "$target" "$listofports" "$resultsPath"
}

cat banner
chmod +x -R ./bin

while getopts ":ht:a:e:" option; do
	case $option in
	h) # display Help
		Help
		exit
		;;
	t) # Enter a name
		target=$OPTARG
		printf "Target IP: ${YELLOW} %s${PLAIN}\n" "$target"
		Get_Open_Ports "$target"
		exit
		;;
	a)
		atarget=$OPTARG
		targetFolder="$outputFolder/$atarget"
		nmapFile="$targetFolder/$atarget.nmap"
		Analyse_Results "$targetFolder" "$nmapFile" "$atarget"
		exit
		;;
	e)
		protocol=$OPTARG
		Exploit "$protocol"
		exit
		;;
	\?) # Invalid option
		echo "Error: Invalid option"
		exit
		;;
	esac
done
