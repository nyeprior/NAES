#!/bin/bash

dashsep="----------------"
user=$(whoami)
desktopFolder="/home/$user/Desktop/"
http="80"
https="443"
althttp="8080"
dns="53"
kerb="88"
ldap="389"


Help()
{
   # Display Help
   echo "Add description of the script functions here."
   echo
   echo "Syntax: enum.sh [-t|h|v|V]"
   echo "options:"
   echo "-t [target-ip]     Enumerate a target."
   echo "-h     Print this help."
   echo
}

ExploitLDAP()
{
target=$1
resultsFolder=$desktopFolder/$target
FILE=$resultsFolder/$target.nmap.simple
if test -f "$FILE"; then
    ldapResults="$resultsFolder/ldap"
    mkdir -p $ldapResults
    dn=$(cat $FILE | grep 'Base dn' | awk -F ': ' '{print $2}' )
    domain=$(cat $FILE | grep 'Domain name:' | awk -F ': ' '{print $2}' )
    ldapsearch=$(ldapsearch -x -b $dn -h $target -p 389 | tee $ldapResults/ldapsearch.txt)
    windapsearch=$(./ldap/windapsearch -m users -d $domain --dc $target -U | tee $ldapResults/windapsearch.txt)
    users=$(echo "$windapsearch" | grep 'userPrincipalName' | awk -F ': ' '{print $2}' | tee $ldapResults/identifiedUsers.txt)
    ou=$(echo "$windapsearch"  | grep "OU=" | awk -F 'OU=' '{$1=""; print $0}' | awk -F 'DC=' '{print $1}' | sed s/,$// | awk -F ',' '{print $1; print $2; print $3;}' | awk '!seen[$0]++' | tee $resultsFolder/OU.txt)
    objectClass=$(./ldap/windapsearch -m custom --filter="(objectClass=*)" -d $domain --dc $target -U > $ldapResults/objectClasses.txt)
    cn=$(cat $ldapResults/objectClasses.txt | grep -a 'CN=' | awk -F ': ' '{print $2}' | awk -F [=,] '{print $2}' | awk '!seen[$0]++' | tee $ldapResults/CN.txt)
else
    Analyse_Results $resultsFolder/$target.nmap
    ExploitLDAP $target
fi
}

Exploit()
{
protocol=$1
echo "What is your target IP address?"
read ip
case $protocol in 
    ldap)
        ExploitLDAP $ip
        ;;
    *) 
        echo "Not a (currently) supported protocol"
        ;;
esac
}

Analyse_Results(){
resultsFolder=$1
resultsFile=$2
target=$3
filename="allports.txt"
cat "$resultsFolder//$filename"
results=$(cat $resultsFolder/$filename)
echo $dashsep
if [[ $(cat $resultsFolder/$filename | grep -i 'ldap') ]]; then
printf "LDAP --> https://book.hacktricks.xyz/network-services-pentesting/pentesting-ldap \n$dashsep\n"
fi
if [[ $(cat $resultsFolder/$filename | grep -i 'ssh') ]]; then
printf "SSH --> https://book.hacktricks.xyz/network-services-pentesting/pentesting-ssh \n$dashsep\n"
fi
if [[ $(cat $resultsFolder/$filename | grep -i 'http\|https\|http-alt') ]]; then
printf "WEB --> https://book.hacktricks.xyz/network-services-pentesting/pentesting-web \n"
printf "Subdomain Bruteforce:\n\twfuzz -c -w /path/to/SecLists/Discovery/DNS/bitquark-subdomains-top100000.txt --sc 200 -H 'Host:FUZZ.boxname.htb' -u $target -t 10 \n$dashsep\n"
fi
if [[ $(cat $resultsFolder/$filename | grep -i 'dns\|domain') ]]; then
printf "DNS --> https://book.hacktricks.xyz/network-services-pentesting/pentesting-dns \n"
fi
if [[ $(cat $resultsFolder/$filename | grep -i 'smb\|microsoft-ds\|netbios') ]]; then
printf "SMB --> https://book.hacktricks.xyz/network-services-pentesting/pentesting-smb \n"
fi
if [[ $(cat $resultsFolder/$filename | grep -i 'kerberos') ]]; then
printf "Kerberos --> https://book.hacktricks.xyz/network-services-pentesting/pentesting-kerberos-88 \n"
fi
if [[ $(cat $resultsFolder/$filename | grep -i 'snmp') ]]; then
printf "Kerberos --> https://book.hacktricks.xyz/network-services-pentesting/pentesting-snmp \n"
fi
domainName=$(cat "$resultsFile" | grep -i 'Domain name:\|Domain:')
FQDN=$(cat "$resultsFile" | grep -i 'FQDN')
varsFile="$resultsFile.simple"
if [[ $domainName != "" ]]; then
    dname=$(echo $domainName | awk -F : '{print $2}' | awk -F , '{print $1}' | awk '{ gsub(/ /,""); print }')
    printf "Domain name: $dname \n" | tee $varsFile
    dn=$(echo $dname | awk -F '.' '{print "dc=" $1 ",dc=" $2}')
    printf "Base dn: $dn \n" | tee -a $varsFile
fi
if [[ $FQDN != "" ]]; then
    FQDN=$(echo $FQDN | awk -F : '{print $2}'| awk '{ gsub(/ /,""); print }')
    printf "FQDN: $FQDN \n" | tee -a $varsFile
fi
}

Full_Scan(){
target=$1
ports=$2
resultsPath=$3
echo "Enumerating open ports..."
results=$(nmap -sC -sV -Pn -p$ports -oA $resultsPath/$target $target)
resultsFile=$resultsPath/$target.nmap
Analyse_Results $resultsPath $resultsFile $target
}

Get_Open_Ports()
{
target=$1
resultsPath="$desktopFolder/$target"
mkdir -p $resultsPath
FILE=$resultsPath/$target.nmap
if test -f "$FILE"; then
    read -p "Existing scan exists for this target. Overwrite? [y/N]" input
    if [[ "$input" != "y" || "$input" != "Y" ]]; then
        read -p "Analyse results? [Y/n]" input
        if [[ "$input" == "n" || "$input" == "N" ]]; then
            exit
        else
            Analyse_Results $resultsPath $FILE
            exit
        fi
    fi
fi
echo "Checking common ports..."
top_ports_nmap=$(nmap -sT --top-ports 1000 -Pn -T4 $target)
top_ports=$(echo "$top_ports_nmap" | grep ^[0-9] | cut -d '/' -f 1,3)
top_ports_formatted=$(echo "$top_ports_nmap"| grep ^[0-9] | awk -F '/tcp' '{print $1 " " $2}' | awk '{print $1 " " $3}') 
echo "Out of the top 1000 ports, the following responded as OPEN. Investigate these ports further:"
echo "$top_ports_formatted" | tee $resultsPath/top1000.txt
printf "$dashsep\n"
echo "Initial analysis:"
if [[ "$top_ports" == *"$http"* || "$top_ports" == *"$https"* || "$top_ports" == *"$althttp"*  ]]; then
 printf "* There's something running on one of the standard HTTP ports, so have a look for a website. \n "
if [[ "$top_ports" == *"$http"* ]]; then
printf "\t Check http://$target \n"
fi
if [[ "$top_ports" == *"$https"* ]]; then
printf "\t Check https://$target \n"
fi
if [[ "$top_ports" == *"$althttp"* ]]; then
printf "\t Check http://$target:8080 \n"
fi
 printf "Look for subdomains with wfuzz:\n wfuzz -c -w /path/to/SecLists/Discovery/DNS/bitquark-subdomains-top100000.txt --sc 200 -H 'Host:FUZZ.boxname.htb' -u $target -t 10 \n"
fi
if [[ "$top_ports" == *"$dns"* && "$top_ports" == *"$kerb"* && "$top_ports" == *"$ldap"* ]]; then
  printf "* $target could be a Domain Controller. \n Port 88 (Kerberos), 53 (DNS) and 389 (LDAP) are open on the host.\n"
fi
echo "$dashsep"
echo "Checking for more ports..."
all_ports_nmap=$(nmap -sT -p- -Pn -T4 $target)
all_ports=$(echo "$all_ports_nmap" | grep ^[0-9] | cut -d '/' -f 1,3)
all_ports_formatted=$(echo "$all_ports_nmap"| grep ^[0-9] | awk -F '/tcp' '{print $1 " " $2}' | awk '{print $1 " " $3}')
if [[ "$top_ports" == "$all_ports" ]]; then
    echo "No new ports found"
else
    echo "More ports found!"
    echo "The following ports responded as OPEN"
    echo "$all_ports_formatted" | tee $resultsPath/allports.txt
fi

listofports=$(echo "$all_ports" | tr '\n' ','| sed s/,$//)
Full_Scan $target $listofports $resultsPath
}


while getopts ":ht:a:e:" option; do
   case $option in
      h) # display Help
         Help
         exit;;
      t) # Enter a name
         target=$OPTARG
         echo "Target IP: $target"
         Get_Open_Ports $target
         exit;;
      a)
         atarget=$OPTARG
         Analyse_Results "/home/$user/Desktop/$atarget/$atarget.nmap"
         exit;;
      e)
         protocol=$OPTARG
         Exploit $protocol
         exit;;
     \?) # Invalid option
         echo "Error: Invalid option"
         exit;;
   esac
done


