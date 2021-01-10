#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#Routing protocol daemons are typically used on routers to exchange network topology information with other routers. If this software is used when not required, system network information may be unnecessarily transmitted across the network.

#STIG Identification
GrpID="V-230540"
GrpTitle="SRG-OS-000480-GPOS-00227"
RuleID="SV-230540r599732_rule"
STIGID="RHEL-08-040260"
Results="./Results/$GrpID"

#Remove File if already there
[ -e $Results ] && rm -rf $Results

#Setup Results File
echo $GrpID >> $Results
echo $GrpTitle >> $Results
echo $RuleID >> $Results
echo $STIGID >> $Results
##END of Automatic Items##

###Check###

chkfiles="$(grep "^net.ipv4.ip_forward" /etc/sysctl.conf /etc/sysctl.d/* | cut -f 1 -d ":"| sort | uniq)"

if [ -n "$chkfiles" ]; then
for chkfile in $chkfiles; do
 if [ "$(grep "^net.ipv4.ip_forward" "$chkfile" | sort | uniq | wc -l)" -eq 1 ]; then
  chkvalues="$(grep "^net.ipv4.ip_forward" "$chkfile" | cut -f 2 -d"=")"
  for chkvalue in $chkvalues; do
   if [ "$chkvalue" -eq 0 ]; then
    echo "Pass - Setting found in $chkfile - $(grep "^net.ipv4.ip_forward" "$chkfile")" >> $Results
   else
    echo "Fail - Setting not found in $chkfile" >> $Results
   fi
  done
 else
  echo "Fail - $chkfile - too many entries" >> $Results
 fi
done
else
 echo "Fail - Setting Not Found in any files" >> $Results
fi
  
#Runtime
sysctl net.ipv4.ip_forward | awk -v opf="$Results" '/^net.ipv4.ip_forward/ {
	if($3 == 0) {
	 print "Pass - Setting Found in runtime -" $0 >> opf
	 } else {
	 print "Fail - Setting Not Found in runtime -" $0 >> opf
	 }
}'

if grep "Fail" $Results >> /dev/null; then
 echo "Fail" >> $Results 
else
 echo "Pass" >> $Results
fi
