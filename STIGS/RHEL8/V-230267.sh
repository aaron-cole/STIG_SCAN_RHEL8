#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#

#STIG Identification
GrpID="V-230267"
GrpTitle="SRG-OS-000312-GPOS-00122"
RuleID="SV-230267r599732_rule"
STIGID="RHEL-08-010373"
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

chkfiles="$(grep "^fs.protected_symlinks" /etc/sysctl.conf /etc/sysctl.d/* | cut -f 1 -d ":" | sort | uniq)"

if [ -n "$chkfiles" ]; then
for chkfile in $chkfiles; do
 if [ "$(grep "^fs.protected_symlinks" "$chkfile" | sort | uniq | wc -l)" -eq 1 ]; then
  chkvalues="$(grep "^fs.protected_symlinks" "$chkfile" | cut -f 2 -d"=")"
  for chkvalue in $chkvalues; do
   if [ "$chkvalue" -eq 1 ]; then
    echo "Pass - Setting found in $chkfile - $(grep "^fs.protected_symlinks" "$chkfile")" >> $Results
   fi
  done
 fi
done
else
 echo "Fail - Setting Not Found in any files" >> $Results
fi
  
#Runtime
sysctl fs.protected_symlinks | awk -v opf="$Results" '/^fs.protected_symlinks/ {
	if($3 == 1) {
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
