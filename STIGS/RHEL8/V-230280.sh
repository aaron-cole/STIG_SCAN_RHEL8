#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#

#STIG Identification
GrpID="V-230280"
GrpTitle="SRG-OS-000433-GPOS-00193"
RuleID="SV-230280r627750_rule"
STIGID="RHEL-08-010430"
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

chkfiles="$(grep "^kernel.randomize_va_space" /etc/sysctl.conf /etc/sysctl.d/* | cut -f 1 -d ":" | sort | uniq)"

if [ -n "$chkfiles" ]; then
for chkfile in $chkfiles; do
 if [ "$(grep "^kernel.randomize_va_space" "$chkfile" | sort | uniq | wc -l)" -eq 1 ]; then
  chkvalues="$(grep "^kernel.randomize_va_space" "$chkfile" | cut -f 2 -d"=")"
  for chkvalue in $chkvalues; do
   if [ "$chkvalue" -eq 2 ]; then
    echo "Pass - Setting found in $chkfile - $(grep "^kernel.randomize_va_space" "$chkfile")" >> $Results
   fi
  done
 fi
done
else
 echo "Fail - Setting Not Found in any files" >> $Results
fi
  
#Runtime
sysctl kernel.randomize_va_space | awk -v opf="$Results" '/^kernel.randomize_va_space/ {
	if($3 == 2) {
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
