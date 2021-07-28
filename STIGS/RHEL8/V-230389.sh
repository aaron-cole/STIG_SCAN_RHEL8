#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#

#STIG Identification
GrpID="V-230389"
GrpTitle="SRG-OS-000046-GPOS-00022"
RuleID="SV-230389r627750_rule"
STIGID="RHEL-08-030030"
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

if [ -f /etc/aliases ] && [ "$(grep "^postmaster:"  /etc/aliases | wc -l)" -eq 1 ]; then
awk -v opf="$Results" '/^postmaster:/ {
	if($2 == "root") {
	 print $0 >> opf
	 print "Pass" >> opf
	} else {
	 print $0 >> opf
	 print "Fail" >> opf
	}
}'  /etc/aliases
else
 echo "Setting not defined or more than 1 configuration" >> $Results
 echo "Fail" >> $Results
fi
