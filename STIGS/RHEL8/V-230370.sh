#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#

#STIG Identification
GrpID="V-230370"
GrpTitle="SRG-OS-000078-GPOS-00046"
RuleID="SV-230370r627750_rule"
STIGID="RHEL-08-020231"
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

if [ -f /etc/login.defs ] && [ "$(grep "^PASS_MIN_LEN" /etc/login.defs | wc -l)" -eq 1 ]; then
awk -v opf="$Results" '/^PASS_MIN_LEN/ {
	if($2 >= 15) {
	 print $0 >> opf
	 print "Pass" >> opf
	} else {
	 print $0 >> opf
	 print "Fail" >> opf
	}
}' /etc/login.defs
else
 echo "Setting not defined or more than 1 configuration" >> $Results
 echo "Fail" >> $Results
fi
