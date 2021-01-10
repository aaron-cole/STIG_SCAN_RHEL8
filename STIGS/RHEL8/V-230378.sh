#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#

#STIG Identification
GrpID="V-230378"
GrpTitle="SRG-OS-000480-GPOS-00226"
RuleID="SV-230378r599732_rule"
STIGID="RHEL-08-020310"
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

if [ -f /etc/login.defs ] && [ "$(grep "^FAIL_DELAY" /etc/login.defs | wc -l)" -eq 1 ]; then
awk -v opf="$Results" '/^FAIL_DELAY/ {
	if($2 >= 4) {
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
