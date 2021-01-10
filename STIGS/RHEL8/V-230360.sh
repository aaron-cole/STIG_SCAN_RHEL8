#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#

#STIG Identification
GrpID="V-230360"
GrpTitle="SRG-OS-000072-GPOS-00040"
RuleID="SV-230360r599732_rule"
STIGID="RHEL-08-020140"
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

if [ -f /etc/security/pwquality.conf ] && [ "$(grep "^maxclassrepeat" /etc/security/pwquality.conf | wc -l)" -eq 1 ]; then
awk -v opf="$Results" '/^maxclassrepeat/ {
	if($3 <= 4 && $3 > 0) {
	 print $0 >> opf
	 print "Pass" >> opf
	} else {
	 print $0 >> opf
	 print "Fail" >> opf
	}
}' /etc/security/pwquality.conf
else
 echo "Setting not defined or more than 1 configuration" >> $Results
 echo "Fail" >> $Results
fi
