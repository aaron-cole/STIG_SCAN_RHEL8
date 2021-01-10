#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#Enforcing a minimum password lifetime helps to prevent repeated password changes to defeat the password reuse or history enforcement requirement. If users are allowed to immediately and continually change their password, the password could be repeatedly changed in a short period of time to defeat the organization's policy regarding password reuse.

#STIG Identification
GrpID="V-230365"
GrpTitle="SRG-OS-000075-GPOS-00043"
RuleID="SV-230365r599732_rule"
STIGID="RHEL-08-020190"
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

if [ -f /etc/login.defs ] && [ "$(grep "^PASS_MIN_DAYS" /etc/login.defs | wc -l)" -eq 1 ]; then
awk -v opf="$Results" '/^PASS_MIN_DAYS/ {
	if($2 >= 1) {
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
