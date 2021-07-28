#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#

#STIG Identification
GrpID="V-230373"
GrpTitle="SRG-OS-000118-GPOS-00060"
RuleID="SV-230373r627750_rule"
STIGID="RHEL-08-020260"
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

if [ -f /etc/default/useradd ] && [ "$(grep "^INACTIVE" /etc/default/useradd | wc -l)" -eq 1 ]; then
awk -v opf="$Results" -F= '/^INACTIVE/ {
	if($2 >= 0 && $2 <= 35) {
	 print $0 >> opf
	 print "Pass" >> opf
	} else {
	 print $0 >> opf
	 print "Fail" >> opf
	}
}' /etc/default/useradd
else
 echo "Setting not defined or more than 1 configuration" >> $Results
 echo "Fail" >> $Results
fi

