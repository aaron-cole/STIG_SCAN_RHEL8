#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#

#STIG Identification
GrpID="V-230369"
GrpTitle="SRG-OS-000078-GPOS-00046"
RuleID="SV-230369r599732_rule"
STIGID="RHEL-08-020230"
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

if [ -f /etc/security/pwquality.conf ] && [ "$(grep "^minlen" /etc/security/pwquality.conf | wc -l)" -eq 1 ]; then
awk -v opf="$Results" '/^minlen/ {
	if($3 >= 15) {
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
