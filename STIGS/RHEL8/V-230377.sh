#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#If RHEL 8 allows the user to select passwords based on dictionary words, this increases the chances of password compromise by increasing the opportunity for successful guesses, and brute-force attacks.

#STIG Identification
GrpID="V-230377"
GrpTitle="SRG-OS-000480-GPOS-00225"
RuleID="SV-230377r599732_rule"
STIGID="RHEL-08-020300"
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

if [ -f /etc/security/pwquality.conf ] && [ "$(grep "^dictcheck" /etc/security/pwquality.conf | wc -l)" -eq 1 ]; then
awk -v opf="$Results" '/^dictcheck/ {
	if($3 == 1) {
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
