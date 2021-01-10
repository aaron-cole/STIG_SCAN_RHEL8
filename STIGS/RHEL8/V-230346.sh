#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#

#STIG Identification
GrpID="V-230346"
GrpTitle="SRG-OS-000027-GPOS-00008"
RuleID="SV-230346r599786_rule"
STIGID="RHEL-08-020024"
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

if [ -e /etc/security/limits.conf ] && [ "$(grep "^\*.*hard.*maxlogins" /etc/security/limits.conf | wc -l)" -eq 1 ]; then 
awk -v opf="$Results" '/^\*.*hard.*maxlogins/ {
	if($4 <= 10) {
	 print $0 >> opf
	 print "Pass" >> opf
	} else {
	 print $0 >> opf
	 print "Fail" >> opf
	}
}' /etc/security/limits.conf
elif grep -r "^\*.*hard.*maxlogins" /etc/security/limits.d >> $Results; then
 filenames="$(grep -r "^\*.*hard.*maxlogins" /etc/security/limits.d | awk -F: '{print $1}' | sort | uniq)"
 for filename in $filenames; do
awk -v opf="$Results" '/^\*.*hard.*maxlogins/ {
	if($4 <= 10) {
	 print $0 >> opf
	 print "Pass" >> opf
	} else {
	 print $0 >> opf
	 print "Fail" >> opf
	}
}' $filename
 done
else
 echo "Setting not defined in /etc/security/limits.conf or more than 1 configuration" >> $Results 
 echo "Fail" >> $Results
fi

if grep "Fail" $Results >> /dev/null; then
 echo "Fail" >> $Results
else
 echo "Pass" >> $Results
fi
