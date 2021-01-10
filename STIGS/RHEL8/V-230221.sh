#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#

#STIG Identification
GrpID="V-230221"
GrpTitle="SRG-OS-000480-GPOS-00227"
RuleID="SV-230221r599732_rule"
STIGID="RHEL-08-010000"
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

if [ -e /etc/redhat-release ] && [ "$(wc -l < /etc/redhat-release)" -eq 1 ]; then 
awk -v opf="$Results" '/^Red Hat Enterprise Linux / {
	if($6 >= 8.3) {
	 print $0 >> opf
	 print "Pass" >> opf
	} else {
	 print $0 >> opf
	 print "Fail" >> opf
	}
}' /etc/redhat-release
else
 echo "Setting doesn't exist or File has been edited" >> $Results 
 echo "Fail" >> $Results
fi
