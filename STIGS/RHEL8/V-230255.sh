#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#

#STIG Identification
GrpID="V-230255"
GrpTitle="SRG-OS-000250-GPOS-00093"
RuleID="SV-230255r627750_rule"
STIGID="RHEL-08-010294"
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

if [ -f /etc/crypto-policies/back-ends/opensslcnf.config ] && [ "$(grep "^MinProtocol = "  /etc/crypto-policies/back-ends/opensslcnf.config | wc -l)" -eq 1 ]; then
awk -v opf="$Results" '/^MinProtocol = / {
	if($3 == "TLSv1.2") {
	 print $0 >> opf
	 print "Pass" >> opf
	} else {
	 print $0 >> opf
	 print "Fail" >> opf
	}
}'  /etc/crypto-policies/back-ends/opensslcnf.config
else
 echo "Setting not defined or more than 1 configuration" >> $Results
 echo "Fail" >> $Results
fi
