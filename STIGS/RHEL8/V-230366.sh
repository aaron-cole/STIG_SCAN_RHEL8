#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#Any password, no matter how complex, can eventually be cracked. Therefore, passwords need to be changed periodically. If RHEL 8 does not limit the lifetime of passwords and force users to change their passwords, there is the risk that RHEL 8 passwords could be compromised.

#STIG Identification
GrpID="V-230366"
GrpTitle="SRG-OS-000076-GPOS-00044"
RuleID="SV-230366r646878_rule"
STIGID="RHEL-08-020200"
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

if [ -f /etc/login.defs ] && [ "$(grep "^PASS_MAX_DAYS" /etc/login.defs | wc -l)" -eq 1 ]; then
awk -v opf="$Results" '/^PASS_MAX_DAYS/ {
	if($2 <= 60) {
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
