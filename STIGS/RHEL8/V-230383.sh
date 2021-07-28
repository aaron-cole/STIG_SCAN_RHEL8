#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#Setting the most restrictive default permissions ensures that when new accounts are created, they do not have unnecessary access.

#STIG Identification
GrpID="V-230383"
GrpTitle="SRG-OS-000480-GPOS-00228"
RuleID="SV-230383r627750_rule"
STIGID="RHEL-08-020351"
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

if [ -f /etc/login.defs ] && [ "$(grep "^UMASK" /etc/login.defs | wc -l)" -eq 1 ]; then
awk -v opf="$Results" '/^UMASK/ {
	if($2 == "077") {
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
