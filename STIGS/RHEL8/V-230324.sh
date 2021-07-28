#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#If local interactive users are not assigned a valid home directory, there is no place for the storage and control of files they should own.

#STIG Identification
GrpID="V-230324"
GrpTitle="SRG-OS-000480-GPOS-00227"
RuleID="SV-230324r627750_rule"
STIGID="RHEL-08-010760"
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

if [ -f /etc/login.defs ] && [ "$(grep "^CREATE_HOME" /etc/login.defs | wc -l)" -eq 1 ]; then
awk -v opf="$Results" '/^CREATE_HOME/ {
	if($2 == "yes") {
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
