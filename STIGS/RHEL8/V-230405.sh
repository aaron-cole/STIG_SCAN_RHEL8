#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#

#STIG Identification
GrpID="V-230405"
GrpTitle="SRG-OS-000062-GPOS-00031"
RuleID="SV-230405r627750_rule"
STIGID="RHEL-08-030140"
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

if ! auditctl -l | grep "\-w /etc/security/opasswd -p wa" >> $Results; then
 echo "Rule does not exist" >> $Results
 echo "Fail" >> $Results
else
 echo "Pass" >> $Results 
fi
