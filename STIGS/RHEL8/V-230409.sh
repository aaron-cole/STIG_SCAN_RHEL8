#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#

#STIG Identification
GrpID="V-230409"
GrpTitle="SRG-OS-000062-GPOS-00031"
RuleID="SV-230409r627750_rule"
STIGID="RHEL-08-030171"
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

if ! auditctl -l | grep "\-w /etc/sudoers -p wa" >> $Results; then
 echo "Rule does not exist" >> $Results
 echo "Fail" >> $Results
else
 echo "Pass" >> $Results 
fi
