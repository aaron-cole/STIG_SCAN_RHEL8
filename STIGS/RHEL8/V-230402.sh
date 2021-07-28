#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#

#STIG Identification
GrpID="V-230402"
GrpTitle="SRG-OS-000057-GPOS-00027"
RuleID="SV-230402r627750_rule"
STIGID="RHEL-08-030121"
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

tail -1 /etc/audit/audit.rules >> $Results

if [ "$(tail -1 /etc/audit/audit.rules)" == "-e 2" ]; then
 echo "Pass" >> $Results
else
 echo "Setting not found" >> $Results
 echo "Fail" >> $Results
fi
