#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#

#STIG Identification
GrpID="V-230403"
GrpTitle="SRG-OS-000057-GPOS-00027"
RuleID="SV-230403r627750_rule"
STIGID="RHEL-08-030122"
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

if grep "^\-\-loginuid-immutable" /etc/audit/audit.rules >> $Results; then
 echo "Pass" >> $Results
else
 echo "Setting not found" >> $Results
 echo "Fail" >> $Results
fi
