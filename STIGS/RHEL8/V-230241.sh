#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#

#STIG Identification
GrpID="V-230241"
GrpTitle="SRG-OS-000134-GPOS-00068"
RuleID="SV-230241r627750_rule"
STIGID="RHEL-08-010171"
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

if rpm -q policycoreutils >> $Results; then
 echo "Pass" >> $Results
else 
 echo "Fail" >> $Results
fi
