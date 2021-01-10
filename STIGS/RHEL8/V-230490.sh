#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#

#STIG Identification
GrpID="V-230490"
GrpTitle="SRG-OS-000095-GPOS-00049"
RuleID="SV-230490r599732_rule"
STIGID="RHEL-08-040003"
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

if rpm -q gssproxy >> $Results; then
 echo "Fail" >> $Results
else 
 echo "Pass" >> $Results
fi
