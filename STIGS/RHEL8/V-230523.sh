#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#

#STIG Identification
GrpID="V-230523"
GrpTitle="SRG-OS-000368-GPOS-00154"
RuleID="SV-230523r744023_rule"
STIGID="RHEL-08-040135"
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

if rpm -q fapolicyd >> $Results; then
 echo "Pass" >> $Results
else 
 echo "Fail" >> $Results
fi
