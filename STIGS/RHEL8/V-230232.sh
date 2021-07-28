#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#

#STIG Identification
GrpID="V-230232"
GrpTitle="SRG-OS-000073-GPOS-00041"
RuleID="SV-230232r627750_rule"
STIGID="RHEL-08-010120"
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

if cut -f2 -d: /etc/shadow | egrep -v "^\!\!|^\*|^$6" >> $Results; then
 echo "Items found" >> $Results
 echo "Fail" >> $Results
else
 echo "Nothing found" >> $Results
 echo "Pass" >> $Results
fi
