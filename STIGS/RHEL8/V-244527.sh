#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#

#STIG Identification
GrpID="V-244527"
GrpTitle="SRG-OS-000480-GPOS-00227"
RuleID="SV-244527r743830_rule"
STIGID="RHEL-08-010472"
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

if rpm -q rng-tools >> $Results; then
 echo "Pass" >> $Results
else 
 echo "Fail" >> $Results
fi
