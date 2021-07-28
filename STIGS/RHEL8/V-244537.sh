#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#

#STIG Identification
GrpID="V-244537"
GrpTitle="SRG-OS-000028-GPOS-00009"
RuleID="SV-244537r743860_rule"
STIGID="RHEL-08-020039"
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

if rpm -q tmux >> $Results; then
 echo "Pass" >> $Results
else 
 echo "Fail" >> $Results
fi
