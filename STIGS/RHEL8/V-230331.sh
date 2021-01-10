#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#

#STIG Identification
GrpID="V-230331"
GrpTitle="SRG-OS-000002-GPOS-00002"
RuleID="SV-230331r599824_rule"
STIGID="RHEL-08-020000"
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

echo "I hope you don't provision temporary accounts" >> $Results
echo "Fail" >> $Results
