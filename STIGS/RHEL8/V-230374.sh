#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#

#STIG Identification
GrpID="V-230374"
GrpTitle="SRG-OS-000123-GPOS-00064"
RuleID="SV-230374r627750_rule"
STIGID="RHEL-08-020270"
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

echo "I hope you don't provision emergency accounts" >> $Results
echo "Fail" >> $Results
