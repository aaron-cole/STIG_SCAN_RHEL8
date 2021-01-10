#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#

#STIG Identification
GrpID="V-230350"
GrpTitle="SRG-OS-000028-GPOS-00009"
RuleID="SV-230350r599732_rule"
STIGID="RHEL-08-020042"
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

if grep -i tmux /etc/shells >> $Results; then
 echo "Fail" >> $Results
else
 echo "tmux not found in /etc/shells" >> $Results
 echo "Pass" >> $Results
fi
