#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#

#STIG Identification
GrpID="V-230315"
GrpTitle="SRG-OS-000480-GPOS-00227"
RuleID="SV-230315r599732_rule"
STIGID="RHEL-08-010675"
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

if ! grep "^ProcessSizeMax=0" /etc/systemd/coredump.conf >> $Results; then
 grep "ProcessSizeMax=" /etc/systemd/coredump.conf >> $Results
 echo "Setting not found or not correct" >> $Results
 echo "Fail" >> $Results
else
 echo "Pass" >> $Results
fi
