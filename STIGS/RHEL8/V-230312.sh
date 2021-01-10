#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#

#STIG Identification
GrpID="V-230312"
GrpTitle="SRG-OS-000480-GPOS-00227"
RuleID="SV-230312r599782_rule"
STIGID="RHEL-08-010672"
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

echo "$(systemctl status systemd-coredump.socket)" >> $Results

if [ "$(systemctl is-enabled systemd-coredump.socket)" == "masked" ]; then
 echo "Pass" >> $Results
else 
 echo "Fail" >> $Results
fi
