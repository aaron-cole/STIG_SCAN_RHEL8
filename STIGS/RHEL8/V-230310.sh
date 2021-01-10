#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#

#STIG Identification
GrpID="V-230310"
GrpTitle="SRG-OS-000480-GPOS-00227"
RuleID="SV-230310r599780_rule"
STIGID="RHEL-08-010670"
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

echo "kdump status- $(systemctl status kdump)" >> $Results

if [ "$(systemctl is-enabled kdump)" == "disabled" ] && [ "$(systemctl is-active kdump)" == "inactive" ]; then
 echo "Pass" >> $Results
elif [ "$(systemctl is-enabled kdump)" == "disabled" ] && [ "$(systemctl is-active kdump)" == "unknown" ]; then
 echo "Pass" >> $Results
else 
 echo "Fail" >> $Results
fi
