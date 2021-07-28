#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#

#STIG Identification
GrpID="V-244548"
GrpTitle="SRG-OS-000378-GPOS-00163"
RuleID="SV-244548r743893_rule"
STIGID="RHEL-08-040141"
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

echo "usbguard status- $(systemctl status usbguard.service)" >> $Results
echo "Running status- $(systemctl is-active usbguard.service)" >> $Results

if [ "$(systemctl is-enabled usbguard.service)" == "enabled" ] && [ "$(systemctl is-active usbguard.service)" == "active" ]; then
 echo "Pass" >> $Results
else 
 echo "Fail" >> $Results
fi
