#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#

#STIG Identification
GrpID="V-230524"
GrpTitle="SRG-OS-000378-GPOS-00163"
RuleID="SV-230524r599732_rule"
STIGID="RHEL-08-040140"
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

echo "usbguard.service status- $(systemctl status usbguard.service 2>>$Results)" >> $Results
echo "Running status- $(systemctl is-active usbguard.service 2>>$Results)" >> $Results 

if [ "$(systemctl is-enabled usbguard.service 2>>/dev/null)" == "enabled" ] && [ "$(systemctl is-active usbguard.service 2>>/dev/null)" == "active" ]; then
 echo "Pass" >> $Results
else 
 echo "Fail" >> $Results
fi
