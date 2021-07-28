#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#

#STIG Identification
GrpID="V-230298"
GrpTitle="SRG-OS-000480-GPOS-00227"
RuleID="SV-230298r627750_rule"
STIGID="RHEL-08-010561"
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

echo "rsyslog status- $(systemctl status rsyslog)" >> $Results
echo "Running status- $(systemctl is-active rsyslog)" >> $Results

if [ "$(systemctl is-enabled rsyslog)" == "enabled" ] && [ "$(systemctl is-active rsyslog)" == "active" ]; then
 echo "Pass" >> $Results
else 
 echo "Fail" >> $Results
fi
