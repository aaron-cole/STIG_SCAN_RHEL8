#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#

#STIG Identification
GrpID="V-230285"
GrpTitle="SRG-OS-000480-GPOS-00227"
RuleID="SV-230285r627750_rule"
STIGID="RHEL-08-010471"
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

echo "rngd status- $(systemctl status rngd)" >> $Results
echo "Running status- $(systemctl is-active rngd)" >> $Results

if [ "$(systemctl is-enabled rngd)" == "enabled" ] && [ "$(systemctl is-active rngd)" == "active" ]; then
 echo "Pass" >> $Results
else 
 echo "Fail" >> $Results
fi
