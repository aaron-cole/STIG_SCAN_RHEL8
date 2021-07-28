#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#

#STIG Identification
GrpID="V-230481"
GrpTitle="SRG-OS-000342-GPOS-00133"
RuleID="SV-230481r627750_rule"
STIGID="RHEL-08-030710"
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

if grep '$DefaultNetstreamDriver gtls' /etc/rsyslog.conf | grep -v "^#" >> $Results; then
 if grep '$ActionSendStreamDriverMode 1' /etc/rsyslog.conf | grep -v "^#" >> $Results; then 
  echo "Pass" >> $Results
 else
  echo "ActionSendStreamDriverMode not set correctly in /etc/rsyslog.conf" >> $Results
  echo "Fail" >> $Results
 fi
else 
 echo "DefaultNetstreamDriver not set correctly in /etc/rsyslog.conf" >> $Results
 echo "Fail" >> $Results
fi
