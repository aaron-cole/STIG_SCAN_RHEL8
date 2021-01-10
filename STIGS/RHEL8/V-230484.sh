#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#

#STIG Identification
GrpID="V-230484"
GrpTitle="SRG-OS-000355-GPOS-00143"
RuleID="SV-230484r599732_rule"
STIGID="RHEL-08-030740"
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

echo "CHRONYD Status - $(systemctl status chronyd 2>> $Results)" >> $Results

if [ "$(systemctl is-enabled chronyd 2>/dev/null)" == "enabled" ] && [ "$(systemctl is-active chronyd 2>/dev/null)" == "active" ]; then
 if grep "^server " /etc/chrony.conf >> $Results; then
  if [ "$(grep "^server " /etc/chrony.conf | wc -l)" == "$(grep "^server " /etc/chrony.conf | grep "maxpoll [0-1][0-6]"| wc -l)" ]; then
   echo "Pass" >> $Results 
  else
   echo "Maxpoll not set correctly" >> $Results
   echo "Fail" >> $Results
  fi
 else
  echo "servers are not defined" >> $Results
  echo "Fail" >> $Results
 fi
else
 echo "Chrony service is not running" >> $Results 
 echo "Fail" >> $Results
fi
