#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#

#STIG Identification
GrpID="V-230505"
GrpTitle="SRG-OS-000297-GPOS-00115"
RuleID="SV-230505r599732_rule"
STIGID="RHEL-08-040100"
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

if rpm -q firewalld >> $Results; then
 echo "Startup status- $(systemctl is-enabled firewalld)" >> $Results
 echo "Running status- $(systemctl is-active firewalld)" >> $Results
 if [ "$(systemctl is-enabled firewalld)" == "enabled" ] && [ "$(systemctl is-active firewalld)" == "active" ]; then
  echo "Current Firewalld State - $(systemctl status firewalld)" >> $Results
  if [ "$(firewall-cmd --state)" == "running" ]; then
   echo "Pass" >> $Results
  else 
   echo "Fail" >> $Results
  fi
 else 
  echo "Fail" >> $Results
 fi
else 
 echo "Fail" >> $Results
fi
