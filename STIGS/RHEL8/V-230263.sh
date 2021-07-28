#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#

#STIG Identification
GrpID="V-230263"
GrpTitle="SRG-OS-000363-GPOS-00150"
RuleID="SV-230263r627750_rule"
STIGID="RHEL-08-010360"
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

if ps -ef | grep -i tripwire | grep -v grep >> $Results; then
 echo "Tripwire installed and Running" >> $Results
 echo "Pass" >> $Results
elif rpm -q aide >> $Results; then
 if grep -r "/usr/sbin/aide --check" /etc/cron.* /etc/crontab /var/spool/cron/root | grep -v "^#" >> $Results; then
  if grep -r "/usr/sbin/aide --check" /etc/cron.* /etc/crontab /var/spool/cron/root | grep "mail" | grep -v "^#" >> $Results; then
   echo "Pass" >> $Results
  else
   echo "AIDE mail setting not defined in cron files" >> $Results
   echo "Fail" >> $Results
  fi
 else
  echo "AIDE setting not defined in cron files" >> $Results
  echo "Fail" >> $Results
 fi
else
 echo "AIDE or Tripwire is not installed" >> $Results
 echo "Fail" >> $Results 
fi
