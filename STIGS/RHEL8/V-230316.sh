#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#To provide availability for name resolution services, multiple redundant name servers are mandated. A failure in name resolution could lead to the failure of security functions requiring name resolution, which may include time synchronization, centralized authentication, and remote system logging.

#STIG Identification
GrpID="V-230316"
GrpTitle="SRG-OS-000480-GPOS-00227"
RuleID="SV-230316r599732_rule"
STIGID="RHEL-08-010680"
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

if grep "^hosts" /etc/nsswitch.conf | grep dns >> $Results; then
 grep "^nameserver " /etc/resolv.conf >> $Results
 if [ "$(grep "^nameserver " /etc/resolv.conf | wc -l)" -ge 2 ]; then
  echo "2 or more DNS servers are defined" >> $Results
  echo "Pass" >> $Results
 else 
  echo "Less than 2 DNS servers are defined" >> $Results
  echo "Fail" >> $Results
 fi
else 
 if [ -n /etc/resolv.conf ]; then
  echo "Local host files is only being used and not empty" >> $Results
  echo "Fail" >> $Results
 else
  echo "Local host files is only being used and empty" >> $Results
  echo "Pass" >> $Results
 fi
fi
