#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#

#STIG Identification
GrpID="V-230499"
GrpTitle="SRG-OS-000095-GPOS-00049"
RuleID="SV-230499r599732_rule"
STIGID="RHEL-08-040026"
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

grep -r "firewire-core" /etc/modprobe.d | grep -v "^#" >> $Results

if [ "$(grep -r "^install firewire-core \/bin\/true" /etc/modprobe.d)" ]; then 
 if [ "$(grep -r "^blacklist firewire-core" /etc/modprobe.d)" ]; then 
  echo "Pass" >> $Results 
 else
  echo "Blacklist Setting is not defined" >> $Results 
  echo "Fail" >> $Results
 fi
else
 echo "Install Setting is not defined" >> $Results 
 echo "Fail" >> $Results
fi
