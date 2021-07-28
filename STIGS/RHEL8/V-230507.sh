#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#

#STIG Identification
GrpID="V-230507"
GrpTitle="SRG-OS-000300-GPOS-00118"
RuleID="SV-230507r627750_rule"
STIGID="RHEL-08-040111"
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

grep -r "bluetooth" /etc/modprobe.d | grep -v "^#" >> $Results

if [ "$(grep -r "^install bluetooth \/bin\/true" /etc/modprobe.d)" ]; then 
 if [ "$(grep -r "^blacklist bluetooth" /etc/modprobe.d)" ]; then 
  echo "Pass" >> $Results 
 else
  echo "Blacklist Setting is not defined" >> $Results 
  echo "Fail" >> $Results
 fi
else
 echo "Install Setting is not defined" >> $Results 
 echo "Fail" >> $Results
fi
