#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#

#STIG Identification
GrpID="V-230253"
GrpTitle="SRG-OS-000480-GPOS-00227"
RuleID="SV-230253r599732_rule"
STIGID="RHEL-08-010292"
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

if grep "^SSH_USE_STRONG_RNG=32" /etc/sysconfig/sshd >> $Results; then
 echo "Pass" >> $Results
else
 grep "SSH_USE_STRONG" /etc/sysconfig/sshd >> $Results
 echo "Fail" >> $Results
fi
