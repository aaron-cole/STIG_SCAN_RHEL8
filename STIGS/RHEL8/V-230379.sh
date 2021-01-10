#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#Accounts providing no operational purpose provide additional opportunities for system compromise. Unnecessary accounts include user accounts for individuals not requiring access to the system and application accounts for applications not installed on the system.

#STIG Identification
GrpID="V-230379"
GrpTitle="SRG-OS-000480-GPOS-00227"
RuleID="SV-230379r599732_rule"
STIGID="RHEL-08-020320"
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

echo "Document the accounts" >> $Results
cat /etc/passwd >> $Results
echo "Fail" >> $Results
