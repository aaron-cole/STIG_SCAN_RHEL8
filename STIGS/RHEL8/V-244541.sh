#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#If an account has an empty password, anyone could log on and run commands with the privileges of that account. Accounts with empty passwords should never be used in operational environments.

#STIG Identification
GrpID="V-244541"
GrpTitle="SRG-OS-000480-GPOS-00227"
RuleID="SV-244541r743872_rule"
STIGID="RHEL-08-020332"
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
scorecheck=0
filestocheck="/etc/pam.d/password-auth"

for filetocheck in $filestocheck; do
 if grep -i "nullok" $filetocheck | grep -v ^# >> $Results; then
  ((scorecheck+=1)) 
 fi
done

if [ "$scorecheck" != 0 ]; then
 echo "Fail" >> $Results 
else 
 echo "Pass" >> $Results
fi
