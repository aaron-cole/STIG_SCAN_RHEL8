#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#

#STIG Identification
GrpID="V-230368"
GrpTitle="SRG-OS-000077-GPOS-00045"
RuleID="SV-230368r599732_rule"
STIGID="RHEL-08-020220"
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
filestocheck="/etc/pam.d/system-auth /etc/pam.d/password-auth"

for filetocheck in $filestocheck; do
 if grep "^password.*[required|requisite].*pam_pwhistory.so.*remember=[5-9]" $filetocheck >> $Results; then
  echo "" >> /dev/null
 else
  echo "remember not set in $filetocheck" >> $Results
  ((scorecheck+=1)) 
 fi
done

if [ "$scorecheck" != 0 ]; then
 echo "Fail" >> $Results 
else 
 echo "Pass" >> $Results
fi
