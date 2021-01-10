#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#

#STIG Identification
GrpID="V-230342"
GrpTitle="SRG-OS-000021-GPOS-00005"
RuleID="SV-230342r599837_rule"
STIGID="RHEL-08-020020"
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
 if grep "^auth.*required.*pam_faillock.so preauth.*audit" $filetocheck >> $Results; then
  echo "" >> /dev/null
 else
  echo "audit not set in $filetocheck" >> $Results
  ((scorecheck+=1)) 
 fi
done

if [ "$scorecheck" != 0 ]; then
 echo "Fail" >> $Results 
else 
 echo "Pass" >> $Results
fi