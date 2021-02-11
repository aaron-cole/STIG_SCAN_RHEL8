#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#

#STIG Identification
GrpID="V-230333"
GrpTitle="SRG-OS-000021-GPOS-00005"
RuleID="SV-230333r599828_rule"
STIGID="RHEL-08-020011"
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
 if grep "^auth.*req.*pam_faillock.so preauth" $filetocheck >> $Results; then
  echo "" >> /dev/null
 else
  echo "auth pam_faillock.so preauth not set in $filetocheck" >> $Results
  ((scorecheck+=1)) 
 fi
 if grep "^auth.*req*.*pam_faillock.so authfail" $filetocheck >> $Results; then
  echo "" >> /dev/null
 elif grep "^auth.*default=die*.*pam_faillock.so authfail" $filetocheck >> $Results; then
  echo "" >> /dev/null
 else
  echo "auth pam_faillock.so authfail not set in $filetocheck" >> $Results
  ((scorecheck+=1)) 
 fi
 if grep "^account.*required.*pam_faillock.so" $filetocheck >> $Results; then
  echo "" >> /dev/null
 else
  echo "account pam_faillock.so not set in $filetocheck" >> $Results
  ((scorecheck+=1)) 
 fi
done

if grep "^deny = [1-3]" /etc/security/faillock.conf >> $Results; then
 echo "" >> /dev/null
else
 echo "deny is either not set or not configured in /etc/security/faillock.conf" >> $Results
 ((scorecheck+=1))
fi

if [ "$scorecheck" != 0 ]; then
 echo "Fail" >> $Results 
else 
 echo "Pass" >> $Results
fi
