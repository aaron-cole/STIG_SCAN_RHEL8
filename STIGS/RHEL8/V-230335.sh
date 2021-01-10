#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#

#STIG Identification
GrpID="V-230335"
GrpTitle="SRG-OS-000021-GPOS-00005"
RuleID="SV-230335r599830_rule"
STIGID="RHEL-08-020013"
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
 if grep "^auth.*required.*pam_faillock.so preauth" $filetocheck >> $Results; then
  echo "" >> /dev/null
 else
  echo "auth pam_faillock.so preauth not set in $filetocheck" >> $Results
  ((scorecheck+=1)) 
 fi
 if grep "^auth.*required.*pam_faillock.so authfail" $filetocheck >> $Results; then
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

if grep "^fail_interval = " /etc/security/faillock.conf >> $Results; then
 if [ "$(grep "^fail_interval = " /etc/security/faillock.conf | awk '{print $3}')" -le 900 ]; then
  echo "" >> /dev/null
 else
  echo "fail_interval greater than 900" >> $Results 
  ((scorecheck+=1))
 fi  
else
 echo "fail_interval not configured in /etc/security/faillock.conf" >> $Results
 ((scorecheck+=1))
fi

if [ "$scorecheck" != 0 ]; then
 echo "Fail" >> $Results 
else 
 echo "Pass" >> $Results
fi
