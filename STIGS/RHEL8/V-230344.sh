#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#

#STIG Identification
GrpID="V-230344"
GrpTitle="SRG-OS-000021-GPOS-00005"
RuleID="SV-230344r599839_rule"
STIGID="RHEL-08-020022"
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
rhel8version="$(rpm -qi redhat-release | grep "^Version" | awk '{print $3}')"

if (( $(echo "$rhel8version > 8.1" | bc -l) )); then
 echo "RHEL Version is $rhel8version" >> $Results
 echo "NA" >> $Results
else
 for filetocheck in $filestocheck; do
  if grep "^auth.*required.*pam_faillock.so preauth.*even_deny_root" $filetocheck >> $Results; then
   echo "" >> /dev/null
  else
   echo "even_deny_root not set in $filetocheck" >> $Results
   ((scorecheck+=1)) 
  fi
 done

 if [ "$scorecheck" != 0 ]; then
  echo "Fail" >> $Results 
 else 
  echo "Pass" >> $Results
 fi
fi
