#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#

#STIG Identification
GrpID="V-244533"
GrpTitle="SRG-OS-000021-GPOS-00005"
RuleID="SV-244533r743848_rule"
STIGID="RHEL-08-020025"
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
rhel8version="$(rpm -qi redhat-release | grep "^Version" | awk '{print $3}')"

if (( $(echo "$rhel8version < 8.2" | bc -l) )); then
 echo "RHEL Version is $rhel8version" >> $Results
 echo "NA" >> $Results
else
 if grep "^auth.*[required|requisite].*pam_faillock.so.*preauth" /etc/pam.d/system-auth >> $Results; then
  echo "Pass" >> $Results
 else
  grep "^auth.*pam_faillock.so.*preauth" /etc/pam.d/system-auth >> $Results
  echo "auth preauth not set in $filetocheck" >> $Results
  echo "Fail" >> $Results  
 fi
fi
