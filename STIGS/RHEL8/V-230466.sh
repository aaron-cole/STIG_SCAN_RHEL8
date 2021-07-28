#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#

#STIG Identification
GrpID="V-230466"
GrpTitle="SRG-OS-000062-GPOS-00031"
RuleID="SV-230466r627750_rule"
STIGID="RHEL-08-030590"
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

filetocheck="$(grep "^dir = " /etc/security/faillock.conf | awk '{print $3}')"

echo "$filetocheck from /etc/security/faillock" >> $Results
if [ -d $filetocheck ]; then
 if grep "\-w $filetocheck \-p wa" /etc/audit/audit.rules >> $Results; then
  echo "Pass" >> $Results
 else 
  echo "No audit Watch for $filetocheck found or not configured correctly" >> $Results
  echo "Fail" >> $Results
 fi
else
 echo "$filetocheck from /etc/security/faillock does not exist" >> $Results 
 echo "Fail" >> $Results
fi
