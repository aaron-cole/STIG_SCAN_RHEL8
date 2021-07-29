#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#

#STIG Identification
GrpID="V-237642"
GrpTitle="SRG-OS-000480-GPOS-00227"
RuleID="SV-237642r646896_rule"
STIGID="RHEL-08-010383"
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

if grep '!targetpw' /etc/sudoers /etc/sudoers.d/* 2>>$Results | grep "Defaults" | grep -v "^#" >> $Results; then 
 if grep '!rootpw' /etc/sudoers /etc/sudoers.d/* 2>>$Results | grep "Defaults" | grep -v "^#" >> $Results; then 
  if grep '!runaspw' /etc/sudoers /etc/sudoers.d/* 2>>$Results | grep "Defaults" | grep -v "^#" >> $Results; then 
   echo "Pass" >> $Results
  else 
   echo "Fail" >> $Results
  fi
 else
  echo "Fail" >> $Results
 fi
else
 echo "Fail" >> $Results
fi
