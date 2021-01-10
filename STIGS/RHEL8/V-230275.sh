#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#

#STIG Identification
GrpID="V-230275"
GrpTitle="SRG-OS-000376-GPOS-00161"
RuleID="SV-230275r599732_rule"
STIGID="RHEL-08-010410"
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

if rpm -q gnutls >> $Results; then
 if rpm -q opensc >> $Results; then
  if opensc-tool --list-drivers | grep "PIV-II" >> $Results; then
   echo "Pass" >> $Results
  else 
   echo "PIV Drivers not installed" >> $Results
   echo "Fail" >> $Results
  fi
 else
  echo "opensc not installed" >> $Results
  echo "Fail" >> $Results
 fi
else 
 echo "Fail" >> $Results
fi
