#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#

#STIG Identification
GrpID="V-230223"
GrpTitle="SRG-OS-000033-GPOS-00014"
RuleID="SV-230223r627750_rule"
STIGID="RHEL-08-010020"
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

fipscheck 2>>/dev/null >> $Results
if [ "$(fipscheck 2>>/dev/null)" == "fips mode is on" ]; then
 if grub2-editenv - list | grep "fips=1" >> $Results; then
  cat /proc/sys/crypto/fips_enabled >> $Results
  if [ "$(cat /proc/sys/crypto/fips_enabled)" == "1" ]; then
   echo "Pass" >> $Results
  else 
   echo "System is not in FIPS MODE" >> $Results
   echo "Fail" >> $Results
  fi
 else
  echo "Grub not listing FIPS MODE" >> $Results
  echo "Fail" >> $Results
 fi
else
 echo "System is not running in FIPS MODE" >> $Results
 echo "Fail" >> $Results
fi
