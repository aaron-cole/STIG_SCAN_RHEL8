#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#

#STIG Identification
GrpID="V-230503"
GrpTitle="SRG-OS-000114-GPOS-00059"
RuleID="SV-230503r627750_rule"
STIGID="RHEL-08-040080"
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

grep -r "usb-storage" /etc/modprobe.d | grep -v "^#" >> $Results

if [ "$(grep -r "^install usb-storage \/bin\/true" /etc/modprobe.d)" ]; then 
 if [ "$(grep -r "^blacklist usb-storage" /etc/modprobe.d)" ]; then 
  echo "Pass" >> $Results 
 else
  echo "Blacklist Setting is not defined" >> $Results 
  echo "Fail" >> $Results
 fi
else
 echo "Install Setting is not defined" >> $Results 
 echo "Fail" >> $Results
fi
