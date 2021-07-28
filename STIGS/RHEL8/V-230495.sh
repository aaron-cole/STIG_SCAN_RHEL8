#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#

#STIG Identification
GrpID="V-230495"
GrpTitle="SRG-OS-000095-GPOS-00049"
RuleID="SV-230495r627750_rule"
STIGID="RHEL-08-040022"
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

grep -r "CAN" /etc/modprobe.d | grep -v "^#" >> $Results

if [ "$(grep -r "^install CAN \/bin\/true" /etc/modprobe.d)" ]; then 
 if [ "$(grep -r "^blacklist CAN" /etc/modprobe.d)" ]; then 
  echo "Pass" >> $Results 
 else
  echo "Blacklist Setting is not defined" >> $Results 
  echo "Fail" >> $Results
 fi
else
 echo "Install Setting is not defined" >> $Results 
 echo "Fail" >> $Results
fi
