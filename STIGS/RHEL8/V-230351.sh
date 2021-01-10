#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#

#STIG Identification
GrpID="V-230351"
GrpTitle="SRG-OS-000028-GPOS-00009"
RuleID="SV-230351r599792_rule"
STIGID="RHEL-08-020050"
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

#if rpm -q gnome-desktop3 >> $Results; then 
 if grep -R "removal-action='lock-screen'" /etc/dconf/db/* >> $Results; then
  echo "Pass" >> $Results
 else 
  echo "Installed Setting not defined" >> $Results
  echo "Fail" >> $Results
 fi
#else
# echo "GNOME is not installed" >> $Results
# echo "NA" >> $Results
#fi
