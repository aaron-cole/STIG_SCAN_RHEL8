#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#Leaving the user list enabled is a security risk since it allows anyone with physical access to the system to enumerate known user accounts without authenticated access to the system.

#STIG Identification
GrpID="V-244536"
GrpTitle="SRG-OS-000480-GPOS-00227"
RuleID="SV-244536r743857_rule"
STIGID="RHEL-08-020032"
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

if rpm -q gnome-desktop3 >> $Results; then 
 if grep -R "disable-user-list='false'" /etc/dconf/db/* >> $Results; then
  echo "Pass" >> $Results
 else 
  echo "Installed Setting not defined" >> $Results
  echo "Fail" >> $Results
 fi
else
 echo "GNOME is not installed" >> $Results
 echo "NA" >> $Results
fi
