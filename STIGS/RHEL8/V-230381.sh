#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#Providing users with feedback on when account accesses last occurred facilitates user recognition and reporting of unauthorized account use.

#STIG Identification
GrpID="V-230381"
GrpTitle="SRG-OS-000480-GPOS-00227"
RuleID="SV-230381r599732_rule"
STIGID="RHEL-08-020340"
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

if grep "^session.*required.*pam_lastlog.so.*showfailed" /etc/pam.d/postlogin | grep -v "silent" >> $Results; then
 echo "Pass" >> $Results
else
 echo "Not Defined Correctly in /etc/pam.d/postlogin" >> $Results
 echo "Fail" >> $Results
fi
