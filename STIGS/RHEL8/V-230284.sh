#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#The ".shosts" files are used to configure host-based authentication for individual users or the system via SSH. Host-based authentication is not sufficient for preventing unauthorized access to the system, as it does not require interactive identification and authentication of a connection request, or for the use of two-factor authentication.

#STIG Identification
GrpID="V-230284"
GrpTitle="SRG-OS-000480-GPOS-00227"
RuleID="SV-230284r599732_rule"
STIGID="RHEL-08-010470"
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

if [ $(find / -type f -name "*.shosts" 2>>/dev/null ) ]; then
 echo ".shosts files found" >> $Results
 echo "Fail" >> $Results 
else 
 echo "no .shosts files found" >> $Results
 echo "Pass" >> $Results
fi
