#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#The "shosts.equiv" files are used to configure host-based authentication for the system via SSH. Host-based authentication is not sufficient for preventing unauthorized access to the system, as it does not require interactive identification and authentication of a connection request, or for the use of two-factor authentication.

#STIG Identification
GrpID="V-230283"
GrpTitle="SRG-OS-000480-GPOS-00227"
RuleID="SV-230283r627750_rule"
STIGID="RHEL-08-010460"
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

if [ $(find / -type f -name "shosts.equiv" 2>>/dev/null) ]; then
 echo ".shosts.equiv files found" >> $Results
 echo "Fail" >> $Results 
else 
 echo "NO .shosts.equiv files found" >> $Results
 echo "Pass" >> $Results
fi
