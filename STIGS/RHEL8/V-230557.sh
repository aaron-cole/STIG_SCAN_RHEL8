#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#Restricting TFTP to a specific directory prevents remote users from copying, transferring, or overwriting system files.

#STIG Identification
GrpID="V-230557"
GrpTitle="SRG-OS-000480-GPOS-00227"
RuleID="SV-230557r627750_rule"
STIGID="RHEL-08-040350"
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

if rpm -q tftp-server >> $Results; then
 if grep "server_args" /etc/xinetd.d/tftp | grep -v "#" | grep "= -s /[A-Za-z].*" >> $Results; then
  echo "Pass" >> $Results
 else
  echo "Setting Not Defined Correctly" >> $Results
  echo "Fail" >> $Results
 fi
else 
 echo "NA" >> $Results
fi
