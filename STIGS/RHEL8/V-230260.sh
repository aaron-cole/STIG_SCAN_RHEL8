#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#

#STIG Identification
GrpID="V-230260"
GrpTitle="SRG-OS-000259-GPOS-00100"
RuleID="SV-230260r627750_rule"
STIGID="RHEL-08-010330"
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

if find -L /lib /lib64 /usr/lib /usr/lib64 -perm /0022 -type f >> $Results ; then 
 echo "Fail" >> $Results 
else
 echo "Nothing Found" >> $Results 
 echo "Pass" >> $Results
fi
