#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#

#STIG Identification
GrpID="V-230258"
GrpTitle="SRG-OS-000259-GPOS-00100"
RuleID="SV-230258r599732_rule"
STIGID="RHEL-08-010310"
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

if [ $(find -L /bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin ! -user root) ] ; then 
 echo "Fail" >> $Results 
else
 echo "Nothing Found" >> $Results 
 echo "Pass" >> $Results
fi
