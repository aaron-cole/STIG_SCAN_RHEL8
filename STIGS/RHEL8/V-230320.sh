#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#If local interactive users are not assigned a valid home directory, there is no place for the storage and control of files they should own.

#STIG Identification
GrpID="V-230320"
GrpTitle="SRG-OS-000480-GPOS-00227"
RuleID="SV-230320r599732_rule"
STIGID="RHEL-08-010720"
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

if pwck -r | grep "directory" | grep "does not exist" | egrep -v "avahi-autoipd|ftp|saslauth|pulse|gnome|memcached|hacluster" >> $Results 2>>/dev/null; then
 echo "Fail" >> $Results
else
 echo "Nothing Found" >> $Results  
 echo "Pass" >> $Results
fi
