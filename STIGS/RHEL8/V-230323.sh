#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#If a local interactive user has a home directory defined that does not exist, the user may be given access to the "/" directory as the current working directory upon logon. This could create a denial of service because the user would not be able to access their logon configuration files, and it may give them visibility to system files they normally would not be able to access.

#STIG Identification
GrpID="V-230323"
GrpTitle="SRG-OS-000480-GPOS-00227"
RuleID="SV-230323r599732_rule"
STIGID="RHEL-08-010750"
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

if pwck -r | grep "directory" | grep "does not exist" | egrep -v "avahi-autoipd|ftp|saslauth|pulse|gnome|memcached|hacluster|clevis|rngd|cockpit-wsinstance" >> $Results 2>>/dev/null; then
 echo "Fail" >> $Results
else
 echo "Nothing Found" >> $Results  
 echo "Pass" >> $Results
fi
