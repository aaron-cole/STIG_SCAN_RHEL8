#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#Cron logging can be used to trace the successful or unsuccessful execution of cron jobs. It can also be used to spot intrusions into the use of the cron facility by unauthorized and malicious users.

#STIG Identification
GrpID="V-230387"
GrpTitle="SRG-OS-000480-GPOS-00227"
RuleID="SV-230387r599732_rule"
STIGID="RHEL-08-030010"
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

if [ "$(grep "^cron\.\*" /etc/rsyslog.conf)" ] || [ "$(grep "^cron\.\*" /etc/rsyslog.d/*.conf)" ]; then
 grep "^cron\.\*" /etc/rsyslog.conf /etc/rsyslog.d/*.conf >> $Results 2>>/dev/null
 echo "Pass" >> $Results
elif [ "$(grep "^\*\.\*" /etc/rsyslog.conf)" ] || [ "$(grep "^\*\.\*" /etc/rsyslog.d/*.conf)" ]; then
 grep "^\*\.\*" /etc/rsyslog.conf /etc/rsyslog.d/*.conf >> $Results 2>>/dev/null
 echo "Pass" >> $Results
else
 echo "cron logging not found" >> $Results 
 echo "Fail" >> $Results
fi
