#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#

#STIG Identification
GrpID="V-230352"
GrpTitle="SRG-OS-000029-GPOS-00010"
RuleID="SV-230352r599732_rule"
STIGID="RHEL-08-020060"
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
 gsettings get org.gnome.desktop.session idle-delay >> $Results 
 if [ "$(gsettings get org.gnome.desktop.session idle-delay | awk '{print $2}')" -gt 0 ] && [ "$(gsettings get org.gnome.desktop.session idle-delay | awk '{print $2}')" -le 900 ] ; then
  echo "Pass" >> $Results
 else 
  echo "Gnome installed Setting not defined" >> $Results
  echo "Fail" >> $Results
 fi
else
 echo "GNOME is not installed" >> $Results
 echo "NA" >> $Results
fi
