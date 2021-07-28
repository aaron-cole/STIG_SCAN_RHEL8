 #!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#

#STIG Identification
GrpID="V-230347"
GrpTitle="SRG-OS-000028-GPOS-00009"
RuleID="SV-230347r627750_rule"
STIGID="RHEL-08-020030"
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
 gsettings get org.gnome.desktop.screensaver lock-enabled >> $Results 
 if [ "$(gsettings get org.gnome.desktop.screensaver lock-enabled)" == "true" ]; then
  echo "Pass" >> $Results
 else 
  echo "Gnome installed Setting not defined" >> $Results
  echo "Fail" >> $Results
 fi
else
 echo "GNOME is not installed" >> $Results
 echo "NA" >> $Results
fi
