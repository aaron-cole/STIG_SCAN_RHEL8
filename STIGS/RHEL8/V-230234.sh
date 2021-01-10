#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#If the system does not require valid authentication before it boots into single-user or maintenance mode, anyone who invokes single-user or maintenance mode is granted privileged access to all files on the system. GRUB 2 is the default boot loader for RHEL 8 and is designed to require a password to boot into single-user mode or make modifications to the boot menu.

#STIG Identification
GrpID="V-230234"
GrpTitle="SRG-OS-000080-GPOS-00048"
RuleID="SV-230234r599732_rule"
STIGID="RHEL-08-010140"
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

if [ -e /boot/grub2/grub.cfg ]; then 
 echo "Server is using BIOS" >> $Results
 echo "NA" >> $Results
elif [ "$(rpm -qi redhat-release-server | grep "^Version" | awk '{print $3}' | cut -f 2 -d ".")" -lt 2 ]; then
 rpm -q redhat-release-server >> $Results
 echo "NA" >> $Results
elif [ -e /boot/efi/EFI/redhat/user.cfg ] && [ "$(grep "^GRUB2_PASSWORD=grub.pbkdf2.sha512" /boot/efi/EFI/redhat/user.cfg)" ]; then
 echo "Grub Password is defined - $(grep "^GRUB2_PASSWORD=grub.pbkdf2.sha512" /boot/efi/EFI/redhat/user.cfg)" >> $Results
 if grep 'set superusers="root"' /boot/efi/EFI/redhat/grub.cfg >> $Results; then
  echo "superusers set as root" >> $Results
  echo "Pass" >> $Results
 else
  echo "superusers not set as root" >> $Results
  echo "Fail" >> $Results
 fi
else 
 echo "Fail" >> $Results
fi
