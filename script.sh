#!/binbash

echo "Running test on Securing SSH"
#test based on http://www.binbert.com/blog/2010/11/securing-ssh-in-linux-servers/

      permitrootlogin=`grep "^PermitRootLogin" /etc/ssh/sshd_config`
      if [[ $permitrootlogin == "PermitRootLogin no" ]]
      then
      isVulnerability="No"
      else
      isVulnerability="Yes"
      fi
      echo "/etc/ssh/sshd_config - PermitRootLogin Should be set to NO"
      echo "------Vulnerability: $isVulnerability"

      protocol=`grep "^Protocol" /etc/ssh/sshd_config`
      if [[ $protocol == "Protocol 2" ]]
      then
      isVulnerability="No"
      else
      isVulnerability="Yes"
      fi
      echo "/etc/ssh/sshd_config - Protocol Should be set to 2"
      echo "------Vulnerability: $isVulnerability"

      allowTcpForwarding=`grep "^AllowTcpForwarding" /etc/ssh/sshd_config`
      if [[ $allowTcpForwarding == "AllowTcpForwarding no" ]]
      then
      isVulnerability="No"
      else
      isVulnerability="Yes"
      fi
      echo "/etc/ssh/sshd_config - AllowTcpForwarding Should be set to no"
      echo "------Vulnerability: $isVulnerability"

      X11Forwarding=`grep "^X11Forwarding" /etc/ssh/sshd_config`
      if [[ $X11Forwarding == "X11Forwarding no" ]]
      then
      isVulnerability="No"
      else
      isVulnerability="Yes"
      fi
      echo "/etc/ssh/sshd_config - X11Forwarding Should be set to no"
      echo "------Vulnerability: $isVulnerability"

      StrictModes=`grep "^StrictModes" /etc/ssh/sshd_config`
      if [[ $X11Forwarding == "StrictModes yes" ]]
      then
      isVulnerability="No"
      else
      isVulnerability="Yes"
      fi
      echo "/etc/ssh/sshd_config - StrictModes Should be set to yes"
      echo "------Vulnerability: $isVulnerability"

      IgnoreRhosts=`grep "^IgnoreRhosts" /etc/ssh/sshd_config`
      if [[ $X11Forwarding == "IgnoreRhosts yes" ]]
      then
      isVulnerability="No"
      else
      isVulnerability="Yes"
      fi
      echo "/etc/ssh/sshd_config - IgnoreRhosts Should be set to yes"
      echo "------Vulnerability: $isVulnerability"

      HostbasedAuthentication=`grep "^HostbasedAuthentication" /etc/ssh/sshd_config`
      if [[ $X11Forwarding == "HostbasedAuthentication no" ]]
      then
      isVulnerability="No"
      else
      isVulnerability="Yes"
      fi
      echo "/etc/ssh/sshd_config - HostbasedAuthentication Should be set to no"
      echo "------Vulnerability: $isVulnerability"
