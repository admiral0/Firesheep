//
// linux_platform.cpp: Linux functions
// Part of the Firesheep project.
//
// Copyright (C) 2010 Eric Butler
//
// Authors:
//   Michajlo Matijkiw <michajlo.matijkiw@gmail.com>
//   Nick Kossifidis <mickflemm@gmail.com>
//   Eric Butler <eric@codebutler.com>
//   Radu Andries <admiral0@tuxfamily.org>
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

#include <iostream>
#include <cstdio>
#include <cstdlib>
#include <pcap/pcap.h>
#include "linux_platform.hpp"
#include <iwlib.h>

using namespace std;
using namespace boost;

vector<InterfaceInfo> LinuxPlatform::ifaces;
LinuxPlatform::LinuxPlatform(string path) : UnixPlatform(path) { }

bool LinuxPlatform::run_privileged() 
{
  string cmd = string("/usr/bin/pkexec ");
  cmd += this->path();
  cmd += " --fix-permissions";

  int ret = system(cmd.c_str());
  return (ret == 0);
}

/*
 * Gather info
 */
static int collect_info(int skfd, char *ifname, char *args[], int count) {
  string id,desc,type;
  id=string(ifname);
  /* Some defaults */
  type=string("ieee80211");
  desc=id;
  
  /* Avoid "Unused parameter" warning */
  args = args; count = count;
  
  /* Basic info */
  struct wireless_info	infoc;
  struct wireless_info *info;
  info=&infoc;
  /* Zero all the things! */
  memset((char *) info, 0, sizeof(struct wireless_info));
  
  /* Get basic information */
  if(iw_get_basic_config(skfd, ifname, &(info->b)) < 0)
    {
      /* If no wireless name : no wireless extensions */
      /* But let's check if the interface exists at all */
      struct ifreq ifr;

      strncpy(ifr.ifr_name, ifname, IFNAMSIZ);
      if(ioctl(skfd, SIOCGIFFLAGS, &ifr) < 0)
	return 0;
      /* Assuming it's ethernet */
      else
	type=string("ethernet");
    }
  if(info->b.has_mode) {
    if(info->b.mode==6){
      type=string("ieee80211_monitor");
    }
  }
  InterfaceInfo hinfo(id, desc, type);
  LinuxPlatform::addInterface(hinfo);
  return 0;
}


vector<InterfaceInfo> LinuxPlatform::interfaces()
{
  
  int skfd;		/* generic raw socket desc.	*/
  int goterr = 0;

  /* Clean all the things!!! */
  ifaces.clear();
  /* Create a channel to the NET kernel. */
  if((skfd = iw_sockets_open()) < 0) {
      perror("socket");
      throw runtime_error("Cannot open channel to NET kernel");
  }
  
  
  iw_enum_devices(skfd, &collect_info, NULL, 0);
  
  /* Close the socket. */
  iw_sockets_close(skfd);

  return ifaces; 
}

