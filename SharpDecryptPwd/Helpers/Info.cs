using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace SharpDecryptPwd.Helpers
{
    public class Info
    {
        public static void ShowLogo()
        {
            Console.WriteLine($@"
   _____ _                      _____                             _   _____              _ 
  / ____| |                    |  __ \                           | | |  __ \            | |
 | (___ | |__   __ _ _ __ _ __ | |  | | ___  ___ _ __ _   _ _ __ | |_| |__) |_      ____| |
  \___ \| '_ \ / _` | '__| '_ \| |  | |/ _ \/ __| '__| | | | '_ \| __|  ___/\ \ /\ / / _` |
  ____) | | | | (_| | |  | |_) | |__| |  __/ (__| |  | |_| | |_) | |_| |     \ V  V / (_| |
 |_____/|_| |_|\__,_|_|  | .__/|_____/ \___|\___|_|   \__, | .__/ \__|_|      \_/\_/ \__,_|
                         | |                           __/ | |                             
                         |_|                          |___/|_|           by Rcoil  V 2.3.0                                                                                
");
        }

        public static void ShowUsage()
        {
            string FileName = System.Diagnostics.Process.GetCurrentProcess().ProcessName;
            string usage = $@"
### Command Line Usage ###

    {FileName} Navicat
    {FileName} Xmanager 
    {FileName} TeamViewer
    {FileName} FileZilla
    {FileName} Foxmail
    {FileName} TortoiseSVN
    {FileName} WinSCP
    {FileName} Chrome
    {FileName} RDCMan
    {FileName} SunLogin

";
            Console.WriteLine(usage);
            Environment.Exit(0);
        }
    }
}
