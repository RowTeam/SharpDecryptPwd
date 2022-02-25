using Microsoft.Win32;
using SharpDecryptPwd.Domain;
using SharpDecryptPwd.Helpers;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;

namespace SharpDecryptPwd.Commands
{
    class Sunlogin : ICommand
    {
        public static string CommandName => "sunlogin";

        public void DecryptPwd(ArgumentParserContent arguments)
        {
            AutoGetSunLoginPath();
        }
        public static void AutoGetSunLoginPath()
        {
            string reg_path = "SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\Oray SunLogin RemoteClient";
            string reg_path1 = ".DEFAULT\\Software\\Oray\\SunLogin\\SunloginClient\\SunloginGreenInfo";
            string reg_path2 = ".DEFAULT\\Software\\Oray\\SunLogin\\SunloginClient\\SunloginInfo";
            string config_path = "";
            string InstallLocation = "";
            RegistryKey registryKey = Registry.LocalMachine.OpenSubKey(reg_path);
            RegistryKey registryKey1 = Registry.LocalMachine.OpenSubKey(reg_path1);
            RegistryKey registryKey2 = Registry.LocalMachine.OpenSubKey(reg_path2);
            if (registryKey != null)
            {
                InstallLocation = Registry.LocalMachine.OpenSubKey(reg_path).GetValue("InstallLocation").ToString();
                Writer.Out("InstallLocation", InstallLocation);
                config_path = InstallLocation + "\\config.ini";
                Writer.Out("Path", config_path);
                string fileData = File.ReadAllText(config_path);
                string fastcode = Regex.Match(fileData, "fastcode=(.*)", RegexOptions.Multiline).Groups[1].Value;
                string encry_pwd = Regex.Match(fileData, "encry_pwd=(.*)", RegexOptions.Multiline).Groups[1].Value;
                string sunlogincode = Regex.Match(fileData, "sunlogincode=(.*)", RegexOptions.Multiline).Groups[1].Value;
                Writer.Out("Fastcode", fastcode);
                Writer.Out("Encry_pwd", encry_pwd);
                Writer.Out("Sunlogincode", sunlogincode + "\r\n");
            }
            else if (registryKey1 != null)
            {
                string base_fastcode = Registry.LocalMachine.OpenSubKey(reg_path1).GetValue("base_fastcode").ToString();
                string base_encry_pwd = Registry.LocalMachine.OpenSubKey(reg_path1).GetValue("base_encry_pwd").ToString();
                string base_sunlogincode = Registry.LocalMachine.OpenSubKey(reg_path1).GetValue("base_sunlogincode").ToString();
                Writer.Out("Fastcode", base_fastcode);
                Writer.Out("Encry_pwd", base_encry_pwd);
                Writer.Out("Sunlogincode", base_sunlogincode + "\r\n");
            }
            else if (registryKey2 != null)
            {
                string base_fastcode = Registry.LocalMachine.OpenSubKey(reg_path2).GetValue("base_fastcode").ToString();
                string base_encry_pwd = Registry.LocalMachine.OpenSubKey(reg_path2).GetValue("base_encry_pwd").ToString();
                string base_sunlogincode = Registry.LocalMachine.OpenSubKey(reg_path2).GetValue("base_sunlogincode").ToString();
                Writer.Out("Fastcode", base_fastcode);
                Writer.Out("Encry_pwd", base_encry_pwd);
                Writer.Out("Sunlogincode", base_sunlogincode + "\r\n");
            }
            if (File.Exists(@"C:\\ProgramData\\Oray\\SunloginClient\\config.ini"))
            {
                config_path = "C:\\ProgramData\\Oray\\SunloginClient\\config.ini";
                Writer.Out("Path", config_path);
                string fileData = File.ReadAllText(config_path);
                string fastcode = Regex.Match(fileData, "fastcode=(.*)", RegexOptions.Multiline).Groups[1].Value;
                string encry_pwd = Regex.Match(fileData, "encry_pwd=(.*)", RegexOptions.Multiline).Groups[1].Value;
                string sunlogincode = Regex.Match(fileData, "sunlogincode=(.*)", RegexOptions.Multiline).Groups[1].Value;
                Writer.Out("Fastcode", fastcode);
                Writer.Out("Encry_pwd", encry_pwd);
                Writer.Out("Sunlogincode", sunlogincode + "\r\n");

            }
            else if (File.Exists(string.Format("C:\\Users\\{0}\\AppData\\Roaming\\Oray\\SunloginClientLite\\sys_lite_config.ini", Environment.UserName)))
            {
                config_path = string.Format("C:\\Users\\{0}\\AppData\\Roaming\\Oray\\SunloginClientLite\\sys_lite_config.ini", Environment.UserName);
                Writer.Out("Path", config_path);
                string fileData = File.ReadAllText(config_path);
                string fastcode = Regex.Match(fileData, "fastcode=(.*)", RegexOptions.Multiline).Groups[1].Value;
                string encry_pwd = Regex.Match(fileData, "encry_pwd=(.*)", RegexOptions.Multiline).Groups[1].Value;
                string sunlogincode = Regex.Match(fileData, "sunlogincode=(.*)", RegexOptions.Multiline).Groups[1].Value;
                Writer.Out("Fastcode", fastcode);
                Writer.Out("Encry_pwd", encry_pwd);
                Writer.Out("Sunlogincode", sunlogincode + "\r\n");

            }
            else if (File.Exists(@"C:\Windows\system32\config\systemprofile\AppData\Roaming\Oray\SunloginClient\sys_config.ini"))
            {
                config_path = @"C:\Windows\system32\config\systemprofile\AppData\Roaming\Oray\SunloginClient\sys_config.ini";
                Writer.Out("Path", config_path);
                string fileData = File.ReadAllText(config_path);
                string fastcode = Regex.Match(fileData, "fastcode=(.*)", RegexOptions.Multiline).Groups[1].Value;
                string encry_pwd = Regex.Match(fileData, "encry_pwd=(.*)", RegexOptions.Multiline).Groups[1].Value;
                string sunlogincode = Regex.Match(fileData, "sunlogincode=(.*)", RegexOptions.Multiline).Groups[1].Value;
                Writer.Out("Fastcode", fastcode);
                Writer.Out("Encry_pwd", encry_pwd);
                Writer.Out("Sunlogincode", sunlogincode + "\r\n");

            }

        }

    }
}



