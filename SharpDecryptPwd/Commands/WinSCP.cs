using SharpDecryptPwd.Domain;
using SharpDecryptPwd.Helpers;
using System;
using System.IO;

namespace SharpDecryptPwd.Commands
{
    class WinSCP : ICommand
    {
        static readonly int PW_MAGIC = 0xA3;
        static readonly char PW_FLAG = (char)0xFF;

        struct Flags
        {
            public char flag;
            public string remainingPass;
        }

        private static Flags DecryptNextCharacterWinSCP(string passwd)
        {
            Flags Flag;
            string bases = "0123456789ABCDEF";

            int firstval = bases.IndexOf(passwd[0]) * 16;
            int secondval = bases.IndexOf(passwd[1]);
            int Added = firstval + secondval;
            Flag.flag = (char)(((~(Added ^ PW_MAGIC) % 256) + 256) % 256);
            Flag.remainingPass = passwd.Substring(2);
            return Flag;
        }

        private static string DecryptWinSCPPassword(string Host, string userName, string passWord)
        {
            var clearpwd = string.Empty;
            char length;
            string unicodeKey = userName + Host;
            Flags Flag = DecryptNextCharacterWinSCP(passWord);

            int storedFlag = Flag.flag;

            if (storedFlag == PW_FLAG)
            {
                Flag = DecryptNextCharacterWinSCP(Flag.remainingPass);
                Flag = DecryptNextCharacterWinSCP(Flag.remainingPass);
                length = Flag.flag;
            }
            else
            {
                length = Flag.flag;
            }

            Flag = DecryptNextCharacterWinSCP(Flag.remainingPass);
            Flag.remainingPass = Flag.remainingPass.Substring(Flag.flag * 2);

            for (int i = 0; i < length; i++)
            {
                Flag = DecryptNextCharacterWinSCP(Flag.remainingPass);
                clearpwd += Flag.flag;
            }
            if (storedFlag == PW_FLAG)
            {
                if (clearpwd.Substring(0, unicodeKey.Length) == unicodeKey)
                {
                    clearpwd = clearpwd.Substring(unicodeKey.Length);
                }
                else
                {
                    clearpwd = "";
                }
            }
            return clearpwd;
        }

        public static string CommandName => "winscp";

        public void DecryptPwd(ArgumentParserContent arguments)
        {
            // 如果是安装版本，则信息在注册表中，如果是便捷式版本，则在　C:\Users\John\AppData\Roaming\winscp.ini 中
            string registry = @"Software\Martin Prikryl\WinSCP 2\Sessions";
            var registryKey = Microsoft.Win32.Registry.CurrentUser.OpenSubKey(registry);
            if (registryKey != null)
            {
                Writer.Log($@"WinSCP 2 registry location: HKEY_LOCAL_MACHINE\{registry}");
                using (registryKey)
                {
                    foreach (string rname in registryKey.GetSubKeyNames())
                    {
                        using (var session = registryKey.OpenSubKey(rname))
                        {
                            if (session != null)
                            {
                                string hostname = (session.GetValue("HostName") != null) ? session.GetValue("HostName").ToString() : "";
                                if (string.IsNullOrEmpty(hostname))
                                {
                                    try
                                    {
                                        string username = session.GetValue("UserName").ToString();
                                        string password = session.GetValue("Password").ToString();
                                        Writer.Out("hostname", hostname);
                                        Writer.Out("username", username);
                                        Writer.Out("rawpass", password);
                                        Writer.Out("password", DecryptWinSCPPassword(hostname, username, password) + "\r\n");
                                    }
                                    catch
                                    { }
                                }
                            }
                        }
                    }
                }
            }else
            {
                Writer.Log($@"Not Find WinSCP 2 registry location: HKEY_LOCAL_MACHINE\{registry}");
            }

        }
    }
}
