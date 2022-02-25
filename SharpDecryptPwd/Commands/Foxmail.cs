using System;
using System.IO;
using SharpDecryptPwd.Domain;
using SharpDecryptPwd.Helpers;

namespace SharpDecryptPwd.Commands
{
    public class Foxmail : ICommand
    {
        /// <summary>
        /// Foxmail password decoder
        /// Credit: Jacob Soo
        /// https://github.com/jacobsoo/FoxmailRecovery/blob/c3263424dd961ec23868d03c9caad13fa5c017ee/Foxmail%20Password%20Recovery/Foxmail%20Password%20Recovery/SharedFunctions.cs#L72
        /// https://github.com/lim42snec/foxmaildump/blob/ca29edc6d767b4e52ee939cdad1d0f8cd7c9f626/FoxmailDump.cpp#L34
        /// </summary>
        public static string DecodePW(int ver, string strHash)
        {
            string decodedPW = string.Empty;
            int[] a;
            int fc0;

            if (ver == 0) // Version 6
            {
                int[] v6a = { '~', 'd', 'r', 'a', 'G', 'o', 'n', '~' };
                a = v6a;
                fc0 = Convert.ToInt32("5A", 16); //90
            }
            else // Version 7
            {
                int[] v7a = { '~', 'F', '@', '7', '%', 'm', '$', '~' };
                a = v7a;
                fc0 = Convert.ToInt32("71", 16); // 113
            }

            int size = strHash.Length / 2;
            int index = 0;
            int[] b = new int[size];
            for (int i = 0; i < size; i++)
            {

                b[i] = Convert.ToInt32(strHash.Substring(index, 2), 16);
                index = index + 2;
            }

            int[] c = new int[b.Length];

            c[0] = b[0] ^ fc0;

            Array.Copy(b, 1, c, 1, b.Length - 1);

            while (b.Length > a.Length)
            {
                int[] newA = new int[a.Length * 2];
                Array.Copy(a, 0, newA, 0, a.Length);
                Array.Copy(a, 0, newA, a.Length, a.Length);
                a = newA;
            }

            int[] d = new int[b.Length];

            for (int i = 1; i < b.Length; i++)
            {
                d[i - 1] = b[i] ^ a[i - 1];

            }

            int[] e = new int[d.Length];

            for (int i = 0; i < d.Length - 1; i++)
            {
                if (d[i] - c[i] < 0)
                {
                    e[i] = d[i] + 255 - c[i];

                }

                else
                {
                    e[i] = d[i] - c[i];
                }

                decodedPW += (char)e[i];
            }

            return decodedPW;
        }

        private static void ParseSecretFiles(string userData, string email, string password)
        {
            using (var fs = new FileStream(userData, FileMode.Open))
            {
                var len = (int)fs.Length;
                var bits = new byte[len];

                bool accfound = false;
                string buffer = "";
                int ver = 0;

                fs.Read(bits, 0, len);

                // 判断foxmail版本，首字节为0xD0，则为6.X版本
                if (bits[0] == 0xD0)
                {
                    // Version 6.X
                    ver = 0;
                }
                else
                {
                    // Version 7.X
                    ver = 1;
                }

                for (int jx = 0; jx < len; ++jx)
                {
                    if (bits[jx] > 0x20 && bits[jx] < 0x7f && bits[jx] != 0x3d)
                    {
                        buffer += (char)bits[jx];
                        string acc = "";
                        if (buffer.Equals("Account") || buffer.Equals("POP3Account"))
                        {
                            accfound = true;

                            int index = jx + 9;

                            if (ver == 0)
                            {
                                index = jx + 2;
                            }
                            while (bits[index] > 0x20 && bits[index] < 0x7f)
                            {
                                acc += (char)bits[index];
                                index++;
                            }

                            jx = index;
                        }

                        else if (accfound && (buffer.Equals("Password") || buffer.Equals("POP3Password")))
                        {
                            int index = jx + 9;
                            if (ver == 0)
                            {
                                index = jx + 2;
                            }
                            string pw = "";

                            while (bits[index] > 0x20 && bits[index] < 0x7f)
                            {
                                pw += (char)bits[index];
                                index++;
                            }
                            password = DecodePW(ver, pw);

                            jx = index;
                            break;
                        }

                        Writer.Out("E-Mail", email);
                        Writer.Out("PASSWORD", password + "\r\n");
                    }
                    else
                    {
                        buffer = "";
                    }
                }
            }

            File.Delete(userData);
        }

        public static string CommandName => "foxmail";

        public void DecryptPwd(ArgumentParserContent arguments)
        {
            string foxPath = arguments.path;
            string userData = string.Empty, email = string.Empty, password = string.Empty;

            if (string.IsNullOrEmpty(foxPath))
            {
                // 获取软件安装路径
                foxPath = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Classes\Foxmail.url.mailto\Shell\open\command").GetValue("").ToString();
                // 处理路径
                foxPath = foxPath.Remove(foxPath.LastIndexOf("Foxmail.exe", StringComparison.Ordinal)).Replace("\"", "") + @"Storage\";

                // 路径处理过程
                foreach (var dir in Directory.GetDirectories(foxPath, "*@*", SearchOption.TopDirectoryOnly))
                {
                    email = dir.Substring(dir.LastIndexOf("\\", StringComparison.Ordinal) + 1);

                    // 测试时，Foxmail 在运行中则出现错误，为了防止这个错误，先复制再读。
                    File.Copy(dir + @"\Accounts\Account.rec0", dir + @"\Accounts\Account.rec1");
                    userData = dir + @"\Accounts\Account.rec1";
                }
            }
            else
            {
                userData = foxPath;
            }

            Writer.Log($"Foxmail Path: {foxPath}");
            Writer.Log($"Foxmail userData: {userData}");

            ParseSecretFiles(userData, email, password);
        }
    }
}
