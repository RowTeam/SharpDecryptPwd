using System;
using System.IO;
using System.Xml;
using System.Text;
using SharpDecryptPwd.Domain;
using SharpDecryptPwd.Helpers;

namespace SharpDecryptPwd.Commands
{
    public class FileZilla : ICommand
    {
        public static string CommandName => "filezilla";

        public void DecryptPwd(ArgumentParserContent arguments)
        {
            string fzPath = string.Empty;
            if (string.IsNullOrEmpty(arguments.path))
            {
                fzPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), @"FileZilla\recentservers.xml");
            }
            else
            {
                fzPath = arguments.path;
            }

            if (File.Exists(fzPath))
            {
                try
                {
                    var objXmlDocument = new XmlDocument();
                    objXmlDocument.Load(fzPath);
                    foreach (XmlElement XE in ((XmlElement)objXmlDocument.GetElementsByTagName("RecentServers")[0]).GetElementsByTagName("Server"))
                    {
                        var host = XE.GetElementsByTagName("Host")[0].InnerText;
                        var port = XE.GetElementsByTagName("Port")[0].InnerText;
                        var username = XE.GetElementsByTagName("User")[0].InnerText;
                        var password = (Encoding.UTF8.GetString(Convert.FromBase64String(XE.GetElementsByTagName("Pass")[0].InnerText)));

                        if (!string.IsNullOrEmpty(host) && !string.IsNullOrEmpty(port) && !string.IsNullOrEmpty(username) && !string.IsNullOrEmpty(password))
                        {
                            Writer.Out("Host", host);
                            Writer.Out("Port", port);
                            Writer.Out("User", username);
                            Writer.Out("Pass", password + "\r\n");
                        }
                        else
                        {
                            break;
                        }
                    }
                }
                catch (Exception ex)
                {
                    Writer.Error(ex.Message);
                }
            }
        }
    }
}
