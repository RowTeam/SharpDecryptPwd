using System;
using System.IO;
using CS_SQLite3;
using System.Data;
using System.Text;
using SharpDecryptPwd.Domain;
using SharpDecryptPwd.Helpers;
using System.Security.Cryptography;
using System.Text.RegularExpressions;

namespace SharpDecryptPwd.Commands
{
    public class Chrome : ICommand
    {

        public static string DecryptWithKey(byte[] encryptedData, byte[] MasterKey)
        {
            byte[] iv = new byte[] { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };

            Array.Copy(encryptedData, 3, iv, 0, 12);

            try
            {
                byte[] Buffer = new byte[encryptedData.Length - 15];
                Array.Copy(encryptedData, 15, Buffer, 0, encryptedData.Length - 15);

                byte[] tag = new byte[16];
                byte[] data = new byte[Buffer.Length - tag.Length];

                Array.Copy(Buffer, Buffer.Length - 16, tag, 0, 16);
                Array.Copy(Buffer, 0, data, 0, Buffer.Length - tag.Length);

                return Encoding.UTF8.GetString(new Lib.Crypt.AesGcm().Decrypt(MasterKey, iv, null, data, tag));
            }
            catch (Exception ex)
            {
                Writer.Failed(ex.Message);
                return null;
            }
        }

        /// <summary>
        /// 80 版本以上新增了一个 MasterKey
        /// </summary>
        public static byte[] GetMasterKey(string filePath)
        {
            byte[] masterKey = new byte[] { };

            if (File.Exists(filePath) == false)
                return null;

            var pattern = new Regex("\"encrypted_key\":\"(.*?)\"", RegexOptions.Compiled).Matches(File.ReadAllText(filePath));

            foreach (Match prof in pattern)
            {
                if (prof.Success)
                    masterKey = Convert.FromBase64String((prof.Groups[1].Value)); //Decode base64
            }

            byte[] temp = new byte[masterKey.Length - 5];
            Array.Copy(masterKey, 5, temp, 0, masterKey.Length - 5);

            try
            {
                return ProtectedData.Unprotect(temp, null, DataProtectionScope.CurrentUser);
            }
            catch (Exception ex)
            {
                Writer.Failed(ex.Message);
                return null;
            }
        }

        public static bool Browser_logins(string login_data_path, string chrome_state_file)
        {
            string login_data_tmpFile = Path.GetTempFileName();
            File.Copy(login_data_path, login_data_tmpFile, true);

            Writer.Log($"Copy {login_data_path} to {login_data_tmpFile}");

            SQLiteDatabase database = new SQLiteDatabase(login_data_tmpFile);
            string query = @"
            SELECT 
                origin_url, 
                username_value, 
                password_value, 
                datetime(date_created / 1000000 + (strftime('%s', '1601-01-01')), 'unixepoch', 'localtime') 
            FROM logins";
            DataTable resultantQuery = database.ExecuteQuery(query);

            foreach (DataRow row in resultantQuery.Rows)
            {
                var url = row["origin_url"].ToString();
                var username = row["username_value"].ToString();
                var crypt_password = row["password_value"].ToString();
                var date_created = row[3].ToString();
                var password = string.Empty;

                byte[] passwordBytes = Convert.FromBase64String(crypt_password);
                try
                {
                    //老版本解密
                    password = Encoding.UTF8.GetString(ProtectedData.Unprotect(passwordBytes, null, DataProtectionScope.CurrentUser));
                }
                catch//如果异常了就用新加密方式尝试
                {
                    byte[] masterKey = GetMasterKey(chrome_state_file);
                    password = DecryptWithKey(passwordBytes, masterKey);
                }

                Writer.Out("URL", url);
                Writer.Out("Date_Created", date_created);
                Writer.Out("USERNAME", username);
                Writer.Out("PASSWORD", password + "\r\n");
            }
            database.CloseDatabase();
            File.Delete(login_data_tmpFile);
            Writer.Log($"Delete File {login_data_tmpFile}");

            return false;
        }

        public static string CommandName => "chrome";

        public void DecryptPwd(ArgumentParserContent arguments)
        {
            string uname = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);

            if (File.Exists(uname + @"\Google\Chrome\User Data\Default\Login Data"))
            {
                Writer.Log("Get Chrome Login Data");

                var login_data_path = uname + @"\Google\Chrome\User Data\Default\Login Data";
                var chrome_state_file = uname + @"\Google\Chrome\User Data\Local State";
                Browser_logins(login_data_path, chrome_state_file);
            }
            else
            {
                Writer.Error("Google 'Login Data' Not Found!");
            }
        }
    }
}
