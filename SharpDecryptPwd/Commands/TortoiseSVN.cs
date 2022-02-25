using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using SharpDecryptPwd.Domain;
using System.Runtime.InteropServices;
using System.IO;
using System.ComponentModel;
using SharpDecryptPwd.Helpers;

namespace SharpDecryptPwd.Commands
{

    internal class AuthFileParser
    {

        // Set a limit on maximum lines parsed to avoid stalling out on big files
        const int MAX_LINES = 1000;

        // Parser states
        enum States
        {
            ExpectingKeyDef,
            ExpectingKeyName,
            ExpectingValueDef,
            ExpectingValue
        }

        // Current state
        private States state = States.ExpectingKeyDef;

        // Data persisted between states
        private string keyName = "";
        private int nextLength = -1;

        // Values read so far
        private Dictionary<string, string> props = new Dictionary<string, string>();

        // Only allow access through static ReadFile() method
        private AuthFileParser() { }

        private bool tryParseNextLine(string line)
        {

            switch (state)
            {
                case States.ExpectingKeyDef: return parseKeyDef(line);
                case States.ExpectingKeyName: return parseKeyName(line);
                case States.ExpectingValueDef: return parseValueDef(line);
                case States.ExpectingValue: return parseValue(line);
                default: return false;
            }

        }

        private bool parseKeyDef(string line)
        {
            if (!parseDefLine("K", line)) return false;
            state = States.ExpectingKeyName;
            return true;
        }

        private bool parseKeyName(string line)
        {
            if (!parseValLine(line)) return false;
            state = States.ExpectingValueDef;
            return true;
        }

        private bool parseValueDef(string line)
        {
            if (!parseDefLine("V", line)) return false;
            state = States.ExpectingValue;
            return true;
        }

        private bool parseValue(string line)
        {
            if (!parseValLine(line)) return false;
            state = States.ExpectingKeyDef;
            return true;
        }

        // Do some rudimentary validation to ensure the current line looks like a definition
        // line, then parse it.  A definition line looks something like "K #" or "V #",
        // where # is the length of the next line.  K means the next line will be a key name,
        // while V means it will be a value.  # will be stored in nextLength.
        private bool parseDefLine(string prefix, string line)
        {
            line = line.Trim();
            if (!line.ToUpper().StartsWith(prefix + " ")) return false;
            string[] parts = line.Split(' ');
            if (parts.Length != 2) return false;
            if (!int.TryParse(parts[1], out nextLength)) return false;
            return true;
        }

        // Read a key name or value line.  If this is a value line, then save the key/value
        // pair that has just been read.
        private bool parseValLine(string line)
        {

            if (line.Length < nextLength) return false;
            string val = line.Substring(0, nextLength);
            nextLength = -1;

            if (state == States.ExpectingKeyName)
            {
                keyName = val.Trim();
                if (keyName == "") return false;
                if (keyName.Contains(" ")) return false;
            }
            else
            {
                props.Add(keyName, val);
                keyName = "";
            }

            return true;
        }

        public static Dictionary<string, string> ReadFile(string path)
        {
            AuthFileParser parser = new AuthFileParser();
            using (StreamReader rd = File.OpenText(path))
            {

                int lineNum = 1;
                string line = rd.ReadLine();
                while (line != null)
                {

                    if (lineNum > MAX_LINES) break;

                    // Skip comment lines
                    if (!line.Trim().StartsWith("#"))
                    {

                        // Check for end of file marker
                        if (parser.state == States.ExpectingKeyDef && line.Trim().ToUpper() == "END")
                        {
                            return parser.props;  // Return results
                        }

                        // Attempt to parse the line
                        if (!parser.tryParseNextLine(line)) throw new AuthParseException(path, lineNum);

                    }

                    // Read next line
                    lineNum++;
                    line = rd.ReadLine();

                }

                // If reached this point, we either encountered too many lines or the file
                // ended prematurely.
                throw new AuthParseException(path, -1);
            }

        }
    }

    internal class AuthParseException : Exception
    {

        private string path;
        private int lineNum;

        public AuthParseException(string path, int lineNum)
        {
            this.path = path;
            this.lineNum = lineNum;
        }

        public string Path
        {
            get { return path; }
        }
        public int LineNum
        {
            get { return lineNum; }
        }

        public override string Message
        {
            get
            {
                if (lineNum != -1)
                {
                    return String.Format("Error parsing line {0} of {1}", lineNum, path);
                }
                else
                {
                    return String.Format("Error parsing {0}", path);
                }
            }
        }

    }

    /// <summary>
    /// Encrypts and decrypts data using DPAPI functions.
    /// </summary>
    internal class DPAPI
    {
        // Wrapper for DPAPI CryptProtectData function.
        [DllImport("crypt32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        private static extern bool CryptProtectData(ref DATA_BLOB pPlainText,
                                        string szDescription,
                                    ref DATA_BLOB pEntropy,
                                        IntPtr pReserved,
                                    ref CRYPTPROTECT_PROMPTSTRUCT pPrompt,
                                        int dwFlags,
                                    ref DATA_BLOB pCipherText);

        // Wrapper for DPAPI CryptUnprotectData function.
        [DllImport("crypt32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        private static extern bool CryptUnprotectData(ref DATA_BLOB pCipherText,
                                    ref string pszDescription,
                                    ref DATA_BLOB pEntropy,
                                        IntPtr pReserved,
                                    ref CRYPTPROTECT_PROMPTSTRUCT pPrompt,
                                        int dwFlags,
                                    ref DATA_BLOB pPlainText);

        // BLOB structure used to pass data to DPAPI functions.
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        internal struct DATA_BLOB
        {
            public int cbData;
            public IntPtr pbData;
        }

        // Prompt structure to be used for required parameters.
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        internal struct CRYPTPROTECT_PROMPTSTRUCT
        {
            public int cbSize;
            public int dwPromptFlags;
            public IntPtr hwndApp;
            public string szPrompt;
        }

        // Wrapper for the NULL handle or pointer.
        static private IntPtr NullPtr = ((IntPtr)((int)(0)));

        // DPAPI key initialization flags.
        private const int CRYPTPROTECT_UI_FORBIDDEN = 0x1;
        private const int CRYPTPROTECT_LOCAL_MACHINE = 0x4;

        /// <summary>
        /// Initializes empty prompt structure.
        /// </summary>
        /// <param name="ps">
        /// Prompt parameter (which we do not actually need).
        /// </param>
        private static void InitPrompt(ref CRYPTPROTECT_PROMPTSTRUCT ps)
        {
            ps.cbSize = Marshal.SizeOf(
                                      typeof(CRYPTPROTECT_PROMPTSTRUCT));
            ps.dwPromptFlags = 0;
            ps.hwndApp = NullPtr;
            ps.szPrompt = null;
        }

        /// <summary>
        /// Initializes a BLOB structure from a byte array.
        /// </summary>
        /// <param name="data">
        /// Original data in a byte array format.
        /// </param>
        /// <param name="blob">
        /// Returned blob structure.
        /// </param>
        private static void InitBLOB(byte[] data, ref DATA_BLOB blob)
        {
            // Use empty array for null parameter.
            if (data == null)
                data = new byte[0];

            // Allocate memory for the BLOB data.
            blob.pbData = Marshal.AllocHGlobal(data.Length);

            // Make sure that memory allocation was successful.
            if (blob.pbData == IntPtr.Zero)
                throw new Exception(
                    "Unable to allocate data buffer for BLOB structure.");

            // Specify number of bytes in the BLOB.
            blob.cbData = data.Length;

            // Copy data from original source to the BLOB structure.
            Marshal.Copy(data, 0, blob.pbData, data.Length);
        }

        // Flag indicating the type of key. DPAPI terminology refers to
        // key types as user store or machine store.
        public enum KeyType { UserKey = 1, MachineKey };

        // It is reasonable to set default key type to user key.
        private static KeyType defaultKeyType = KeyType.UserKey;

        /// <summary>
        /// Calls DPAPI CryptProtectData function to encrypt a plaintext
        /// string value with a user-specific key. This function does not
        /// specify data description and additional entropy.
        /// </summary>
        /// <param name="plainText">
        /// Plaintext data to be encrypted.
        /// </param>
        /// <returns>
        /// Encrypted value in a base64-encoded format.
        /// </returns>
        public static string Encrypt(string plainText)
        {
            return Encrypt(defaultKeyType, plainText, String.Empty,
                            String.Empty);
        }

        /// <summary>
        /// Calls DPAPI CryptProtectData function to encrypt a plaintext
        /// string value. This function does not specify data description
        /// and additional entropy.
        /// </summary>
        /// <param name="keyType">
        /// Defines type of encryption key to use. When user key is
        /// specified, any application running under the same user account
        /// as the one making this call, will be able to decrypt data.
        /// Machine key will allow any application running on the same
        /// computer where data were encrypted to perform decryption.
        /// Note: If optional entropy is specifed, it will be required
        /// for decryption.
        /// </param>
        /// <param name="plainText">
        /// Plaintext data to be encrypted.
        /// </param>
        /// <returns>
        /// Encrypted value in a base64-encoded format.
        /// </returns>
        public static string Encrypt(KeyType keyType, string plainText)
        {
            return Encrypt(keyType, plainText, String.Empty,
                            String.Empty);
        }

        /// <summary>
        /// Calls DPAPI CryptProtectData function to encrypt a plaintext
        /// string value. This function does not specify data description.
        /// </summary>
        /// <param name="keyType">
        /// Defines type of encryption key to use. When user key is
        /// specified, any application running under the same user account
        /// as the one making this call, will be able to decrypt data.
        /// Machine key will allow any application running on the same
        /// computer where data were encrypted to perform decryption.
        /// Note: If optional entropy is specifed, it will be required
        /// for decryption.
        /// </param>
        /// <param name="plainText">
        /// Plaintext data to be encrypted.
        /// </param>
        /// <param name="entropy">
        /// Optional entropy which - if specified - will be required to
        /// perform decryption.
        /// </param>
        /// <returns>
        /// Encrypted value in a base64-encoded format.
        /// </returns>
        public static string Encrypt(KeyType keyType,
                                     string plainText,
                                     string entropy)
        {
            return Encrypt(keyType, plainText, entropy, String.Empty);
        }

        /// <summary>
        /// Calls DPAPI CryptProtectData function to encrypt a plaintext
        /// string value.
        /// </summary>
        /// <param name="keyType">
        /// Defines type of encryption key to use. When user key is
        /// specified, any application running under the same user account
        /// as the one making this call, will be able to decrypt data.
        /// Machine key will allow any application running on the same
        /// computer where data were encrypted to perform decryption.
        /// Note: If optional entropy is specifed, it will be required
        /// for decryption.
        /// </param>
        /// <param name="plainText">
        /// Plaintext data to be encrypted.
        /// </param>
        /// <param name="entropy">
        /// Optional entropy which - if specified - will be required to
        /// perform decryption.
        /// </param>
        /// <param name="description">
        /// Optional description of data to be encrypted. If this value is
        /// specified, it will be stored along with encrypted data and
        /// returned as a separate value during decryption.
        /// </param>
        /// <returns>
        /// Encrypted value in a base64-encoded format.
        /// </returns>
        public static string Encrypt(KeyType keyType,
                                     string plainText,
                                     string entropy,
                                     string description)
        {
            // Make sure that parameters are valid.
            if (plainText == null) plainText = String.Empty;
            if (entropy == null) entropy = String.Empty;

            // Call encryption routine and convert returned bytes into
            // a base64-encoded value.
            return Convert.ToBase64String(
                    Encrypt(keyType,
                            Encoding.UTF8.GetBytes(plainText),
                            Encoding.UTF8.GetBytes(entropy),
                            description));
        }

        /// <summary>
        /// Calls DPAPI CryptProtectData function to encrypt an array of
        /// plaintext bytes.
        /// </summary>
        /// <param name="keyType">
        /// Defines type of encryption key to use. When user key is
        /// specified, any application running under the same user account
        /// as the one making this call, will be able to decrypt data.
        /// Machine key will allow any application running on the same
        /// computer where data were encrypted to perform decryption.
        /// Note: If optional entropy is specifed, it will be required
        /// for decryption.
        /// </param>
        /// <param name="plainTextBytes">
        /// Plaintext data to be encrypted.
        /// </param>
        /// <param name="entropyBytes">
        /// Optional entropy which - if specified - will be required to
        /// perform decryption.
        /// </param>
        /// <param name="description">
        /// Optional description of data to be encrypted. If this value is
        /// specified, it will be stored along with encrypted data and
        /// returned as a separate value during decryption.
        /// </param>
        /// <returns>
        /// Encrypted value.
        /// </returns>
        public static byte[] Encrypt(KeyType keyType,
                                     byte[] plainTextBytes,
                                     byte[] entropyBytes,
                                     string description)
        {
            // Make sure that parameters are valid.
            if (plainTextBytes == null) plainTextBytes = new byte[0];
            if (entropyBytes == null) entropyBytes = new byte[0];
            if (description == null) description = String.Empty;

            // Create BLOBs to hold data.
            DATA_BLOB plainTextBlob = new DATA_BLOB();
            DATA_BLOB cipherTextBlob = new DATA_BLOB();
            DATA_BLOB entropyBlob = new DATA_BLOB();

            // We only need prompt structure because it is a required
            // parameter.
            CRYPTPROTECT_PROMPTSTRUCT prompt =
                                      new CRYPTPROTECT_PROMPTSTRUCT();
            InitPrompt(ref prompt);

            try
            {
                // Convert plaintext bytes into a BLOB structure.
                try
                {
                    InitBLOB(plainTextBytes, ref plainTextBlob);
                }
                catch (Exception ex)
                {
                    throw new Exception(
                        "Cannot initialize plaintext BLOB.", ex);
                }

                // Convert entropy bytes into a BLOB structure.
                try
                {
                    InitBLOB(entropyBytes, ref entropyBlob);
                }
                catch (Exception ex)
                {
                    throw new Exception(
                        "Cannot initialize entropy BLOB.", ex);
                }

                // Disable any types of UI.
                int flags = CRYPTPROTECT_UI_FORBIDDEN;

                // When using machine-specific key, set up machine flag.
                if (keyType == KeyType.MachineKey)
                    flags |= CRYPTPROTECT_LOCAL_MACHINE;

                // Call DPAPI to encrypt data.
                bool success = CryptProtectData(ref plainTextBlob,
                                                    description,
                                                ref entropyBlob,
                                                    IntPtr.Zero,
                                                ref prompt,
                                                    flags,
                                                ref cipherTextBlob);
                // Check the result.
                if (!success)
                {
                    // If operation failed, retrieve last Win32 error.
                    int errCode = Marshal.GetLastWin32Error();

                    // Win32Exception will contain error message corresponding
                    // to the Windows error code.
                    throw new Exception(
                        "CryptProtectData failed.", new Win32Exception(errCode));
                }

                // Allocate memory to hold ciphertext.
                byte[] cipherTextBytes = new byte[cipherTextBlob.cbData];

                // Copy ciphertext from the BLOB to a byte array.
                Marshal.Copy(cipherTextBlob.pbData,
                                cipherTextBytes,
                                0,
                                cipherTextBlob.cbData);

                // Return the result.
                return cipherTextBytes;
            }
            catch (Exception ex)
            {
                throw new Exception("DPAPI was unable to encrypt data.", ex);
            }
            // Free all memory allocated for BLOBs.
            finally
            {
                if (plainTextBlob.pbData != IntPtr.Zero)
                    Marshal.FreeHGlobal(plainTextBlob.pbData);

                if (cipherTextBlob.pbData != IntPtr.Zero)
                    Marshal.FreeHGlobal(cipherTextBlob.pbData);

                if (entropyBlob.pbData != IntPtr.Zero)
                    Marshal.FreeHGlobal(entropyBlob.pbData);
            }
        }

        /// <summary>
        /// Calls DPAPI CryptUnprotectData to decrypt ciphertext bytes.
        /// This function does not use additional entropy and does not
        /// return data description.
        /// </summary>
        /// <param name="cipherText">
        /// Encrypted data formatted as a base64-encoded string.
        /// </param>
        /// <returns>
        /// Decrypted data returned as a UTF-8 string.
        /// </returns>
        /// <remarks>
        /// When decrypting data, it is not necessary to specify which
        /// type of encryption key to use: user-specific or
        /// machine-specific; DPAPI will figure it out by looking at
        /// the signature of encrypted data.
        /// </remarks>
        public static string Decrypt(string cipherText)
        {
            string description;

            return Decrypt(cipherText, String.Empty, out description);
        }

        /// <summary>
        /// Calls DPAPI CryptUnprotectData to decrypt ciphertext bytes.
        /// This function does not use additional entropy.
        /// </summary>
        /// <param name="cipherText">
        /// Encrypted data formatted as a base64-encoded string.
        /// </param>
        /// <param name="description">
        /// Returned description of data specified during encryption.
        /// </param>
        /// <returns>
        /// Decrypted data returned as a UTF-8 string.
        /// </returns>
        /// <remarks>
        /// When decrypting data, it is not necessary to specify which
        /// type of encryption key to use: user-specific or
        /// machine-specific; DPAPI will figure it out by looking at
        /// the signature of encrypted data.
        /// </remarks>
        public static string Decrypt(string cipherText,
                                     out string description)
        {
            return Decrypt(cipherText, String.Empty, out description);
        }

        /// <summary>
        /// Calls DPAPI CryptUnprotectData to decrypt ciphertext bytes.
        /// </summary>
        /// <param name="cipherText">
        /// Encrypted data formatted as a base64-encoded string.
        /// </param>
        /// <param name="entropy">
        /// Optional entropy, which is required if it was specified during
        /// encryption.
        /// </param>
        /// <param name="description">
        /// Returned description of data specified during encryption.
        /// </param>
        /// <returns>
        /// Decrypted data returned as a UTF-8 string.
        /// </returns>
        /// <remarks>
        /// When decrypting data, it is not necessary to specify which
        /// type of encryption key to use: user-specific or
        /// machine-specific; DPAPI will figure it out by looking at
        /// the signature of encrypted data.
        /// </remarks>
        public static string Decrypt(string cipherText,
                                         string entropy,
                                     out string description)
        {
            // Make sure that parameters are valid.
            if (entropy == null) entropy = String.Empty;

            return Encoding.UTF8.GetString(
                        Decrypt(Convert.FromBase64String(cipherText),
                                    Encoding.UTF8.GetBytes(entropy),
                                out description));
        }

        /// <summary>
        /// Calls DPAPI CryptUnprotectData to decrypt ciphertext bytes.
        /// </summary>
        /// <param name="cipherTextBytes">
        /// Encrypted data.
        /// </param>
        /// <param name="entropyBytes">
        /// Optional entropy, which is required if it was specified during
        /// encryption.
        /// </param>
        /// <param name="description">
        /// Returned description of data specified during encryption.
        /// </param>
        /// <returns>
        /// Decrypted data bytes.
        /// </returns>
        /// <remarks>
        /// When decrypting data, it is not necessary to specify which
        /// type of encryption key to use: user-specific or
        /// machine-specific; DPAPI will figure it out by looking at
        /// the signature of encrypted data.
        /// </remarks>
        public static byte[] Decrypt(byte[] cipherTextBytes,
                                         byte[] entropyBytes,
                                     out string description)
        {
            // Create BLOBs to hold data.
            DATA_BLOB plainTextBlob = new DATA_BLOB();
            DATA_BLOB cipherTextBlob = new DATA_BLOB();
            DATA_BLOB entropyBlob = new DATA_BLOB();

            // We only need prompt structure because it is a required
            // parameter.
            CRYPTPROTECT_PROMPTSTRUCT prompt =
                                      new CRYPTPROTECT_PROMPTSTRUCT();
            InitPrompt(ref prompt);

            // Initialize description string.
            description = String.Empty;

            try
            {
                // Convert ciphertext bytes into a BLOB structure.
                try
                {
                    InitBLOB(cipherTextBytes, ref cipherTextBlob);
                }
                catch (Exception ex)
                {
                    throw new Exception(
                        "Cannot initialize ciphertext BLOB.", ex);
                }

                // Convert entropy bytes into a BLOB structure.
                try
                {
                    InitBLOB(entropyBytes, ref entropyBlob);
                }
                catch (Exception ex)
                {
                    throw new Exception(
                        "Cannot initialize entropy BLOB.", ex);
                }

                // Disable any types of UI. CryptUnprotectData does not
                // mention CRYPTPROTECT_LOCAL_MACHINE flag in the list of
                // supported flags so we will not set it up.
                int flags = CRYPTPROTECT_UI_FORBIDDEN;

                // Call DPAPI to decrypt data.
                bool success = CryptUnprotectData(ref cipherTextBlob,
                                                  ref description,
                                                  ref entropyBlob,
                                                      IntPtr.Zero,
                                                  ref prompt,
                                                      flags,
                                                  ref plainTextBlob);

                // Check the result.
                if (!success)
                {
                    // If operation failed, retrieve last Win32 error.
                    int errCode = Marshal.GetLastWin32Error();

                    // Win32Exception will contain error message corresponding
                    // to the Windows error code.
                    throw new Exception(
                        "CryptUnprotectData failed.", new Win32Exception(errCode));
                }

                // Allocate memory to hold plaintext.
                byte[] plainTextBytes = new byte[plainTextBlob.cbData];

                // Copy ciphertext from the BLOB to a byte array.
                Marshal.Copy(plainTextBlob.pbData,
                             plainTextBytes,
                             0,
                             plainTextBlob.cbData);

                // Return the result.
                return plainTextBytes;
            }
            catch (Exception ex)
            {
                throw new Exception("DPAPI was unable to decrypt data.", ex);
            }
            // Free all memory allocated for BLOBs.
            finally
            {
                if (plainTextBlob.pbData != IntPtr.Zero)
                    Marshal.FreeHGlobal(plainTextBlob.pbData);

                if (cipherTextBlob.pbData != IntPtr.Zero)
                    Marshal.FreeHGlobal(cipherTextBlob.pbData);

                if (entropyBlob.pbData != IntPtr.Zero)
                    Marshal.FreeHGlobal(entropyBlob.pbData);
            }
        }
    }
    class TortoiseSVN : ICommand
    {
        public static string CommandName => "tortoisesvn";

        const string AUTHFILE_SUBPATH = @"Subversion\auth\svn.simple";    // Relative path to password files (from %APPDATA%)
        const int MAX_FILES_COUNT = 200;

        static string username, repository, encryptedPassword, decryptedPassword = String.Empty;

        static bool TryParseAuthFile(string path, out string username, out string repository, out string encryptedPassword)
        {

            username = "";
            repository = "";
            encryptedPassword = "";

            // Read file and parse key/value pairs
            Dictionary<string, string> results = null;
            try
            {
                results = AuthFileParser.ReadFile(path);
                if (!results.TryGetValue("username", out username)) return false;
                if (!results.TryGetValue("svn:realmstring", out repository)) return false;
                if (!results.TryGetValue("password", out encryptedPassword)) return false;
                return true;
            }
            catch (AuthParseException e)
            {
                Console.WriteLine(e.Message);
                return false;
            }

        }

        static bool TryDecryptPassword(string encrypted, out string decrypted)
        {
            decrypted = "";
            try
            {
                decrypted = DPAPI.Decrypt(encrypted);
                return true;
            }
            catch (Exception)
            {
                Writer.ErrorLine("Unable to decrypt the password");
                return false;
            }
        }

        public void DecryptPwd(ArgumentParserContent arguments)
        {
            // 查找密码文件
            string folder = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), AUTHFILE_SUBPATH);
            if (!Directory.Exists(folder))
            {
                Writer.ErrorLine("[!] Path not found: " + folder);
                Environment.Exit(0);
            }
            string[] files = Directory.GetFiles(folder, new String('?', 32)); // 密码文件名的长度为32个字符
            if (files.Length < 1)
            {
                Writer.ErrorLine("[!] No cached credentials files");
                Environment.Exit(0);
            }
            Writer.Log(String.Format("[*] Found {0} cached credentials files in {1}", files.Length, folder));

            // 遍历所有文件
            for (int i = 0; i < files.Length; i++)
            {
                if (i > MAX_FILES_COUNT)
                {
                    Writer.ErrorLine("Too many files in");
                }

                Console.WriteLine();
                Writer.Log("Parsing " + Path.GetFileName(files[i]));

                if (TryParseAuthFile(files[i], out username, out repository, out encryptedPassword))
                {
                    Writer.Out("Repository" , repository);
                    Writer.Out("Username" ,username);
                    if (TryDecryptPassword(encryptedPassword, out decryptedPassword))
                    {
                        Writer.Out("Password",decryptedPassword +"\r\n");
                    }
                }
            } // end for
        }
    }
}
