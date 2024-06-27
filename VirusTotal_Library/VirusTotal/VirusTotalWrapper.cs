using Newtonsoft.Json.Linq;
using System;
using System.CodeDom;
using System.IO;
using System.Net.Http;
using System.Security.Cryptography;
using System.Windows.Forms;

namespace VirusTotal_Library.VirusTotal
{
    public class VirusTotalWrapper
    {

        public static string ApiKey { get; set; } // Insert your VirusTotal API Key
        public readonly HttpClient _client;

        public VirusTotalWrapper(string apiKey)
        {
            ApiKey = apiKey;
            _client = new HttpClient();
            _client.BaseAddress = new Uri("https://www.virustotal.com/api/v3/");
            // Add an Accept header for JSON format.
            //_client.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));

            //Authorization 
            _client.DefaultRequestHeaders.Add("x-apikey", ApiKey);
            _client.DefaultRequestHeaders.Add("accept", "application/json");
        }

        public DateTime ConvertTimeStampsToDateTime(long timeStamp)
        {
            // Chuyển đổi Unix timestamp sang DateTime
            DateTimeOffset dateTimeOffset = DateTimeOffset.FromUnixTimeSeconds(timeStamp);
            DateTime dateTime = dateTimeOffset.DateTime;

            //return new DateTime(1970, 1, 1, 0, 0, 0, 0).AddSeconds(Convert.ToDouble(timeStamp));

            return dateTime;
        }

        public DateTime ConvertDateStringToDateTime(string dateTimeString)
        {
            //MessageBox.Show(dateTimeString);
            DateTimeOffset dateTime = DateTimeOffset.ParseExact(dateTimeString, "ddd, dd MMM yyyy HH:mm:ss 'GMT'", System.Globalization.CultureInfo.InvariantCulture);
            //DateTime dateTime1= DateTime.Parse(dateTimeString);
            return dateTime.DateTime;
        }

        public JToken GetJsonValueIgnoreCase(JToken jToken, string key)
        {
            if (jToken == null)
                return null;

            JToken jto = jToken; 

            string[] jtoStr = { key, key.ToLower(), key.ToUpper(), char.ToLower(key[0]) + key.Substring(1) };
          
            
            for(int i=0; i < jtoStr.Length; i++)
            {
                foreach (var property in ((JObject)jToken).Properties())
                {
                    if (property.Name == jtoStr[i])
                    {
                        jto = property.Value;
                        break;
                    }
                }

            }    
            return jto;
        }



        // Get MD5 hash of a file
        public string GetMD5(string filePath)
        {
            using (var md5 = MD5.Create())
            {
                using (var stream = File.OpenRead(filePath))
                {
                    return BitConverter.ToString(md5.ComputeHash(stream)).Replace("-", "").ToLower();
                }
            }
        }

        // Get SHA1 hash of a file  
        public string GetSHA1(string filePath)
        {
            using (var sha1 = SHA1.Create())
            {
                using (var stream = File.OpenRead(filePath))
                {
                    return BitConverter.ToString(sha1.ComputeHash(stream)).Replace("-", "").ToLower();
                }
            }
        }

        // Get SHA256 hash of a file
        public string GetSHA256(string filePath)
        {
            using (var sha256 = SHA256.Create())
            {
                using (var stream = File.OpenRead(filePath))
                {
                    return BitConverter.ToString(sha256.ComputeHash(stream)).Replace("-", "").ToLower();
                }
            }
        }



    }
}
