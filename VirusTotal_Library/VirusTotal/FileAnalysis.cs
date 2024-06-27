using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.IO;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Threading.Tasks;
using VirusTotal_Library.Structs;

namespace VirusTotal_Library.VirusTotal
{
    public class FileAnalysis : VirusTotalWrapper
    {
        public FileAnalysis(string apiKey) : base(apiKey)
        {

        }




        public async Task<FileScanResult> ScanFileViaAnalyses(string filePath)
        {

            //_client.DefaultRequestHeaders.Add("x-apikey", ApiKey);

            var fileId = await UploadFile(filePath);

            fileId = (string)(JObject.Parse(fileId))["data"]["id"];

            var jsonResponse = await CheckScanResultViaAnalyses(fileId);


            JObject data = JObject.Parse(jsonResponse);
            data = ((JObject)data["data"]);

            var result = new FileScanResult();


            // ____ File Info ____

            JObject metaData = JObject.Parse(jsonResponse);
            metaData = ((JObject)metaData["meta"]["file_info"]);
            result.Md5 = (string)metaData["md5"];
            result.Sha1 = (string)metaData["sha1"];
            result.Sha256 = (string)metaData["sha256"];
            result.Size = (string)metaData["size"];

            // ____ File Info ____

            //result.Magika = (string)data["magika"];
            //result.MeaningfulName = (string)data["meaningful_name"];
            //result.FirstSubmissionDate = (string)data["first_submission_date"];

            //result.TimesSubmitted = (string)data["times_submitted"];

            //result.LastModificationDate = (string)data["last_modification_date"];
            //result.LastAnalysisDate = (string)data["last_analysis_date"];
            //result.LastSubmissionDate = (string)data["last_submission_date"];
            //result.Ssdeep = (string)data["ssdeep"];
            //result.TypeTag = (string)data["type_tag"];
            //result.Tlsh = (string)data["tlsh"];
            //result.TypeDescription = (string)data["type_description"];
            //result.Reputation = (string)data["reputation"];
            //result.Magic = (string)data["magic"];
            //result.TypeExtension = (string)data["type_extension"] + "\n";
            //result.TypeTags = "";

            var signatureInfo = new SignatureInfo();

            result.SignatureInfo = signatureInfo;

            var AnalysisStatis = new AnalysisStatis();
            AnalysisStatis.Harmless = (int)data["attributes"]["stats"]["harmless"];
            AnalysisStatis.Malicious = (int)data["attributes"]["stats"]["malicious"];
            AnalysisStatis.Suspicious = (int)data["attributes"]["stats"]["suspicious"];
            AnalysisStatis.Undetected = (int)data["attributes"]["stats"]["undetected"];
            AnalysisStatis.TimeOut = (int)data["attributes"]["stats"]["timeout"];
            AnalysisStatis.Failure = (int)data["attributes"]["stats"]["failure"];
            AnalysisStatis.TypeUnsupported = (int)data["attributes"]["stats"]["type-unsupported"];
            AnalysisStatis.Confirmed_TimeOut = (int)data["attributes"]["stats"]["confirmed-timeout"];

            result.AnalysisStatis = AnalysisStatis;

            // Set DateTime
            result.Date = ConvertTimeStampsToDateTime((long)data["attributes"]["date"]);

            result.EngineResults = new List<EnginerResult>();

            int index = 0;
            var vendors = ((JObject)data["attributes"]["results"]).Properties();
            foreach (var b in vendors)
            {
                var vendorRe = new EnginerResult();
                vendorRe.Index = index;
                vendorRe.EngineName = (string)b.Value["engine_name"];
                vendorRe.Category = (string)b.Value["category"];
                vendorRe.Result = (string)b.Value["result"];
                vendorRe.EngineUpdate = (string)b.Value["engine_update"];
                vendorRe.EngineVersion = (string)b.Value["engine_version"];
                vendorRe.Method = (string)b.Value["method"];

                result.EngineResults.Add(vendorRe);
                index++;
            }
            return result;
        }


        public async Task<FileScanResult> ScanFileViaHash(string filePath)
        {
            string getHashSHA256 = GetSHA256(filePath);
            //_client.DefaultRequestHeaders.Add("x-apikey", ApiKey);
            JObject data = JObject.Parse(await CheckScanResultViaHash(getHashSHA256));
            data = ((JObject)data["data"]["attributes"]);


            var result = new FileScanResult();
            result.Names = data["names"].ToObject<string[]>();

            result.Md5 = (string)data["md5"];
            result.Sha1 = (string)data["sha1"];
            result.Sha256 = (string)data["sha256"];
            result.Size = (string)data["size"];
            result.Magika = (string)data["magika"];
            result.MeaningfulName = (string)data["meaningful_name"];

            result.FirstSubmissionDate = ConvertTimeStampsToDateTime((long)data["first_submission_date"]);
            result.LastAnalysisDate = ConvertTimeStampsToDateTime((long)data["last_analysis_date"]);
            result.LastSubmissionDate = ConvertTimeStampsToDateTime((long)data["last_submission_date"]);

            result.TimesSubmitted = (string)data["times_submitted"];

            result.LastModificationDate = (string)data["last_modification_date"];

            result.Ssdeep = (string)data["ssdeep"];
            result.TypeTag = (string)data["type_tag"];
            result.Tlsh = (string)data["tlsh"];
            result.TypeDescription = (string)data["type_description"];
            result.Reputation = (string)data["reputation"];
            result.Magic = (string)data["magic"];
            result.TypeExtension = (string)data["type_extension"] + "\n";


            var signatureInfo = new SignatureInfo();
            signatureInfo.Description = (string)data["signature_info"]["description"];
            signatureInfo.FileVersion = (string)data["signature_info"]["file version"];
            signatureInfo.OriginalName = (string)data["signature_info"]["original name"];
            signatureInfo.Product = (string)data["signature_info"]["product"];
            signatureInfo.InternalName = (string)data["signature_info"]["internal name"];
            result.SignatureInfo = signatureInfo;

            var AnalysisStatis = new AnalysisStatis();
            AnalysisStatis.Harmless = (int)data["last_analysis_stats"]["harmless"];
            AnalysisStatis.Malicious = (int)data["last_analysis_stats"]["malicious"];
            AnalysisStatis.Suspicious = (int)data["last_analysis_stats"]["suspicious"];
            AnalysisStatis.Undetected = (int)data["last_analysis_stats"]["undetected"];
            AnalysisStatis.TimeOut = (int)data["last_analysis_stats"]["timeout"];
            AnalysisStatis.Failure = (int)data["last_analysis_stats"]["failure"];
            AnalysisStatis.TypeUnsupported = (int)data["last_analysis_stats"]["type-unsupported"];
            AnalysisStatis.Confirmed_TimeOut = (int)data["last_analysis_stats"]["confirmed-timeout"];

            result.AnalysisStatis = AnalysisStatis;

            foreach (string v in data["tags"])
            {
                result.Tags += v + ", ";
            }

            foreach (string b in data["type_tags"])
            {
                result.TypeTags += b + ", ";
            }


            result.EngineResults = new List<EnginerResult>();
            int index = 0;
            var vendors = ((JObject)data["last_analysis_results"]).Properties();
            foreach (var b in vendors)
            {
                var vendorRe = new EnginerResult();
                vendorRe.Index = index;
                vendorRe.EngineName = b.Name;
                vendorRe.Category = (string)b.Value["category"];
                vendorRe.Result = (string)b.Value["result"];
                vendorRe.EngineUpdate = (string)b.Value["engine_update"];
                vendorRe.EngineVersion = (string)b.Value["engine_version"];
                vendorRe.Method = (string)b.Value["method"];

                result.EngineResults.Add(vendorRe);
                index++;
            }
            return result;

        }


        public async Task<string> CheckScanResultViaAnalyses(string fileId)
        {
            string a = "";
            //_client.DefaultRequestHeaders.Add("x-apikey", ApiKey);
            var response = await _client.GetAsync($"analyses/{fileId}");   // id scan
            if (response.IsSuccessStatusCode)
                a = await response.Content.ReadAsStringAsync();
            else
                throw new Exception($"Failed to check scan result: {response.StatusCode}");

            return a;
        }

        public async Task<string> CheckScanResultViaHash(string hash)
        {
            string a = "";
            //_client.DefaultRequestHeaders.Add("x-apikey", ApiKey);
            var response = await _client.GetAsync($"files/{hash}");
            if (response.IsSuccessStatusCode)
                a = await response.Content.ReadAsStringAsync();
            else
                throw new Exception($"Failed to check scan result: {response.StatusCode}");

            return a;
        }

        public async Task<string> UploadFile(string filePath)
        {
            using (var formData = new MultipartFormDataContent())
            {
                byte[] fileBytes = File.ReadAllBytes(filePath);
                var fileContent = new ByteArrayContent(fileBytes);
                fileContent.Headers.ContentType = MediaTypeHeaderValue.Parse("application/octet-stream");

                formData.Add(fileContent, "file", Path.GetFileName(filePath));

                //_client.DefaultRequestHeaders.Add("x-apikey", ApiKey);
                var response = await _client.PostAsync("https://www.virustotal.com/api/v3/files", formData);

                if (response.IsSuccessStatusCode)
                {
                    string jsonResponse = await response.Content.ReadAsStringAsync();
                    Console.WriteLine(jsonResponse);
                    // Parse response to get file ID
                    // Example parsing: var fileId = JsonConvert.DeserializeObject<dynamic>(jsonResponse)["data"]["id"].ToString();
                    // Return fileId
                    return jsonResponse;
                }
                else
                {
                    throw new Exception($"Failed to upload file: {response.StatusCode}");
                }
            }
        }

    }
}
