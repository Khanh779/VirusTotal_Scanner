using Newtonsoft.Json.Linq;
using System.Collections.Generic;
using System.Net.Http;
using System.Threading.Tasks;
using VirusTotal_Library.Structs;

namespace VirusTotal_Library.VirusTotal
{
    public class UrlAnalysis : VirusTotalWrapper
    {
        public UrlAnalysis(string apiKey) : base(apiKey)
        {

        }

        /// <summary>
        /// Get the URL scan results.
        /// </summary>
        /// <param name="url">Gets or sets URL to scan.</param>
        /// <param name="scanType">0: To Scan Url. 1: To Analysis Url</param>
        /// <returns></returns>
        public async Task<URLScanResult> ScanUrl(string url, int scanType = 0)
        {
            var result = new URLScanResult();

            string scanId = await GetIdOfUrl(url);

            string scanDataString = await (scanType == 0 ? ScanUrlReturnJsonString(scanId) : AnalysesUrlReturnJsonString(scanId));

            JObject scanData = JObject.Parse(scanDataString);

            var getDataAttributes = scanData["data"]["attributes"];

            var getReputation = getDataAttributes["reputation"];
            result.Reputation = getDataAttributes["reputation"] != null ? (int)getReputation : 0;

            result.Url = (string)getDataAttributes["url"];
            //result.Permalink = (string)scanData["data"]["attributes"]["link"];
            result.Resource = scanId;
            result.ScanId = scanId;
            result.ResponseCode = 1;
            var timeSu = scanData["data"]["attributes"]["times_submitted"];
            result.TimesSubmitted = timeSu != null ? (int)timeSu : 0;
            var threNames = scanData["data"]["attributes"]["threat_names"];
            result.ThreatNames = threNames != null ? threNames.ToObject<string[]>() : new string[] { };

            result.Title = (string)scanData["data"]["attributes"]["title"] ?? "";

            result.LastSubmissionDate = ConvertTimeStampsToDateTime((long)(scanData["data"]["attributes"]["date"] ?? scanData["data"]["attributes"]["last_submission_date"]));

            var lastAnalysisDate = scanData["data"]["attributes"]["last_analysis_date"];
            result.LastAnalysisDate = ConvertTimeStampsToDateTime(lastAnalysisDate != null ? (long)lastAnalysisDate : 0);

            var lastModDate = scanData["data"]["attributes"]["last_modification_date"];
            result.LastModificationDate = ConvertTimeStampsToDateTime(lastModDate != null ? (long)lastModDate : 0);

            if (scanData["data"]["attributes"]["date"] != null)
            {
                result.Date = ConvertTimeStampsToDateTime((long)scanData["data"]["attributes"]["date"]);
            }
            else
            {
                result.Date = ConvertDateStringToDateTime((string)scanData["data"]["attributes"]["last_http_response_headers"]["date"]);
            }


            var analysis = new AnalysisStatis();
            var getStat = scanData["data"]["attributes"]["stats"] ?? scanData["data"]["attributes"]["last_analysis_stats"];
            analysis.Harmless = (int)getStat["harmless"];
            analysis.Malicious = (int)getStat["malicious"];
            analysis.Suspicious = (int)getStat["suspicious"];
            analysis.Undetected = (int)getStat["undetected"];
            analysis.TimeOut = (int)getStat["timeout"];
            analysis.Confirmed_TimeOut = (int)getStat["timeout"];
            result.AnalysisStatis = analysis;

            var categories = new List<URLCategorie>();
            if (getDataAttributes["categories"] != null)
            {
                var getCate = ((JObject)(getDataAttributes["categories"])).Properties();
                int indexCat = 0;
                foreach (var cate in getCate)
                {
                    var category = new URLCategorie();
                    category.Index = indexCat;
                    category.CategoryName = cate.Name;
                    category.Description = (string)cate.Value;
                    categories.Add(category);
                    indexCat++;
                }
            }
            result.Categories = categories;

            var tags = getDataAttributes["tags"];
            result.Tags = tags != null ? tags.ToObject<string[]>() : new string[] { };

            var outLinks = getDataAttributes["outgoing_links"];
            result.OutgoingLinks = outLinks != null ? outLinks.ToObject<string[]>() : new string[] { };

            var redirChain = getDataAttributes["redirection_chain"];
            result.RedirectionChain = redirChain != null ? redirChain.ToObject<string[]>() : new string[] { };


            result.EngineResults = new List<EnginerResult>();
            var getVend = scanData["data"]["attributes"];
            var engineResults = ((JObject)(getVend["results"] ?? getVend["last_analysis_results"])).Properties();
            int index = 0;
            foreach (var engine in engineResults)
            {
                var engineResult = new EnginerResult();
                engineResult.Index = index;
                engineResult.EngineName = (string)engine.Value["engine_name"];
                engineResult.EngineUpdate = (string)engine.Value["engine_update"];
                engineResult.EngineVersion = (string)engine.Value["engine_version"];
                engineResult.Method = (string)engine.Value["method"];
                engineResult.Category = (string)engine.Value["category"];
                engineResult.Result = (string)engine.Value["result"];
                result.EngineResults.Add(engineResult);
                index++;
            }
            return result;
        }

        public async Task<string> ScanUrlReturnStringID(string url)
        {
            string result = "";

            //var content = new StringContent($"url={url}", System.Text.Encoding.UTF8, "application/x-www-form-urlencoded");

            var content = new FormUrlEncodedContent(new[]
                {
                new KeyValuePair<string, string>("url", url)
                });

            //_client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", "YOUR_API_KEY");
            var response = await _client.PostAsync("urls", content);
            result = await response.Content.ReadAsStringAsync();
            return result;
        }

        public async Task<string> GetIdOfUrl(string url)
        {

            string getContentId = await ScanUrlReturnStringID(url);
            JObject responseJson = JObject.Parse(getContentId);

            string a = "";
            a = (string)responseJson["data"]?["id"];

            return a;
        }




        public async Task<string> AnalysesUrlReturnJsonString(string scanId)
        {
            string a = "";
            // Get the scan results
            var response = await _client.GetAsync($"analyses/{scanId}");
            a = await response.Content.ReadAsStringAsync();
            return a;
        }

        public async Task<string> ScanUrlReturnJsonString(string scanId)
        {
            string a = "";
            // Get the scan results
            var response = await _client.GetAsync($"urls/{scanId.Split('-')[1]}");
            a = await response.Content.ReadAsStringAsync();
            return a;
        }


    }
}
