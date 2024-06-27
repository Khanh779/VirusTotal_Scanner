using Newtonsoft.Json.Linq;
using System;
using System.CodeDom;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using VirusTotal_Library.Structs;

namespace VirusTotal_Library.VirusTotal
{
    public class IpAnalysis: VirusTotalWrapper
    {
        public IpAnalysis(string apiKey) : base(apiKey)
        {
        }

        public async Task<string> GetIpResultJsonContent(string ip)
        {
            string a = "";
            var sendIpRequest= await _client.GetAsync(@"ip_addresses/" + ip);
            if (sendIpRequest.IsSuccessStatusCode)
            {
                a = await sendIpRequest.Content.ReadAsStringAsync();
            }

            return a;
        }

        public async Task<IpAddressResult> GetIpAddressResult(string ipAddress)
        {
            IpAddressResult ipAddressResult = new IpAddressResult();

            JObject data = JObject.Parse(await GetIpResultJsonContent(ipAddress));

            ipAddressResult.IpId = data["data"]["id"].ToString();

            var getDataAttributes = data["data"]["attributes"];
            ipAddressResult.Reputation = (string)getDataAttributes["reputation"];
            ipAddressResult.WhoIs = (string)getDataAttributes["whois"];

            ipAddressResult.WhoIsDate = ConvertTimeStampsToDateTime((long)getDataAttributes["whois_date"]);
            ipAddressResult.LastAnalysisDate = ConvertTimeStampsToDateTime((long)getDataAttributes["last_analysis_date"]);

            var getTags = getDataAttributes["tags"];
            
            ipAddressResult.Tags = getTags.ToObject<string[]>();

            var analysisStatis = new AnalysisStatis();

            analysisStatis.Harmless = int.Parse(getDataAttributes["last_analysis_stats"]["harmless"].ToString());
            analysisStatis.Malicious = int.Parse(getDataAttributes["last_analysis_stats"]["malicious"].ToString());
            analysisStatis.Suspicious = int.Parse(getDataAttributes["last_analysis_stats"]["suspicious"].ToString());
            analysisStatis.Undetected = int.Parse(getDataAttributes["last_analysis_stats"]["undetected"].ToString());
            analysisStatis.Confirmed_TimeOut = int.Parse(getDataAttributes["last_analysis_stats"]["timeout"].ToString());

            ipAddressResult.AnalysisStatis = analysisStatis;

            ipAddressResult.EngineResults = new List<EnginerResult>();

            foreach (var item in data["data"]["attributes"]["last_analysis_results"])
            {
                ipAddressResult.EngineResults.Add(new EnginerResult()
                {
                    EngineName = item.First["engine_name"].ToString(),
                    Category = item.First["category"].ToString(),
                    Result = item.First["result"].ToString(),
                    Method = item.First["method"].ToString(),
                });
            }



            return ipAddressResult;
        }
    }
}
