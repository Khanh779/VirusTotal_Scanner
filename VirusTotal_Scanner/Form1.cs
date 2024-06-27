using System;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Windows.Forms;
using VirusTotal_Library.Structs;
using VirusTotal_Library.VirusTotal;

namespace VirusTotal_Scanner
{
    public partial class Form1 : Form
    {



        public Form1()
        {
            InitializeComponent();

            GetApiKey_FromFile(Application.StartupPath + "\\VirusTotal_Cfg.ini");
        }


        void GetApiKey_FromFile(string filePath)
        {
            if (!File.Exists(filePath))
            {
                //File.Create(filePath);
                File.AppendAllLines(filePath, new string[] { "ApiKey=" + ApiKey });
                MessageBox.Show("Please enter your API Key in the VirusTotal_Cfg.ini file in the application directory.", Application.ProductName,
                    MessageBoxButtons.OK, MessageBoxIcon.Warning);
            }



            if (File.Exists(filePath))
            {
                string[] lines = System.IO.File.ReadAllLines(filePath);
                foreach (string line in lines)
                {
                    if (line.Split('=')[0].Contains("ApiKey"))
                    {
                        if (line.Split('=')[1] != ApiKey)
                        {
                            ApiKey = line.Split('=')[1];
                            isApiKeySet = true;
                        }

                    }

                }
            }

        }


        // ___________ API KEY _________

        public static string ApiKey = "<Enter Your API Key Here>";
        bool isApiKeySet = false;

        // ___________ API KEY _________




        private void Form1_Load(object sender, EventArgs e)
        {

        }

        private void button1_MouseClick(object sender, MouseEventArgs e)
        {
            if (e.Button == MouseButtons.Left)
            {
                if (openFileDialog1.ShowDialog() == DialogResult.OK)
                {
                    textBox1.Text = openFileDialog1.FileName;
                }
            }
        }

        private async void button2_MouseClick(object sender, MouseEventArgs e)
        {
            if (e.Button == MouseButtons.Left && isApiKeySet == true)
            {
                VirusTotal_Library.VirusTotal.FileAnalysis fileAnalysis = new VirusTotal_Library.VirusTotal.FileAnalysis(ApiKey);


                var checkScanRe = await fileAnalysis.ScanFileViaAnalyses(textBox1.Text);

                richTextBox1.Text = "";
                richTextBox1.Text += "Reputation: " + checkScanRe.Reputation + "\n";
                richTextBox1.Text += "MD5: " + checkScanRe.Md5 + "\n";
                richTextBox1.Text += "SHA1: " + checkScanRe.Sha1 + "\n";
                richTextBox1.Text += "SHA256: " + checkScanRe.Sha256 + "\n";
                richTextBox1.Text += "Size: " + checkScanRe.Size + "\n";
                richTextBox1.Text += "Magika: " + checkScanRe.Magika + "\n";
                richTextBox1.Text += "Meaningful Name: " + checkScanRe.MeaningfulName + "\n";
                richTextBox1.Text += "First Submission Date: " + checkScanRe.FirstSubmissionDate + "\n";
                richTextBox1.Text += "Times Submitted: " + checkScanRe.TimesSubmitted + "\n";
                richTextBox1.Text += "Last Modification Date: " + checkScanRe.LastModificationDate + "\n";
                richTextBox1.Text += "Last Analysis Date: " + checkScanRe.LastAnalysisDate + "\n";
                richTextBox1.Text += "Last Submission Date: " + checkScanRe.LastSubmissionDate + "\n";
                richTextBox1.Text += "Ssdeep: " + checkScanRe.Ssdeep + "\n";
                richTextBox1.Text += "Type Tag: " + checkScanRe.TypeTag + "\n";
                richTextBox1.Text += "Type Tags: " + checkScanRe.TypeTags + "\n";
                richTextBox1.Text += "Tlsh: " + checkScanRe.Tlsh + "\n";
                richTextBox1.Text += "Type Description: " + checkScanRe.TypeDescription + "\n";
                richTextBox1.Text += "Date Time: " + checkScanRe.Date + "\n";

                richTextBox1.Text += "_____________________\nStatistical analysis: \nHarmless: " + checkScanRe.AnalysisStatis.Harmless +
                    "\nMalicious: " + checkScanRe.AnalysisStatis.Malicious + "\nSuspicious: " + checkScanRe.AnalysisStatis.Suspicious + "\n" +
                    "Undetected: " + checkScanRe.AnalysisStatis.Undetected +
                    "\nConfirmed TimeOut: " + checkScanRe.AnalysisStatis.Confirmed_TimeOut;

                richTextBox1.Text += "\n_____________________\nSignature Info:\n";

                richTextBox1.Text += "Description: " + checkScanRe.SignatureInfo.Description + "\n";
                richTextBox1.Text += "File Version: " + checkScanRe.SignatureInfo.FileVersion + "\n";
                richTextBox1.Text += "Original Name: " + checkScanRe.SignatureInfo.OriginalName + "\n";
                richTextBox1.Text += "Product: " + checkScanRe.SignatureInfo.Product + "\n";
                richTextBox1.Text += "Internal Name: " + checkScanRe.SignatureInfo.InternalName + "\n_____________________\n";


                foreach (var engineRe in checkScanRe.EngineResults)
                {
                    richTextBox1.Text += "----------------------------------------\n";
                    richTextBox1.Text += "Index: " + engineRe.Index + "\n";
                    richTextBox1.Text += "Engine Name: " + engineRe.EngineName + "\n";
                    richTextBox1.Text += "Engine Update: " + engineRe.EngineUpdate + "\n";
                    richTextBox1.Text += "Engine Version: " + engineRe.EngineVersion + "\n";
                    richTextBox1.Text += "Method: " + engineRe.Method + "\n";
                    richTextBox1.Text += "Category: " + engineRe.Category + "\n";
                    richTextBox1.Text += "Result: " + engineRe.Result + "\n";

                }
            }
        }

        private async void button3_MouseClick(object sender, MouseEventArgs e)
        {
            if (e.Button == MouseButtons.Left && isApiKeySet)
            {
                VirusTotal_Library.VirusTotal.UrlAnalysis urlAnalysis = new VirusTotal_Library.VirusTotal.UrlAnalysis(ApiKey);

                int scanType = 0;

                var report = await urlAnalysis.ScanUrl(textBox2.Text, scanType);
                richTextBox2.Text = "Scan Type: " + (scanType == 0 ? "Url" : "Analysis")+ " (0 - Recommended)";
                richTextBox2.Text += "\n_________________________\n";

                richTextBox2.Text += "URL: " + report.Url + "\n";
                richTextBox2.Text += "Title: " + report.Title + "\n";
                richTextBox2.Text += "Permalink: " + report.Permalink + "\n";
                richTextBox2.Text += "Resource: " + report.Resource + "\n";
                richTextBox2.Text += "Response Code: " + report.ResponseCode + "\n";
                richTextBox2.Text += "Scan Date: " + report.Date + "\n";
                richTextBox2.Text += "Scan ID: " + report.ScanId + "\n";
                richTextBox2.Text += "Reputation: " + report.Reputation + "\n";
                richTextBox2.Text += "TLD: " + report.Tld + "\n";
                richTextBox2.Text += "Times Submitted: " + report.TimesSubmitted + "\n";
                richTextBox2.Text += "Last Submission Date: " + report.LastSubmissionDate + "\n";
                richTextBox2.Text += "Last Analysis Date: " + report.LastAnalysisDate + "\n";
                richTextBox2.Text += "Last Modification Date: " + report.LastModificationDate + "\n";
                richTextBox2.Text += "Date: " + report.Date + "\n";


                richTextBox2.Text += "\n_______________\nStatistical analysis:\n";
                richTextBox2.Text += "Harmless: " + report.AnalysisStatis.Harmless + "\n";
                richTextBox2.Text += "Malicious: " + report.AnalysisStatis.Malicious + "\n";
                richTextBox2.Text += "Suspicious: " + report.AnalysisStatis.Suspicious + "\n";
                richTextBox2.Text += "Undetected: " + report.AnalysisStatis.Undetected + "\n";
                richTextBox2.Text += "Confirmed TimeOut: " + report.AnalysisStatis.Confirmed_TimeOut + "\n";

                richTextBox2.Text += "\n_______________\nThreat Names: \n";
                foreach (var threat in report.ThreatNames)
                {
                    richTextBox2.Text += threat + ", ";
                }

                richTextBox2.Text += "\n___________________\nCategories: \n";
                foreach (var category in report.Categories)
                {
                    richTextBox2.Text += "----------------\n";
                    richTextBox2.Text += "Category Name: " + category.CategoryName + "\n";
                    richTextBox2.Text += "Description: " + category.Description + "\n";
                }
                richTextBox2.Text += "\n___________________\nTags: \n";
                foreach (var tag in report.Tags)
                {
                    richTextBox2.Text += tag + ", ";
                }
                richTextBox2.Text += "\n___________________\nOutgoing Links: \n";
                foreach (var link in report.OutgoingLinks)
                {
                    richTextBox2.Text += link + ", ";

                }
                richTextBox2.Text += "\n___________________\nRedirection Chain: \n";
                foreach (var redir in report.RedirectionChain)
                {
                    richTextBox2.Text += redir + ", ";
                }

                richTextBox2.Text += "\n___________________\nHTTP Response Headers: \n";
                richTextBox2.Text += "Content Type: " + report.HttpResponseHeaders.ContentType + "\n";
                richTextBox2.Text += "Content Security Policy Report Only: " + report.HttpResponseHeaders.ContentSecurityPolicyReportOnly + "\n";
                richTextBox2.Text += "Accept CH: " + report.HttpResponseHeaders.AcceptCH + "\n";
                richTextBox2.Text += "Permissions Policy: " + report.HttpResponseHeaders.PermissionsPolicy + "\n";
                richTextBox2.Text += "P3P: " + report.HttpResponseHeaders.P3P + "\n";
                richTextBox2.Text += "Content Encoding: " + report.HttpResponseHeaders.ContentEncoding + "\n";
                richTextBox2.Text += "Date: " + report.HttpResponseHeaders.Date + "\n";
                richTextBox2.Text += "Server: " + report.HttpResponseHeaders.Server + "\n";
                richTextBox2.Text += "Content Length: " + report.HttpResponseHeaders.ContentLength + "\n";
                richTextBox2.Text += "XXSS Protection: " + report.HttpResponseHeaders.XXSSProtection + "\n";
                richTextBox2.Text += "XFrame Options: " + report.HttpResponseHeaders.XFrameOptions + "\n";
                richTextBox2.Text += "Cache Control: " + report.HttpResponseHeaders.CacheControl + "\n";
                richTextBox2.Text += "Set Cookie: " + report.HttpResponseHeaders.SetCookie + "\n";
                richTextBox2.Text += "Alt Svc: " + report.HttpResponseHeaders.AltSvc + "\n";
                richTextBox2.
                    Text += "\n___________________\n";

                richTextBox2.Text += "\nEngine Results: \n";

                foreach (var scan in report.EngineResults)
                {
                    richTextBox2.Text += "----------------------------------------\n";
                    richTextBox2.Text += "Antivirus Vendor: " + scan.EngineName + "\n";
                    richTextBox2.Text += "Method: " + scan.Method + "\n";
                    richTextBox2.Text += "Result: " + scan.Result + "\n";
                    richTextBox2.Text += "Update: " + scan.EngineUpdate + "\n";
                    richTextBox2.Text += "Version: " + scan.EngineVersion + "\n";
                }
            }
        }

        private async void button4_MouseClick(object sender, MouseEventArgs e)
        {
            if (e.Button == MouseButtons.Left && isApiKeySet == true)
            {
                IpAnalysis ipAnalysis = new IpAnalysis(ApiKey);

                var ipResult = await ipAnalysis.GetIpAddressResult(textBox3.Text);

                richTextBox3.Text = "Ip ID: " + ipResult.IpId + "\n";
                richTextBox3.Text += "WhoIs Date: " + ipResult.WhoIsDate + "\n";
                richTextBox3.Text += "Reputation: " + ipResult.Reputation + "\n";
                richTextBox3.Text += "___________________\nWhoIs: \n-----------------\n" + ipResult.WhoIs + "\n-----------------\n______________________\n";
                richTextBox3.Text += "Last Analysis Date: " + ipResult.LastAnalysisDate + "\n";
                richTextBox3.Text += "Tags: \n";
                foreach (var tag in ipResult.Tags)
                {
                    richTextBox3.Text += tag + ", ";
                }

                richTextBox3.Text += "\n_____________________\nStatistical analysis: \nHarmless: " + ipResult.AnalysisStatis.Harmless +
                    "\nMalicious: " + ipResult.AnalysisStatis.Malicious + "\nSuspicious: " + ipResult.AnalysisStatis.Suspicious + "\n" +
                    "Undetected: " + ipResult.AnalysisStatis.Undetected +
                    "\nConfirmed TimeOut: " + ipResult.AnalysisStatis.Confirmed_TimeOut;

                richTextBox3.Text += "\n_____________________\nEngine Results:\n";

                foreach (var engineRe in ipResult.EngineResults)
                {
                    richTextBox3.Text += "----------------------------------------\n";
                    richTextBox3.Text += "Engine Name: " + engineRe.EngineName + "\n";
                    richTextBox3.Text += "Category: " + engineRe.Category + "\n";
                    richTextBox3.Text += "Result: " + engineRe.Result + "\n";
                    richTextBox3.Text += "Method: " + engineRe.Method + "\n";

                }
            }
        }

        private async void button5_MouseClick(object sender, MouseEventArgs e)
        {
            if(e.Button== MouseButtons.Left && isApiKeySet)
            {
                DomainAnalysis domainAnalysis = new DomainAnalysis(ApiKey);

                var domainResult = await domainAnalysis.GetDomainReport(textBox4.Text);

                richTextBox4.Text = "Domain ID: " + domainResult.DomainId + "\n";
                richTextBox4.Text += "Reputation: " + domainResult.Reputation + "\n";

                richTextBox4.Text += "Dns Records Date: " + domainResult.DnsRecordsDate + "\n";
                richTextBox4.Text += "Tld: " + domainResult.Tld + "\n";
                richTextBox4.Text += "Jarm: " + domainResult.Jarm + "\n";
                richTextBox4.Text += "Last Analysis Date: " + domainResult.LastAnalysisDate + "\n";
                richTextBox4.Text += "Https Certificate Date: " + domainResult.HttpsCertificateDate + "\n";
                richTextBox4.Text += "Last Modification Date: " + domainResult.LastModificationDate + "\n";
                richTextBox4.Text += "Analysis Date: " + domainResult.AnalysisDate + "\n";
                
                
                richTextBox4.Text += "_____________________\n";

                richTextBox4.Text += "Categories: \n";
                foreach (var category in domainResult.Categories)
                {
                    richTextBox4.Text += "----------------\n";
                    richTextBox4.Text += "Category Name: " + category.CategoryName + "\n";
                    richTextBox4.Text += "Description: " + category.Description + "\n";
                }

                richTextBox4.Text += "Tags: \n";
                foreach (var tag in domainResult.Tags)
                {
                    richTextBox4.Text += tag + ", ";
                }

                richTextBox4.Text += "\n_____________________\nStatistical analysis: \nHarmless: " + domainResult.AnalysisStats.Harmless +
                    "\nMalicious: " + domainResult.AnalysisStats.Malicious + "\nSuspicious: " + domainResult.AnalysisStats.Suspicious + "\n" +
                    "Undetected: " + domainResult.AnalysisStats.Undetected +
                    "\nConfirmed TimeOut: " + domainResult.AnalysisStats.TimeOut;

                richTextBox4.Text += "\n_____________________\nEngine Results:\n";

                foreach (var engineRe in domainResult.EnginerResults)
                {
                    richTextBox4.Text += "----------------------------------------\n";
                    richTextBox4.Text += "Engine Name: " + engineRe.EngineName + "\n";
                    richTextBox4.Text += "Category: " + engineRe.Category + "\n";
                    richTextBox4.Text += "Result: " + engineRe.Result + "\n";
                    richTextBox4.Text += "Method: " + engineRe.Method + "\n";
                }

                richTextBox4.Text += "\n_____________________\nDns Records:\n";

                foreach (var dnsRecord in domainResult.DnsRecords)
                {
                    richTextBox4.Text += "----------------------------------------\n";
                    richTextBox4.Text += "Type: " + dnsRecord.Type + "\n";
                    richTextBox4.Text += "Value: " + dnsRecord.Value + "\n";
                    richTextBox4.Text += "Ttl: " + dnsRecord.Ttl + "\n";
                    richTextBox4.Text += "Priority: " + dnsRecord.Priority + "\n";
                    richTextBox4.Text += "Rname: " + dnsRecord.Rname + "\n";
                    richTextBox4.Text += "Serial: " + dnsRecord.Serial + "\n";
                    richTextBox4.Text += "Refresh: " + dnsRecord.Refresh + "\n";
                    richTextBox4.Text += "Retry: " + dnsRecord.Retry + "\n";
                    richTextBox4.Text += "Expire: " + dnsRecord.Expire + "\n";
                    richTextBox4.Text += "Minimum: " + dnsRecord.Minimum + "\n";
                }

                richTextBox4.Text += "\n_____________________\nPopularity Ranks:\n";

                foreach (var popRank in domainResult.PopularityRanks)
                {
                    richTextBox4.Text += "----------------------------------------\n";
                    richTextBox4.Text += "Rank Name: " + popRank.RankName + "\n";
                    richTextBox4.Text += "Time Stamp: " + popRank.TimeStamp + "\n";
                    richTextBox4.Text += "Rank: " + popRank.Rank + "\n";
                }


            }    
        }
    }
}
