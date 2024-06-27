using System;
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
        }

        private void button1_Click(object sender, EventArgs e)
        {
            if (openFileDialog1.ShowDialog() == DialogResult.OK)
            {
                textBox1.Text = openFileDialog1.FileName;
            }
        }


        // ___________ API KEY _________

        public static string ApiKey = "<Enter Your API Key Here>";

        // ___________ API KEY _________




        private async void button2_Click(object sender, EventArgs e)
        {
            VirusTotal_Library.VirusTotal.FileAnalysis fileAnalysis = new VirusTotal_Library.VirusTotal.FileAnalysis(ApiKey);


            var checkScanRe = await fileAnalysis.ScanFileViaHash(textBox1.Text);

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

        private async void button3_Click(object sender, EventArgs e)
        {
            VirusTotal_Library.VirusTotal.UrlAnalysis urlAnalysis = new VirusTotal_Library.VirusTotal.UrlAnalysis(ApiKey);


            var report = await urlAnalysis.ScanUrl(textBox2.Text, 0);


            richTextBox2.Text += "URL: " + report.Url + "\n";
            richTextBox2.Text += "Permalink: " + report.Permalink + "\n";
            richTextBox2.Text += "Resource: " + report.Resource + "\n";
            richTextBox2.Text += "Response Code: " + report.ResponseCode + "\n";
            richTextBox2.Text += "Scan Date: " + report.Date + "\n";
            richTextBox2.Text += "Scan ID: " + report.ScanId + "\n";

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

        private void Form1_Load(object sender, EventArgs e)
        {

        }

        private async void button4_Click(object sender, EventArgs e)
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
}
