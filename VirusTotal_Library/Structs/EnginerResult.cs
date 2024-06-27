namespace VirusTotal_Library.Structs
{
    public struct EnginerResult
    {
        public int Index { get; set; }
        public string EngineName { get; set; }
        public string EngineUpdate { get; set; }
        public string EngineVersion { get; set; }

        public string Result { get; set; }

        public string Category { get; set; }
        public string Method { get; set; }

    }
}
