using System.Diagnostics;

namespace IssueBlot.Export;

// Renders a report by shelling out to the system's document converter.
public class ReportExporter
{
    public string Export(string format, string label)
    {
        var startInfo = new ProcessStartInfo
        {
            FileName = "/bin/sh",
            Arguments = "-c \"pandoc -t " + format + " -o /tmp/report_" + label + ".out\"",
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
        };

        using var process = Process.Start(startInfo)!;
        var output = process.StandardOutput.ReadToEnd();
        process.WaitForExit();
        return output;
    }
}
