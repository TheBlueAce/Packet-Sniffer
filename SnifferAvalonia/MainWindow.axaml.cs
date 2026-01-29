using Avalonia.Controls;
using Avalonia.Interactivity;
using Avalonia.Threading;
using System.Collections.Concurrent;
using System.Diagnostics; 
using System.IO;          
using System;
using Avalonia.Platform.Storage;
using System.Threading.Tasks;

namespace SnifferAvalonia;

public partial class MainWindow : Window
{
    private Process? _snifferProcess;
    
    private ConcurrentQueue<string> _packetBuffer = new();
    
    private DispatcherTimer _uiUpdateTimer;
    
    private int _totalPackets = 0;
    private Stopwatch _runTimer = new();

    public MainWindow()
    {
        InitializeComponent();

        _uiUpdateTimer = new DispatcherTimer
        {
            Interval = TimeSpan.FromMilliseconds(100)
        };
        _uiUpdateTimer.Tick += UpdateGuiFromBuffer;
    }

    private void UpdateGuiFromBuffer(object? sender, EventArgs e)
    {
        bool hidePackets = HidePacketsBox.IsChecked ?? false;

        // If no new packets, still keep summary text updated (once timer has started)
        if (_runTimer.IsRunning)
        {
            string liveTime = _runTimer.Elapsed.ToString(@"hh\:mm\:ss");
            SummaryText.Text = $"Status: Capturing | Packets: {_totalPackets} | Time: {liveTime}";
        }

        if (_packetBuffer.IsEmpty) return;

        while (_packetBuffer.TryDequeue(out string? line))
        {
            if (string.IsNullOrWhiteSpace(line))
                continue;

            // Start timer only when first packet actually arrives
            if (!_runTimer.IsRunning)
                _runTimer.Start();

            _totalPackets++;

            if (!hidePackets)
                PacketList.Items.Add(line);
        }

        if (!hidePackets && PacketList.Items.Count > 0)
        {
            PacketList.ScrollIntoView(PacketList.Items.Count - 1);
        }
    }

    // START BUTTON
    public void OnStartClick(object sender, RoutedEventArgs e)
    {
        if (_snifferProcess != null && !_snifferProcess.HasExited)
        {
            PacketList.Items.Add("[ERROR] Sniffer is already running!");
            return;
        }

        PacketList.Items.Clear();
        PacketList.Items.Add("Initializing Engine...");

        _totalPackets = 0;
        _runTimer.Reset();
        _runTimer.Start();
        _packetBuffer.Clear();
        _uiUpdateTimer.Start();

        string baseDir = AppDomain.CurrentDomain.BaseDirectory;
        string engineExe = Path.Combine(baseDir, "engine", "sniffer_gui.exe");
        
        string scriptPath = Path.Combine(Directory.GetCurrentDirectory(), "sniffer_gui.py");
        if (!File.Exists(scriptPath)) 
        {
             scriptPath = Path.Combine(baseDir, "..", "sniffer_gui.py"); 
        }

        ProcessStartInfo startInfo;
        bool isLinux = System.Runtime.InteropServices.RuntimeInformation.IsOSPlatform(System.Runtime.InteropServices.OSPlatform.Linux);
        
        if (File.Exists(engineExe) && !isLinux)
        {
             PacketList.Items.Add($"Mode: Production (Windows Engine)");
             string args = BuildArguments(); 
             startInfo = CreateProcessInfo(engineExe, args, Path.GetDirectoryName(engineExe) ?? baseDir);
        }
        // The Raw Python Script (Docker / Linux / Mac)
        else if (File.Exists(scriptPath))
        {
             PacketList.Items.Add($"Mode: Container/Dev (Python Script)");
             string pythonName = isLinux ? "python3" : "python";
             
             string args = $"\"{scriptPath}\" " + BuildArguments();
             startInfo = CreateProcessInfo(pythonName, args, Path.GetDirectoryName(scriptPath) ?? baseDir);
        }
        else
        {
             PacketList.Items.Add("[CRITICAL ERROR] No engine found!");
             PacketList.Items.Add($"Checked: {engineExe}");
             PacketList.Items.Add($"Checked: {scriptPath}");
             StopAndFinalize();
             return;
        }

        try
        {
            _snifferProcess = new Process { StartInfo = startInfo };
            
            _snifferProcess.OutputDataReceived += (sender, args) => 
            {
                 if (!string.IsNullOrEmpty(args.Data)) {
                    string line = args.Data.Trim();
                    if (line.StartsWith("[SUMMARY]")) {
                        Dispatcher.UIThread.InvokeAsync(() => {
                            StopAndFinalize();
                            string cleanSummary = line.Replace("[SUMMARY]", "").Trim();
                            SummaryText.Text = $"Done! {cleanSummary}";
                            PacketList.Items.Add("--------------------------------");
                            PacketList.Items.Add("CAPTURE COMPLETE.");
                        });
                    } else if (line != "") {
                        _packetBuffer.Enqueue(line);
                    }
                 }
            };
            
            _snifferProcess.ErrorDataReceived += (sender, args) => 
            {
                if (!string.IsNullOrEmpty(args.Data)) Dispatcher.UIThread.InvokeAsync(() => PacketList.Items.Add($"[STDERR] {args.Data}"));
            };

            _snifferProcess.Start();
            _snifferProcess.BeginOutputReadLine();
            _snifferProcess.BeginErrorReadLine();
            PacketList.Items.Add("[SUCCESS] Engine Started.");
        }
        catch (Exception ex)
        {
            StopAndFinalize();
            PacketList.Items.Add($"[CRITICAL ERROR] Launch failed: {ex.Message}");
        }
    }

    // --- HELPER 1: Build Arguments String ---
    private string BuildArguments()
    {
        string filter = FilterBox.Text ?? ""; 
        string duration = DurationBox.Text ?? "0";
        string count = CountBox.Text ?? "0";
        string fileName = FileNameBox.Text ?? "capture";
        var selectedItem = FormatBox.SelectedItem as ComboBoxItem;
        string extension = selectedItem?.Content?.ToString() ?? ".csv";
        bool saveToFile = SaveToFileBox.IsChecked ?? false;
        string saveArg = saveToFile ? "--save" : "";

        return $"--filter \"{filter}\" --duration {duration} --count {count} --filename \"{fileName}\" --format \"{extension}\" {saveArg}";
    }

    private ProcessStartInfo CreateProcessInfo(string fileName, string args, string workingDir)
    {
        return new ProcessStartInfo
        {
            FileName = fileName, 
            Arguments = args,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            RedirectStandardInput = true, 
            UseShellExecute = false,
            CreateNoWindow = true,
            WorkingDirectory = workingDir 
        };
    }

    // STOP BUTTON
    public void OnStopClick(object sender, RoutedEventArgs e)
    {
        if (_snifferProcess != null && !_snifferProcess.HasExited)
        {
            try
            {
                PacketList.Items.Add("[INFO] Requesting graceful stop...");
                SummaryText.Text = "Stopping...";

                _snifferProcess.StandardInput.WriteLine("STOP");
                _snifferProcess.StandardInput.Flush();

                if (!_snifferProcess.WaitForExit(3000))
                {
                    PacketList.Items.Add("[WARN] Engine didn't stop in time, forcing kill...");
                    _snifferProcess.Kill(true);
                    _snifferProcess.WaitForExit(2000);
                }

                StopAndFinalize();
                _snifferProcess = null;
            }
            catch (Exception ex)
            {
                PacketList.Items.Add($"[ERROR] Failed to stop: {ex.Message}");
            }
        }
        else
        {
            PacketList.Items.Add("[INFO] No running process to stop.");
        }
    }


    private void StopAndFinalize()
    {
        _uiUpdateTimer.Stop();
        _runTimer.Stop();
    }
}