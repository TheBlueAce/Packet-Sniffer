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
    public async void OnStartClick(object sender, RoutedEventArgs e)
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

        // don't start yet; wait for file to be created/first packet
        SummaryText.Text = "Status: Waiting for first packet...";
        _packetBuffer.Clear();
        _uiUpdateTimer.Start(); 

        // PREPARE ARGUMENTS
        string filter = FilterBox.Text ?? ""; 

        string duration = string.IsNullOrWhiteSpace(DurationBox.Text) ? "0" : DurationBox.Text;
        string count = string.IsNullOrWhiteSpace(CountBox.Text) ? "0" : CountBox.Text;

        if (!int.TryParse(duration, out _) || !int.TryParse(count, out _))
        {
            PacketList.Items.Add("[ERROR] Duration and Count must be numeric values.");
            SummaryText.Text = "Invalid input for duration or count.";
            return;
        }
        string fileName = FileNameBox.Text ?? "capture";
        var selectedItem = FormatBox.SelectedItem as ComboBoxItem;
        string extension = selectedItem?.Content?.ToString() ?? ".csv";
        bool saveToFile = SaveToFileBox.IsChecked ?? false;
        string filterArg = string.IsNullOrWhiteSpace(filter) ? "" : $"--filter \"{filter}\" ";
        string baseDir = AppContext.BaseDirectory; // where the app is running from (bin\Debug\net9.0\ etc.)
        string enginePath = Path.Combine(baseDir, "engine", "sniffer_engine.exe");
        string? outFilePath = null;

        if (saveToFile)
        {
            var sp = this.StorageProvider;

            var fileType = new FilePickerFileType("Capture")
            {
                Patterns = new[] { $"*{extension}" }
            };

            var saveResult = await sp.SaveFilePickerAsync(new FilePickerSaveOptions
            {
                Title = "Save capture as",
                SuggestedFileName = $"{fileName}{extension}",
                FileTypeChoices = new[] { fileType },
                DefaultExtension = extension.TrimStart('.')
            });

            if (saveResult is null)
            {
                // User cancelled save dialog
                PacketList.Items.Add("[INFO] Save cancelled.");
                StopAndFinalize();
                return;
            }

            outFilePath = saveResult.Path.LocalPath;
        }

        string arguments;

        if (saveToFile && !string.IsNullOrWhiteSpace(outFilePath))
        {
            // outfile is full path including extension
            arguments = $"{filterArg}--duration {duration} --count {count} --outfile \"{outFilePath}\" --save";
        }
        else
        {
            arguments = $"{filterArg}--duration {duration} --count {count}";
        }


        if (!File.Exists(enginePath))
        {
            PacketList.Items.Add($"[CRITICAL ERROR] Engine not found: {enginePath}");
            SummaryText.Text = "Engine missing.";
            StopAndFinalize();
            return;
        }

        ProcessStartInfo startInfo = new ProcessStartInfo
        {
            FileName = enginePath,
            Arguments = arguments,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            RedirectStandardInput = true,
            UseShellExecute = false,
            CreateNoWindow = true,
            WorkingDirectory = Path.GetDirectoryName(enginePath) ?? baseDir
        };

        try
        {
            _snifferProcess = new Process { StartInfo = startInfo };

            _snifferProcess.OutputDataReceived += (sender, args) =>
            {
                if (!string.IsNullOrEmpty(args.Data))
                {
                    string line = args.Data.Trim();

                    if (line.StartsWith("[FILE]"))
                    {
                        Dispatcher.UIThread.InvokeAsync(() =>
                        {
                            // Show save location clearly for the user
                            PacketList.Items.Add(line);
                            SummaryText.Text = line.Replace("[FILE]", "Saved to:").Trim();
                        });
                    }
                    else if (line.StartsWith("[SUMMARY]"))
                    {
                        Dispatcher.UIThread.InvokeAsync(() =>
                        {
                            StopAndFinalize();
                            string cleanSummary = line.Replace("[SUMMARY]", "").Trim();
                            SummaryText.Text = $"Done! {cleanSummary}";
                            PacketList.Items.Add("--------------------------------");
                            PacketList.Items.Add("CAPTURE COMPLETE!");
                        });
                    }
                    else if (line != "")
                    {
                        _packetBuffer.Enqueue(line);
                    }

                }
            };
            
            _snifferProcess.ErrorDataReceived += (sender, args) =>
            {
                if (!string.IsNullOrEmpty(args.Data))
                {
                    Dispatcher.UIThread.InvokeAsync(() => 
                        PacketList.Items.Add($"[PYTHON ERROR] {args.Data}"));
                }
            };

            _snifferProcess.Start();
            _snifferProcess.BeginOutputReadLine();
            _snifferProcess.BeginErrorReadLine();

            PacketList.Items.Add("[SUCCESS] Engine Started.");
        }
        catch (Exception ex)
        {
            StopAndFinalize();
            PacketList.Items.Add($"[CRITICAL ERROR] Failed to launch: {ex.Message}");
            SummaryText.Text = "Error launching sniffer.";
        }
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