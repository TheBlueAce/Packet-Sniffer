using System.Diagnostics; // for .exe files
using System.IO; // idk

namespace SnifferGUI
{
    public partial class Form1 : Form
    {
        private Process pythonProcess;
        private string tempFile = "temp_capture"; // temp file if user decides to not save, will be deleted on close
        private bool isManuallyStopped = false;
        public Form1()
        {
            InitializeComponent();
        }

        private void textBox1_TextChanged(object sender, EventArgs e)
        {

        }

        private void label2_Click(object sender, EventArgs e)
        {

        }

        private void btnStart_Click(object sender, EventArgs e)
        {
            txtOutput.Clear();
            btnStart.Enabled = false;
            btnStop.Enabled = true;
            isManuallyStopped = false;
            txtOutput.AppendText("Starting Sniffer...\r\n");

            string selectedFormat = cmbFormat.Text;
            string tempPath = tempFile + selectedFormat;

            // delete old temp file
            if (File.Exists(tempPath))
            {
                try { File.Delete(tempPath); }
                catch { MessageBox.Show("Warning: Could not clear old temp file. Check if open."); }
            }

            string args = $"--duration {txtDuration.Text} --filter \"{txtFilter.Text}\" --filename \"{tempFile}\" --format \"{selectedFormat}\"";

            ProcessStartInfo psi = new ProcessStartInfo();
            psi.FileName = "sniffer_engine.exe";
            psi.Arguments = args;
            psi.UseShellExecute = false;
            psi.RedirectStandardOutput = true;
            psi.CreateNoWindow = true;

            pythonProcess = new Process();
            pythonProcess.StartInfo = psi;
            pythonProcess.EnableRaisingEvents = true;

            pythonProcess.OutputDataReceived += (senderProc, data) =>
            {
                if (isManuallyStopped) return;
                if (!string.IsNullOrEmpty(data.Data))
                {
                    this.BeginInvoke((MethodInvoker)delegate
                    {
                        txtOutput.AppendText(data.Data + Environment.NewLine);
                        txtOutput.ScrollToCaret();
                    });
                }
            };

            pythonProcess.Exited += (senderProc, data) =>
            {
                if (isManuallyStopped) return;
                this.BeginInvoke(new Action(FinishCaptureSession));
            };

            try
            {
                pythonProcess.Start();
                pythonProcess.BeginOutputReadLine();
            }
            catch (Exception ex)
            {
                MessageBox.Show("Error running engine: " + ex.Message);
                btnStart.Enabled = true;
                btnStop.Enabled = false;
            }
        }

        private void PythonProcess_Exited(object? sender, EventArgs e)
        {
            throw new NotImplementedException();
        }

        private void txtDuration_TextChanged(object sender, EventArgs e)
        {

        }

        private void txtOutput_TextChanged(object sender, EventArgs e)
        {

        }

        private void label1_Click(object sender, EventArgs e)
        {

        }

        private void label1_Click_1(object sender, EventArgs e)
        {

        }

        private void Form1_Load(object sender, EventArgs e)
        {

        }

        private void comboBox1_SelectedIndexChanged(object sender, EventArgs e)
        {

        }

        private async void btnStop_Click(object sender, EventArgs e)
        {
            btnStop.Enabled = false;

            if (pythonProcess != null && !pythonProcess.HasExited)
            {
                try
                {
                    isManuallyStopped = true;
                    try { pythonProcess.CancelOutputRead(); } catch { }

                    pythonProcess.Kill();

                    using (var cts = new CancellationTokenSource(TimeSpan.FromSeconds(3)))
                    {
                        try { await pythonProcess.WaitForExitAsync(cts.Token); } catch { }
                    }
                }
                catch (Exception ex)
                {
                    Debug.WriteLine("Kill error: " + ex.Message);
                }
                finally
                {
                    if (pythonProcess != null)
                    {
                        pythonProcess.Dispose();
                        pythonProcess = null;
                    }
                }
            }

            FinishCaptureSession();
        }

        private string GetUniqueFilePath(string path)
        {
            if (!File.Exists(path)) return path;

            string dir = Path.GetDirectoryName(path);
            string fileName = Path.GetFileNameWithoutExtension(path);
            string ext = Path.GetExtension(path);
            int count = 1;

            string newPath;
            do
            {
                newPath = Path.Combine(dir, $"{fileName}({count}){ext}");
                count++;
            } while (File.Exists(newPath));

            return newPath;
        }
        private void FinishCaptureSession()
        {
            if (this.InvokeRequired)
            {
                this.Invoke(new Action(FinishCaptureSession));
                return;
            }

            DialogResult answer = MessageBox.Show("Capture ended. Do you want to save the log?",
                                                  "Save Capture", MessageBoxButtons.YesNo);

            string currentFormat = cmbFormat.Text;
            string sourceFile = tempFile + currentFormat;

            if (answer == DialogResult.Yes)
            {
                SaveFileDialog saveDialog = new SaveFileDialog();
                saveDialog.Filter = "Text File|*.txt|CSV File|*.csv|PCAP File|*.pcap";

                // auto-name: myCapture.csv, myCapture(1).csv, etc.
                string defaultName = "myCapture" + currentFormat;
                saveDialog.FileName = Path.GetFileNameWithoutExtension(GetUniqueFilePath(defaultName));

                switch (currentFormat)
                {
                    case ".csv": saveDialog.FilterIndex = 2; saveDialog.DefaultExt = "csv"; break;
                    case ".pcap": saveDialog.FilterIndex = 3; saveDialog.DefaultExt = "pcap"; break;
                    default: saveDialog.FilterIndex = 1; saveDialog.DefaultExt = "txt"; break;
                }

                if (saveDialog.ShowDialog() == DialogResult.OK)
                {
                    try
                    {
                        if (File.Exists(saveDialog.FileName)) File.Delete(saveDialog.FileName);

                        if (File.Exists(sourceFile))
                        {
                            bool success = false;
                            for (int i = 0; i < 10; i++)
                            {
                                try
                                {
                                    File.Move(sourceFile, saveDialog.FileName);
                                    success = true;
                                    break;
                                }
                                catch (IOException) { Task.Delay(200).Wait(); }
                            }

                            if (success) MessageBox.Show("Saved to: " + saveDialog.FileName);
                            else MessageBox.Show("Error: File was locked by Windows.");
                        }
                        else
                        {
                            MessageBox.Show("Error: Temp file missing.");
                        }
                    }
                    catch (Exception ex) { MessageBox.Show("Save failed: " + ex.Message); }
                }
                else
                {
                    if (File.Exists(sourceFile)) File.Delete(sourceFile);
                }
            }
            else
            {
                if (File.Exists(sourceFile)) File.Delete(sourceFile);
            }

            isManuallyStopped = false;
            btnStart.Enabled = true;
            btnStop.Enabled = false;
        }
    }
}
