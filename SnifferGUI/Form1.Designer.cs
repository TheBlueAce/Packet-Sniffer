namespace SnifferGUI
{
    partial class Form1
    {
        /// <summary>
        ///  Required designer variable.
        /// </summary>
        private System.ComponentModel.IContainer components = null;

        /// <summary>
        ///  Clean up any resources being used.
        /// </summary>
        /// <param name="disposing">true if managed resources should be disposed; otherwise, false.</param>
        protected override void Dispose(bool disposing)
        {
            if (disposing && (components != null))
            {
                components.Dispose();
            }
            base.Dispose(disposing);
        }

        #region Windows Form Designer generated code

        /// <summary>
        ///  Required method for Designer support - do not modify
        ///  the contents of this method with the code editor.
        /// </summary>
        private void InitializeComponent()
        {
            System.ComponentModel.ComponentResourceManager resources = new System.ComponentModel.ComponentResourceManager(typeof(Form1));
            lblFilter = new Label();
            lblDuration = new Label();
            txtFilter = new TextBox();
            txtDuration = new TextBox();
            btnStart = new Button();
            txtOutput = new RichTextBox();
            txtDesc = new Label();
            label1 = new Label();
            btnStop = new Button();
            cmbFormat = new ComboBox();
            SuspendLayout();
            // 
            // lblFilter
            // 
            lblFilter.AutoSize = true;
            lblFilter.Location = new Point(266, 167);
            lblFilter.Name = "lblFilter";
            lblFilter.Size = new Size(36, 15);
            lblFilter.TabIndex = 0;
            lblFilter.Text = "Filter:";
            // 
            // lblDuration
            // 
            lblDuration.AutoSize = true;
            lblDuration.Location = new Point(243, 196);
            lblDuration.Name = "lblDuration";
            lblDuration.Size = new Size(59, 15);
            lblDuration.TabIndex = 1;
            lblDuration.Text = "Duration: ";
            lblDuration.Click += label2_Click;
            // 
            // txtFilter
            // 
            txtFilter.Location = new Point(308, 164);
            txtFilter.Name = "txtFilter";
            txtFilter.Size = new Size(100, 23);
            txtFilter.TabIndex = 2;
            txtFilter.TextChanged += textBox1_TextChanged;
            // 
            // txtDuration
            // 
            txtDuration.Location = new Point(308, 193);
            txtDuration.Name = "txtDuration";
            txtDuration.Size = new Size(100, 23);
            txtDuration.TabIndex = 3;
            txtDuration.Text = "10";
            txtDuration.TextChanged += txtDuration_TextChanged;
            // 
            // btnStart
            // 
            btnStart.Location = new Point(308, 235);
            btnStart.Name = "btnStart";
            btnStart.Size = new Size(100, 24);
            btnStart.TabIndex = 4;
            btnStart.Text = "Start Sniffing!";
            btnStart.UseVisualStyleBackColor = true;
            btnStart.Click += btnStart_Click;
            // 
            // txtOutput
            // 
            txtOutput.Location = new Point(450, 35);
            txtOutput.Name = "txtOutput";
            txtOutput.ReadOnly = true;
            txtOutput.ScrollBars = RichTextBoxScrollBars.Vertical;
            txtOutput.Size = new Size(399, 435);
            txtOutput.TabIndex = 5;
            txtOutput.Text = "";
            txtOutput.TextChanged += txtOutput_TextChanged;
            // 
            // txtDesc
            // 
            txtDesc.AutoSize = true;
            txtDesc.Location = new Point(22, 38);
            txtDesc.Name = "txtDesc";
            txtDesc.Size = new Size(386, 105);
            txtDesc.TabIndex = 6;
            txtDesc.Text = resources.GetString("txtDesc.Text");
            txtDesc.Click += label1_Click;
            // 
            // label1
            // 
            label1.AutoSize = true;
            label1.Location = new Point(22, 64);
            label1.Name = "label1";
            label1.Size = new Size(0, 15);
            label1.TabIndex = 7;
            label1.Click += label1_Click_1;
            // 
            // btnStop
            // 
            btnStop.Enabled = false;
            btnStop.Location = new Point(308, 265);
            btnStop.Name = "btnStop";
            btnStop.Size = new Size(100, 24);
            btnStop.TabIndex = 8;
            btnStop.Text = "Stop and Save!";
            btnStop.UseVisualStyleBackColor = true;
            btnStop.Click += btnStop_Click;
            // 
            // cmbFormat
            // 
            cmbFormat.FormattingEnabled = true;
            cmbFormat.Items.AddRange(new object[] { ".txt", ".csv", ".pcap" });
            cmbFormat.Location = new Point(298, 304);
            cmbFormat.Name = "cmbFormat";
            cmbFormat.Size = new Size(121, 23);
            cmbFormat.TabIndex = 9;
            cmbFormat.Text = ".txt";
            cmbFormat.SelectedIndexChanged += comboBox1_SelectedIndexChanged;
            // 
            // Form1
            // 
            AutoScaleDimensions = new SizeF(7F, 15F);
            AutoScaleMode = AutoScaleMode.Font;
            ClientSize = new Size(861, 494);
            Controls.Add(cmbFormat);
            Controls.Add(btnStop);
            Controls.Add(label1);
            Controls.Add(txtDesc);
            Controls.Add(txtOutput);
            Controls.Add(btnStart);
            Controls.Add(txtDuration);
            Controls.Add(txtFilter);
            Controls.Add(lblDuration);
            Controls.Add(lblFilter);
            Name = "Form1";
            Text = "Form1";
            Load += Form1_Load;
            ResumeLayout(false);
            PerformLayout();
        }

        #endregion

        private Label lblFilter;
        private Label lblDuration;
        private TextBox txtFilter;
        private TextBox txtDuration;
        private Button btnStart;
        private RichTextBox txtOutput;
        private Label txtDesc;
        private Label label1;
        private Button btnStop;
        private ComboBox cmbFormat;
    }
}
