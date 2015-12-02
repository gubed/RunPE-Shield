using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Management;
using System.Reflection;
using System.Threading;
using System.Windows.Forms;
using RunPE_Shield.Extensions;
using RunPE_Shield.PE;

namespace RunPE_Shield.Forms
{
    public partial class frmMain : Form
    {
        public frmMain()
        {
            InitializeComponent();
        }

        private ManagementEventWatcher processStartEvent;
        private void frmMain_Load(object sender, EventArgs e)
        {
            
            processStartEvent = new ManagementEventWatcher("SELECT * FROM Win32_ProcessStartTrace");
            processStartEvent.EventArrived += ProcessStartEventArrived;
            processStartEvent.Start();
        }

        private void Suspend(string processName)
        {
            Process[] processes = Process.GetProcessesByName(processName);
            if (processes.Length == 0)
                return;
            bool killAll = false;
            foreach (Process p in processes)
            {
                if (!p.IsRunning())
                    continue;
                if (p.Is64Bit())
                    continue;

                // If runpe detected, kill original + children
                if (killAll)
                {
                    p.Kill();
                    continue;
                }
                Log("Analyzing process: " + p.ProcessName + ".exe with PID: " + p.Id);
                p.Suspend();

                if (!HasRunPE(p.Modules[0], p.Id))
                {
                    Log("Process clean: " + p.ProcessName + ".exe with PID: " + p.Id);
                    p.Resume();
                    continue;
                }
                if (!killAll) // Only show alert once
                    Log("RunPE detected! Killed process: " + p.ProcessName + ".exe with PID: " + p.Id);
               // p.Resume();
                killAll = true;
                if (p.IsRunning())
                    p.Kill();
            }

        }
        private bool HasRunPE(ProcessModule module, int processPID)
        {
            //Catch if process has been killed already
            try
            {
                Process p = Process.GetProcessById(processPID);
            }
            catch
            {
                return false;
            }

            string modulePath = module.FileName;
            PEInfomation procPE = PELoader.Load(processPID, module);
            PEInfomation filePE = PELoader.Load(modulePath);
            int unmachedValues = 0;


            unmachedValues += ScanType(procPE.FileHeader, filePE.FileHeader); // File Header
            unmachedValues += ScanType(procPE.OptionalHeader32, filePE.OptionalHeader32); // Optional Header
            int sectionAmmount = Math.Min(Convert.ToInt32(procPE.Overview.NumberOfSections), Convert.ToInt32(filePE.Overview.NumberOfSections));

            for (int i = 0; i < sectionAmmount; i++)
            {
                unmachedValues += ScanType(procPE.Sections[i], filePE.Sections[i]);
            }

            return (unmachedValues >= 5);
        }
        public void ProcessStartEventArrived(object sender, EventArrivedEventArgs e)
        {
            List<int> pidList = new List<int>();
            foreach (PropertyData pd in e.NewEvent.Properties)
            {
                string processName = e.NewEvent.Properties["ProcessName"].Value.ToString();
                int processID = Convert.ToInt32(e.NewEvent.Properties["ProcessID"].Value);

                //Avoid checking multiple times
                if(pidList.Contains(processID))
                    continue;
                
                pidList.Add(processID);
                
                // Log process start event
                Log(string.Format("Process {0} started with a PID of {1}.", processName, processID));

                //if (pd.Type != CimType.String)
                //    continue;
                //if (processName.Contains("ScriptedSandbox64"))
                //    continue;
                //if (processName.EndsWith(".vhost"))
                //    continue;
                //if (processName.EndsWith(".vshost.exe"))
                //    continue;


                // Get process name without exe
                int lastdot = processName.LastIndexOf('.');
                string nameNoExe = processName.Substring(0, lastdot);

                // Suspend process to scan
                new Thread(() => { Suspend(nameNoExe); }).Start();

            }
        }

        private int ScanType<T>(T procPE, T filePE)
        {
            Type scanType = typeof(T);

            int TunmachedValues = 0;

            foreach (FieldInfo f in scanType.GetFields())
            {
                object oProc = f.GetValue(procPE);
                object oFile = f.GetValue(filePE);

                if (oProc.ToString() != oFile.ToString())
                    TunmachedValues++;
            }
            return TunmachedValues;
        }

        private void Log(string text)
        {
            Invoke(new MethodInvoker(
                () =>
                {
                    tbLog.Text += string.Format("[{0}]: {1} {2}", DateTime.Now.ToString("hh:mm:ss"), text, Environment.NewLine);
                    tbLog.SelectionStart = tbLog.TextLength;
                    tbLog.ScrollToCaret();
                }));    
        }

        private void frmMain_FormClosing(object sender, FormClosingEventArgs e)
        {
            processStartEvent.Stop();
        }
    }

}
