using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.Reflection;
using System.Threading;
using System.Windows.Forms;
using RunPE_Shield.Extensions;
using RunPE_Shield.PE;

namespace RunPE_Shield.Forms
{
    public partial class frmMain : Form
    {
        private List<int> activeProcesses = new List<int>();
        private DateTime lastCleaned = new DateTime(2014, 1, 1);
        private bool running = true;

        public frmMain()
        {
            InitializeComponent();
        }
        /// <summary>
        /// Form load event. Create thread to loop running processes.
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="e"></param>
        private void frmMain_Load(object sender, EventArgs e)
        {
            new Thread(LoopProcesses).Start();
        }
        /// <summary>
        /// Finds all currently running 32bit processes.
        /// </summary>
        private void LoopProcesses()
        {
            while (running)
            {
                foreach (Process p in Process.GetProcesses())
                {
                    if (p.Is64Bit())
                        continue;
                    if (p.Id == Process.GetCurrentProcess().Id)
                        continue;
                    if (p.MainModule.FileName.Contains(".vshost.exe") || p.MainModule.FileName.Equals(Assembly.GetExecutingAssembly().Location))
                        continue;

                    if (activeProcesses.Contains(p.Id))
                        continue;

                    activeProcesses.Add(p.Id);
                    Log("Process: " + p.ProcessName + ".exe started with PID: " + p.Id);
                    Analyze(p);
                }
                // Remove old processes from list every 30 seconds
                int time = (int)Math.Abs((DateTime.Now - lastCleaned).TotalSeconds);
                if (time >= 30)
                {
                    RemoveOldProcesses();
                    lastCleaned = DateTime.Now;
                }
                GC.Collect();
                Thread.Sleep(750);
            }
        }
        /// <summary>
        /// Removes processes that are no longer running from the process list.
        /// </summary>
        private void RemoveOldProcesses()
        {
            List<int> removeMe = new List<int>();
            foreach (int i in activeProcesses)
            {
                // If fails to get PID, remove from active process list
                try
                {
                    Process.GetProcessById(i);
                }
                catch (Exception)
                {
                    removeMe.Add(i);
                }
            }
            // Separate loops to prevent error
            foreach (int deadPID in removeMe)
            {
                if (activeProcesses.Contains(deadPID))
                    activeProcesses.Remove(deadPID);
            }
        }
        /// <summary>
        /// Determine if process has been created by a RunPE by checking mismatched headers.
        /// </summary>
        /// <param name="p">Process to analyze.</param>
        private void Analyze(Process p)
        {
            Log("Analyzing process: " + p.ProcessName + ".exe with PID: " + p.Id);
            //p.Suspend();

            if (HasRunPE(p.Modules[0], p.Id))
            {
                p.Kill();
                Log("RunPE detected! Killed process: " + p.ProcessName + ".exe with PID: " + p.Id, Color.Red);
                return;
            }

            Log("Process clean: " + p.ProcessName + ".exe with PID: " + p.Id, Color.SeaGreen);
            //p.Resume();
        }
        /// <summary>
        /// 
        /// </summary>
        /// <param name="module">Main module of process being analyzed</param>
        /// <param name="processPID">Process id of process being analyzed</param>
        /// <returns></returns>
        private bool HasRunPE(ProcessModule module, int processPID)
        {
            //Catch if process has been killed already
            //try
            //{
            //    Process.GetProcessById(processPID);
            //}
            //catch
            //{
            //    return false;
            //}

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

            return (unmachedValues >= 8);
        }
        /// <summary>
        /// Compares process PE header and file PE header and counts the differences.
        /// </summary>
        /// <typeparam name="T">Image header type</typeparam>
        /// <param name="procPE">Process PE header info</param>
        /// <param name="filePE">File PE header info</param>
        /// <returns></returns>
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

        /// <summary>
        /// Log all with time.
        /// </summary>
        /// <param name="text">Text to log.</param>
        /// <param name="color">Color of text.</param>
        private void Log(string text, Color color = default(Color))
        {
            Invoke(new MethodInvoker(
                () =>
                {
                    rtbLog.AppendText(string.Format("[{0}]: {1} {2}", DateTime.Now.ToString("hh:mm:ss"), text, Environment.NewLine), color);
                    rtbLog.SelectionStart = rtbLog.TextLength;
                    rtbLog.ScrollToCaret();
                    //tbLog.Text += string.Format("[{0}]: {1} {2}", DateTime.Now.ToString("hh:mm:ss"), text, Environment.NewLine);
                    //tbLog.SelectionStart = tbLog.TextLength;
                    //tbLog.ScrollToCaret();
                }));
        }
        /// <summary>
        /// Form closing event. 
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="e"></param>
        private void frmMain_FormClosing(object sender, FormClosingEventArgs e)
        {
            // Stop all threads
            running = false;
        }
        #region "Old"
        //private void Analyze(string processName)
        //{
        //    Process[] processes = Process.GetProcessesByName(processName);
        //    if (processes.Length == 0)
        //        return;
        //    bool killAll = false;
        //    foreach (Process p in processes)
        //    {
        //        if (!p.IsRunning())
        //            continue;
        //        if (p.Is64Bit())
        //            continue;

        //        // If runpe detected, kill original + children
        //        if (killAll)
        //        {
        //            p.Kill();
        //            continue;
        //        }
        //        Log("Analyzing process: " + p.ProcessName + ".exe with PID: " + p.Id);
        //        p.Suspend();

        //        if (!HasRunPE(p.Modules[0], p.Id))
        //        {
        //            Log("Process clean: " + p.ProcessName + ".exe with PID: " + p.Id);
        //            p.Resume();
        //            continue;
        //        }
        //        if (!killAll) // Only show alert once
        //            Log("RunPE detected! Killed process: " + p.ProcessName + ".exe with PID: " + p.Id);
        //        // p.Resume();
        //        killAll = true;
        //        if (p.IsRunning())
        //            p.Kill();
        //    }
#endregion
    }

}
