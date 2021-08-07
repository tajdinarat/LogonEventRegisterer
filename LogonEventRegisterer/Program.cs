using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;

namespace LogonEventRegisterer
{
    class Program
    {
        public class singleReg
        {
            public singleReg()
            {

            }

            private string message = "";
            private DateTime timeGenerated;
            private DateTime timeWritten;
            private string machine = "";
            private long instanceID;
            private string category = "";
            private string username = "";

            private string entryType = "";
            public void entryTypeSet(string entryType)
            {
                this.entryType = entryType;
            }
            public string entryTypeGet()
            {
                return entryType;
            }
            private string eventId = "";
            public void eventIdSet(string eventId)
            {
                this.eventId = eventId;
            }
            public string eventIdGet()
            {
                return eventId;
            }

            public void messageSet(string message)
            {
                this.message = message;
            }
            public string messageGet()
            {
                return message;
            }

            public void timeGeneratedSet(DateTime timeGenerated)
            {
                this.timeGenerated = timeGenerated;
            }
            public DateTime timeGeneratedGet()
            {
                return timeGenerated;
            }

            public void timeWrittenSet(DateTime timeWritten)
            {
                this.timeWritten = timeWritten;
            }
            public DateTime timeWrittenGet()
            {
                return timeWritten;
            }

            public void machineSet(string machine)
            {
                this.machine = machine;
            }
            public string machineGet()
            {
                return machine;
            }

            public void instanceIDSet(long instanceID)
            {
                this.instanceID = instanceID;
            }
            public long instanceIDGet()
            {
                return instanceID;
            }

            public void categorySet(string category)
            {
                this.category = category;
            }
            public string categoryGet()
            {
                return category;
            }

            public void usernameSet(string username)
            {
                this.username = username;
            }
            public string usernameGet()
            {
                return username;
            }
        }


        static void Main(string[] args)
        {
            /*
             * access "System" log table to get data from
             */
            EventLog[] eventLog = EventLog.GetEventLogs(Environment.MachineName);
            EventLog entryToRead = new EventLog();
            EventLog entryToReadSec = new EventLog();
            List<singleReg> regList = new List<singleReg>();
            List<singleReg> regListSec = new List<singleReg>();
            foreach (var entry in eventLog)
            {
                if(entry.Log == "System")
                {
                    entryToRead = entry;
                }
                else if(entry.Log == "Security")
                {
                    entryToReadSec = entry;
                }
            }

            foreach (EventLogEntry log in entryToRead.Entries)
            {
                if (log.Source == "Microsoft-Windows-Winlogon")
                {
                    singleReg newReg = new singleReg();
                    newReg.messageSet(log.Message.Substring(0, 11).ToUpper());
                    newReg.timeGeneratedSet(log.TimeGenerated);
                    newReg.timeWrittenSet(log.TimeWritten);
                    newReg.machineSet(log.MachineName);
                    newReg.instanceIDSet(log.InstanceId);
                    newReg.categorySet(log.Category);
                    newReg.usernameSet(log.UserName);
                    regList.Add(newReg);


                    //Console.WriteLine($"\nmessage         : {log.Message.Substring(0, 11).ToUpper()}");
                    //Console.WriteLine($"time generated  : {log.TimeGenerated}");
                    //Console.WriteLine($"time written    : {log.TimeWritten}");
                    //Console.WriteLine($"machine         : {log.MachineName}");
                    //Console.WriteLine($"instance ID     : {log.InstanceId}");
                    //Console.WriteLine($"category        : {log.Category}");
                    //Console.WriteLine($"username        : {log.UserName}");
                }
            }
            printToText(regList);
            GC.Collect();

            foreach (EventLogEntry log in entryToReadSec.Entries)
            {
                if(log.Source == "Microsoft-Windows-Security-Auditing")
                {
                    //Console.WriteLine("\n===================================");
                    //Console.WriteLine($"\nmessage             : {log.Message}");
                    //Console.WriteLine($"time generated      : {log.TimeGenerated}");
                    //Console.WriteLine($"time written        : {log.TimeWritten}");
                    //Console.WriteLine($"entry type          : {log.EntryType}");
                    //Console.WriteLine($"event id            : {log.EventID}");
                    //Console.WriteLine($"instance id         : {log.InstanceId}");
                    //Console.WriteLine($"machine name        : {log.MachineName}");
                    //Console.WriteLine($"category            : {log.Category}");
                    //Console.WriteLine($"category number     : {log.CategoryNumber}");
                    //Console.WriteLine($"container           : {log.Container}");
                    //Console.WriteLine($"data                : {log.Data}");
                    //Console.WriteLine($"replacement strings : {log.ReplacementStrings}");
                    //Console.WriteLine($"site                : {log.Site}");
                    //Console.WriteLine($"source              : {log.Source}");
                    //Console.WriteLine($"username            : {log.UserName}");
                    //Console.WriteLine("\n---------------------------------------");
                    //Console.WriteLine($"\n     : {log}");
                    
                    if(log.EntryType.ToString() == "SuccessAudit" || log.EntryType.ToString() == "FailureAudit")
                    {
                        singleReg newReg = new singleReg();
                        newReg.messageSet("-");
                        /*
                         * we should trim it
                         * 
                         * newReg.messageSet(log.Message);
                         */
                        newReg.timeGeneratedSet(log.TimeGenerated);
                        newReg.timeWrittenSet(log.TimeWritten);
                        newReg.machineSet(log.MachineName);
                        newReg.instanceIDSet(log.InstanceId);
                        newReg.categorySet(log.Category);
                        newReg.usernameSet(log.UserName);
                        newReg.entryTypeSet(log.EntryType.ToString());
                        newReg.eventIdSet(log.EventID.ToString());
                        regListSec.Add(newReg);
                    }
                }
            }
            printToTextSec(regListSec);
            
            Console.WriteLine("done.");
            Console.ReadKey();

        }

        public static void printToTextSec(List<singleReg> regList)
        {
            string path = AppDomain.CurrentDomain.BaseDirectory + "\\LOGS";

            if (!Directory.Exists(path))
            {
                Directory.CreateDirectory(path);
            }

            string filepath = path + "\\logRegSec_" + DateTime.Now.Date.ToShortDateString().Replace('/', '_') + "1.csv";

            if (!File.Exists(filepath))
            {
                StreamWriter streamWriter = File.CreateText(filepath);
                streamWriter.Write("InstanceID , MachineName , Date&Time , Message , Username , ");
                streamWriter.WriteLine("Category , EntryType , EventID");
                foreach (var regObject in regList)
                {
                    streamWriter.Write($"{regObject.instanceIDGet()} , {regObject.machineGet()} , {regObject.timeGeneratedGet()} , ");
                    streamWriter.Write($"{regObject.messageGet()} , {regObject.usernameGet()} , ");
                    streamWriter.WriteLine($"{regObject.categoryGet()} , {regObject.entryTypeGet()} , {regObject.eventIdGet()}");
                }
            }
            else
            {
                StreamWriter streamWriter = File.AppendText(filepath);
                foreach (var regObject in regList)
                {
                    streamWriter.Write($"{regObject.instanceIDGet()} , {regObject.machineGet()} , {regObject.timeGeneratedGet()} , ");
                    streamWriter.Write($"{regObject.messageGet()} , {regObject.usernameGet()} , ");
                    streamWriter.WriteLine($"{regObject.categoryGet()} , {regObject.entryTypeGet()} , {regObject.eventIdGet()}");
                }
            }
        }

        public static void printToText(List<singleReg> regList)
        {
            string path = AppDomain.CurrentDomain.BaseDirectory + "\\LOGS";
            if(!Directory.Exists(path))
            {
                Directory.CreateDirectory(path);
            }

            string filepath = path + "\\logReg_" + DateTime.Now.Date.ToShortDateString().Replace('/', '_') + "1.csv";

            if(!File.Exists(filepath))
            {
                StreamWriter streamWriter = File.CreateText(filepath);
                streamWriter.WriteLine("InstanceID , MachineName , Date&Time , Message , Username");
                foreach (var regObject in regList)
                {
                    streamWriter.Write($"{regObject.instanceIDGet()} , {regObject.machineGet()} , {regObject.timeGeneratedGet()} , ");
                    streamWriter.WriteLine($"{regObject.messageGet()} , {regObject.usernameGet()}");
                }
            }
            else
            {
                StreamWriter streamWriter = File.AppendText(filepath);
                foreach (var regObject in regList)
                {
                    streamWriter.Write($"{regObject.instanceIDGet()} , {regObject.machineGet()} , {regObject.timeGeneratedGet()} , ");
                    streamWriter.WriteLine($"{regObject.timeWrittenGet()} , {regObject.messageGet()} , {regObject.usernameGet()}");
                }
            }
        }
    }
}
