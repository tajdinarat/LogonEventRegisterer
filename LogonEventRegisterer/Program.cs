using System;
using System.Diagnostics;
using System.IO;

namespace LogonEventRegisterer
{
    class Program
    {
        static string path = AppDomain.CurrentDomain.BaseDirectory + "LOGS\\";
        static string filepath = path + "logReg_" + DateTime.Now.Date.ToShortDateString().Replace('/', '_') + ".csv";
        public class singleLog
        {
            public singleLog()
            {

            }

            private string state;
            private string securityID;
            private string accountName;
            private string accountDomain;
            private string logonID;
            private DateTime dateTime;

            public void stateSet(string state)
            {
                this.state = state;
            }
            public string stateGet()
            {
                return this.state;
            }
            public void securityIDSet(string securityID)
            {
                this.securityID = securityID;
            }
            public string securityIDGet()
            {
                return this.securityID;
            }
            public void accountNameSet(string accountName)
            {
                this.accountName = accountName;
            }
            public string accountNameGet()
            {
                return this.accountName;
            }
            public void accountDomainSet(string accountDomain)
            {
                this.accountDomain = accountDomain;
            }
            public string accountDomainGet()
            {
                return this.accountDomain;
            }
            public void logonIDSet(string logonID)
            {
                this.logonID = logonID;
            }
            public string logonIDGet()
            {
                return this.logonID;
            }
            public void dateTimeSet(DateTime dateTime)
            {
                this.dateTime = dateTime;
            }
            public DateTime dateTimeGet()
            {
                return this.dateTime;
            }
        }

        static void Main(string[] args)
        {
            DoStuff();
            Console.WriteLine("\n ---Logon Event Registerer Stopped.---");
            Console.ReadKey();
        }

        private static void DoStuff()
        {
            /*
             * access "Security" log table to get data from
             */
            EventLog[] eventLog;
            EventLog entryToRead = new EventLog();

            while (true)
            {
                eventLog = EventLog.GetEventLogs(Environment.MachineName);

                foreach (var entry in eventLog)
                {
                    if (entry.Log == "Security")
                    {
                        entryToRead = entry;
                        break;
                    }
                }

                foreach (EventLogEntry log in entryToRead.Entries)
                {
                    /*
                     * check if log belongs to this date
                     * and check if exists to avoid overflow
                     */
                    if (DateTime.Now.Date == log.TimeWritten.Date)
                    {
                        /*
                         * Category number 4800 and 4801 indicates that
                         * this register contains logon/logoff data
                         */
                        if (log.InstanceId == 4800 || log.InstanceId == 4801)
                        {
                            if (!existControl(log))
                            {
                                singleLog newLog = new singleLog();
                                string[] datass = messageSplitter(log.Message);

                                newLog.stateSet(datass[0]);
                                newLog.securityIDSet(datass[1]);
                                newLog.accountNameSet(datass[2]);
                                newLog.accountDomainSet(datass[3]);
                                newLog.logonIDSet(datass[4]);
                                newLog.dateTimeSet(log.TimeWritten);

                                printLogSingle(newLog);
                            }
                        }
                    }
                }
                Console.WriteLine($"done --> {DateTime.Now}\n\nTarget directory : {path}");
            }
            
        }


        public static bool existControl(EventLogEntry log)
        {
            /*
             * check if the same log record exists
             */
            if (File.Exists(filepath))
            {
                var reader = File.ReadAllLines(filepath);
                foreach (var line in reader)
                {
                    if (log.TimeWritten.ToString().Trim() == line.Split(',')[0].Trim())
                    {
                        return true;
                    }
                }
            }
            return false;
        }
        public static void printLogSingle(singleLog myLog)
        {
            /*
             * create directory if not exists
             */

            Directory.CreateDirectory(path);

            
            /*
             * appending to (or if doesnt exist creating) the file
             * and record with a specific format*
             * 
             * *format : writing order of the strings below is important
             *           due to make reading easier.
             *           
             *           e.g. : headers and infos are aligned so it wont be confusing to read file
             */
            if (!File.Exists(filepath))
            {
                string headerTime = "Date & Time", headerState = "State", headerSecurityID = "Security ID", headerAccountName = "Account Name",
                    headerAccountDomain = "Domain", headerLogonID = "Logon ID";

                StreamWriter streamWriter = File.CreateText(filepath);
                streamWriter.WriteLine($"{headerTime} , {headerState} , {headerAccountDomain} , {headerAccountName} , {headerLogonID} , {headerSecurityID}");
                streamWriter.WriteLine($"{myLog.dateTimeGet()} , {myLog.stateGet()} , {myLog.accountDomainGet()} , {myLog.accountNameGet()} , " +
                    $"{myLog.logonIDGet()} , {myLog.securityIDGet()}");

                streamWriter.Close();
            }
            else
            {
                StreamWriter streamWriter = File.AppendText(filepath);
                streamWriter.WriteLine($"{myLog.dateTimeGet()} , {myLog.stateGet()} , {myLog.accountDomainGet()} , {myLog.accountNameGet()} , " +
                    $"{myLog.logonIDGet()} , {myLog.securityIDGet()}");
                streamWriter.Close();
            }
        }

        public static string[] messageSplitter(string messageToSplit)
        {
            //split message data to retrieve needed info
            string[] lines = messageToSplit.Split(new[] { Environment.NewLine },StringSplitOptions.None);
            string[] linesFinal = new string[5];
            linesFinal[0] = lines[0]; //state
            linesFinal[1] = (lines[3].Trim().Split())[3]; //security id
            linesFinal[2] = (lines[4].Trim().Split())[3]; //account name
            linesFinal[3] = (lines[5].Trim().Split())[3]; //account domain
            linesFinal[4] = (lines[6].Trim().Split())[3]; //logon id
            return linesFinal;
        }
    }
}
