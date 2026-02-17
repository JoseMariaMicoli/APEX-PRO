/*
Copyright (c) 2026 José María Micoli
Licensed under the Business Source License 1.1
Change Date: 2033-02-17
Change License: Apache-2.0

You may:
✔ Study
✔ Modify
✔ Use for internal security testing

You may NOT:
✘ Offer as a commercial service
✘ Sell derived competing products
*/

using System;
using System.Text;
using System.Management.Automation;
using System.Management.Automation.Runspaces;

namespace ApexRunner {
    class Program {
        static void Main(string[] args) {
            try {
                // The @ symbol handles the 28KB string without 'newline' errors
                string encodedScript = "REPLACE_ME"; 

                byte[] data = Convert.FromBase64String(encodedScript);
                string script = Encoding.UTF8.GetString(data);

                using (Runspace rs = RunspaceFactory.CreateRunspace()) {
                    rs.Open();
                    using (PowerShell ps = PowerShell.Create()) {
                        ps.Runspace = rs;
                        
                        // CORRECTION: Add script directly (No curly braces)
                        ps.AddScript(script);

                        // PATCH: Satisfy the Mandatory 'Mode' parameter from ApexSim.ps1
                        if (args.Length == 0) {
                            ps.AddParameter("Mode", "Encrypt");
                            ps.AddParameter("TargetPath", @"C:\SimulationData");
                        } else {
                            // Allows command line override: ApexUpdate.exe Decrypt
                            ps.AddParameter("Mode", args[0]);
                        }

                        // EXECUTE
                        ps.Invoke();
                    }
                    rs.Close();
                }
            } catch (Exception ex) {
                // Error feedback if run via Command Prompt
                Console.WriteLine("PowerShell Engine Error: " + ex.Message);
            }
        }
    }
}