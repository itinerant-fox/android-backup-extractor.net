using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using Org.BouncyCastle;
using Org.BouncyCastle.Crypto;

namespace ABE
{
    public class Program
    {

        public static void Main(String[] args)
        {
            //Security.addProvider(new Bouncy());
            if ((args.Length < 3))
            {
                usage();
                return;
            }

            String mode = args[0];
            if ((!"pack".Equals(mode)
                        && (!"unpack".Equals(mode)
                        && !"pack-kk".Equals(mode))))
            {
                usage();
                return;
            }

            bool unpack = "unpack".Equals(mode);
            String backupFilename = unpack ? args[1] : args[2];
            // TODO: Warning!!!, inline IF is not supported ?
            String tarFilename = unpack ? args[2] : args[1];
            // TODO: Warning!!!, inline IF is not supported ?
            String password = null;
            if ((args.Length > 3))
            {
                password = args[3];
            }

            if ((password == null))
            {
                password = Environment.GetEnvironmentVariable("ABE_PASSWD");
            }

            if (unpack)
            {
                try
                {
                    AndroidBackup.extractAsTar(backupFilename, tarFilename, password);
                }
                catch (InvalidCipherTextException exception)
                {
                    Console.WriteLine($"Error: {exception.Message} , Check supplied password");
                }
                catch (Exception e)
                {
                    Console.WriteLine($"Error: {e.Message}");
                }

            }
            else
            {
                bool isKitKat = "pack-kk".Equals(mode);
                AndroidBackup.packTar(tarFilename, backupFilename, password, isKitKat);
            }

        }

        private static void usage()
        {
            Console.WriteLine("Usage:");
            Console.WriteLine("  unpack:\tabe unpack\t<backup.ab> <backup.tar> [password]");
            Console.WriteLine("  pack:\t\tabe pack\t<backup.tar> <backup.ab> [password]");
            Console.WriteLine("  pack for 4.4:\tabe pack-kk\t<backup.tar> <backup.ab> [password]");
            Console.WriteLine("If the filename is `-`, then data is read from standard input");
            Console.WriteLine("or written to standard output.");
            Console.WriteLine("Envvar ABE_PASSWD is tried when password is not given");
        }
    }
}
