//Reference : https://github.com/lclevy/ab_decrypt
//            https://github.com/nelenkov/android-backup-extractor
//            http://nelenkov.blogspot.in/2012/06/unpacking-android-backups.html

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Authentication.ExtendedProtection;
using System.Text;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.IO;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Paddings;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Utilities.Zlib;

namespace ABE
{
    public class AndroidBackup
    {
        private static int BACKUP_MANIFEST_VERSION = 1;

        private static String BACKUP_FILE_HEADER_MAGIC = "ANDROID BACKUP\n";

        private static int BACKUP_FILE_V1 = 1;

        private static int BACKUP_FILE_V2 = 2;

        private static int BACKUP_FILE_V3 = 3;

        private static int BACKUP_FILE_V4 = 4;

        private static String ENCRYPTION_MECHANISM = "AES/CBC/PKCS5Padding";

        private static int PBKDF2_HASH_ROUNDS = 10000;

        private static int PBKDF2_KEY_SIZE = 256;//  bits
        private static int MASTER_KEY_SIZE = 256;//  bits
        private static int PBKDF2_SALT_SIZE = 512;//  bits


        private static String ENCRYPTION_ALGORITHM_NAME = "AES-256";

        private static bool DEBUG = false;

        private static SecureRandom random = new SecureRandom();

        private AndroidBackup()
        {

        }

        public static void extractAsTar(String backupFilename, String filename, String password)
        {
            try
            {
                Stream inStream = AndroidBackup.getInputStream(backupFilename);

                CipherStream cipherStream = null;
                String magic = AndroidBackup.readHeaderLine(inStream); //  1
                if (DEBUG)
                {
                    Console.WriteLine(("Magic: " + magic));
                }

                String versionStr = AndroidBackup.readHeaderLine(inStream);  //  2
                if (DEBUG)
                {
                    Console.WriteLine(("Version: " + versionStr));
                }

                int version = int.Parse(versionStr);
                if (((version < BACKUP_FILE_V1)
                     || (version > BACKUP_FILE_V4)))
                {
                    throw new ArgumentException("Don\'t know how to process version " + versionStr);
                }

                String compressed = AndroidBackup.readHeaderLine(inStream);  //  3

                bool isCompressed = (int.Parse(compressed) == 1);
                if (DEBUG)
                {
                    Console.WriteLine(("Compressed: " + compressed));
                }

                String encryptionAlg = AndroidBackup.readHeaderLine(inStream); //  4
                if (DEBUG)
                {
                    Console.WriteLine(("Algorithm: " + encryptionAlg));
                }

                bool isEncrypted = false;
                if (encryptionAlg.Equals(ENCRYPTION_ALGORITHM_NAME))
                {
                    isEncrypted = true;


                    //if ((Cipher.getMaxAllowedKeyLength("AES") < MASTER_KEY_SIZE))
                    //{
                    //    Console.WriteLine("WARNING: Maximum allowed key-Length seems smaller than needed. " +
                    //             "Please check that unlimited strength cryptography is available, see README.md for details");
                    //}

                    if (((password == null)
                         || "".Equals(password)))
                    {
                        Console.WriteLine("This backup is encrypted, please provide the password: ");
                        password = ReadPassword('*');
                    }

                    String userSaltHex = AndroidBackup.readHeaderLine(inStream);
                    //  5
                    byte[] userSalt = AndroidBackup.hexToByteArray(userSaltHex);
                    if ((userSalt.Length
                         != (PBKDF2_SALT_SIZE / 8)))
                    {
                        throw new ArgumentException(("Invalid salt Length: " + userSalt.Length));
                    }

                    String ckSaltHex = AndroidBackup.readHeaderLine(inStream); //  6
                    byte[] ckSalt = AndroidBackup.hexToByteArray(ckSaltHex);

                    int rounds = int.Parse(AndroidBackup.readHeaderLine(inStream)); //  7
                    String userIvHex = AndroidBackup.readHeaderLine(inStream); //  8

                    String masterKeyBlobHex = AndroidBackup.readHeaderLine(inStream); //  9

                    //  decrypt the master key blob
                    IBufferedCipher c = CipherUtilities.GetCipher(ENCRYPTION_MECHANISM);

                    //  XXX we don't support non-ASCII passwords
                    byte[] userKey = AndroidBackup.buildPasswordKey(password, userSalt, rounds, false);
                    byte[] IV = AndroidBackup.hexToByteArray(userIvHex);
                    byte[] ivSpec = IV;

                    c.Init(false, new ParametersWithIV(ParameterUtilities.CreateKeyParameter("AES256", userKey), ivSpec));
                    //c.Init(false, new ParametersWithIV(new KeyParameter(userKey), ivSpec));

                    byte[] mkCipher = AndroidBackup.hexToByteArray(masterKeyBlobHex);
                    byte[] mkBlob = c.DoFinal(mkCipher);
                    //  first, the master key IV
                    int offset = 0;
                    int len = mkBlob[offset++];
                    IV = Arrays.CopyOfRange(mkBlob, offset, (offset + len));

                    if (DEBUG)
                    {
                        Console.WriteLine(("IV: " + AndroidBackup.toHex(IV)));
                    }

                    offset = (offset + len);
                    //  then the master key itself
                    len = mkBlob[offset++];
                    byte[] mk = Arrays.CopyOfRange(mkBlob, offset, (offset + len));
                    if (DEBUG)
                    {
                        Console.WriteLine(("MK: " + AndroidBackup.toHex(mk)));
                    }

                    offset = (offset + len);
                    //  and finally the master key checksum hash
                    len = mkBlob[offset++];
                    byte[] mkChecksum = Arrays.CopyOfRange(mkBlob, offset, (offset + len));
                    if (DEBUG)
                    {
                        Console.WriteLine(("MK checksum: " + AndroidBackup.toHex(mkChecksum)));
                    }

                    //  now validate the decrypted master key against the checksum
                    //  first try the algorithm matching the archive version
                    bool useUtf = (version >= BACKUP_FILE_V2);
                    byte[] calculatedCk = AndroidBackup.makeKeyChecksum(mk, ckSalt, rounds, useUtf);
                    Console.Error.WriteLine("Calculated MK checksum (use UTF-8: {0}): {1}\n", useUtf,
                        AndroidBackup.toHex(calculatedCk));
                    if (!Arrays.Equals(calculatedCk, mkChecksum))
                    {
                        Console.WriteLine("Checksum does not match.");
                        //  try the reverse
                        calculatedCk = AndroidBackup.makeKeyChecksum(mk, ckSalt, rounds, !useUtf);
                        Console.Error.WriteLine("Calculated MK checksum (use UTF-8: {0}): {1}\n", useUtf,
                            AndroidBackup.toHex(calculatedCk));
                    }


                    // Even if checksum doesn't match, it works .. No idea why.// 
                    //  if (Arrays.Equals(calculatedCk, mkChecksum))
                    {
                        ivSpec = IV;

                        c.Init(false, new ParametersWithIV(ParameterUtilities.CreateKeyParameter("AES256", mk), ivSpec));
                        //c.init(Cipher.DECRYPT_MODE, new byte[]Spec(mk, "AES"), ivSpec);
                        //  Only if all of the above worked properly will 'result' be
                        //  assigned
                        cipherStream = new CipherStream(inStream, c, null);
                    }

                }

                if ((isEncrypted
                     && (cipherStream == null)))
                {
                    throw new Exception("Invalid password or master key checksum.");
                }

                Stream baseStream = isEncrypted ? cipherStream : inStream;
                Stream input = isCompressed ? new ZInputStream(baseStream) : baseStream;
                Stream output = null;

                try
                {
                    output = getOutputStream(filename);
                    byte[] buff = new byte[(10 * 1024)];
                    int read = -1;
                    int totalRead = 0;
                    while ((read = input.Read(buff, 0, buff.Length)) > 0)
                    {
                        output.Write(buff, 0, read);
                        totalRead = (totalRead + read);
                        if ((DEBUG
                             && ((totalRead % (100 * 1024))
                                 == 0)))
                        {
                            Console.Error.WriteLine("{0} bytes written\n", totalRead);
                        }
                    }
                    Console.Error.WriteLine("{0} bytes written to {1}.\n", totalRead, backupFilename);
                }
                finally
                {
                    if (input != null)
                    {
                        input.Close();
                    }

                    if (output != null)
                    {
                        output.Flush();
                        output.Close();
                    }
                }
            }
            catch (Exception e)
            {
                throw;
            }

        }

        public static void packTar(String tarFilename, String backupFilename, String password, bool isKitKat)
        {
            bool encrypting = ((password != null)
                               && !"".Equals(password));
            bool compressing = true;
            StringBuilder headerbuf = new StringBuilder(1024);

            headerbuf.Append(BACKUP_FILE_HEADER_MAGIC);
            // integer, no trailing \n
            headerbuf.Append(isKitKat ? BACKUP_FILE_V2 : BACKUP_FILE_V1);
            headerbuf.Append(compressing ? "\n1\n" : "\n0\n");

            Stream output = null;
            try
            {
                Stream input = getInputStream(tarFilename);
                Stream ofstream = getOutputStream(backupFilename);
                Stream finalOutput = ofstream;
                // Set up the encryption stage if appropriate, and emit the correct
                // header
                if (encrypting)
                {
                    finalOutput = emitAesBackupHeader(headerbuf, finalOutput,
                            password, isKitKat);
                }
                else
                {
                    headerbuf.Append("none\n");
                }

                byte[] header = System.Text.Encoding.UTF8.GetBytes(headerbuf.ToString()); //.GetBytes("UTF-8");
                ofstream.Write(header, 0, header.Length);
                //  Set up the compression stage feeding into the encryption stage
                //  (if any)
                if (compressing)
                {

                    //   Deflate deflater = new Deflate(Deflater.BEST_COMPRESSION);
                    //  requires Java 7
                    finalOutput = new ZOutputStream(finalOutput, JZlib.Z_BEST_COMPRESSION);
                }

                output = finalOutput;
                byte[] buff = new byte[(10 * 1024)];
                int read = -1;
                int totalRead = 0;
                while ((read = input.Read(buff, 0, buff.Length)) > 0)
                {
                    output.Write(buff, 0, read);
                    totalRead = (totalRead + read);
                    if ((DEBUG
                         && ((totalRead % (100 * 1024))
                             == 0)))
                    {
                        Console.Error.WriteLine("{0} bytes written\n", totalRead);
                    }

                }

                Console.Error.WriteLine("{0} bytes written to {1}.\n", totalRead, backupFilename);
            }
            catch (Exception e)
            {
                throw;
            }
            finally
            {
                if (output != null)
                {
                    try
                    {
                        output.Flush();
                        output.Close();
                    }
                    catch (IOException e)
                    {
                    }
                }
            }

        }

        private static Stream getInputStream(String filename)
        {
            if (filename.Equals("-"))
            {
                return Console.OpenStandardInput();
            }
            else
            {
                return new FileStream(filename, FileMode.Open);
            }

        }

        private static Stream getOutputStream(String filename)
        {
            if (filename.Equals("-"))
            {
                return Console.OpenStandardOutput();
            }
            else
            {
                return new FileStream(filename, FileMode.Create);
            }

        }

        private static byte[] randomBytes(int bits)
        {
            byte[] array = new byte[(bits / 8)];
            random.NextBytes(array);
            return array;
        }

        private static Stream emitAesBackupHeader(StringBuilder headerbuf, Stream ofstream,
            String encryptionPassword, bool useUtf8)
        {
            //  User key will be used to encrypt the master key.
            byte[] newUserSalt = AndroidBackup.randomBytes(PBKDF2_SALT_SIZE);
            byte[] userKey = AndroidBackup.buildPasswordKey(encryptionPassword, newUserSalt, PBKDF2_HASH_ROUNDS, useUtf8);
            //  the master key is random for each backup
            byte[] masterPw = new byte[(MASTER_KEY_SIZE / 8)];
            random.NextBytes(masterPw);
            byte[] checksumSalt = AndroidBackup.randomBytes(PBKDF2_SALT_SIZE);


            ////  primary encryption of the datastream with the random key
            //IBufferedCipher c = CipherUtilities.GetCipher("AES");
            //AesEngine aes = new AesEngine();

            //var spec1 = ParameterUtilities.CreateKeyParameter("AES256", masterPw);
            ////var parameters1 = new ParametersWithIV(spec1, new byte[128]); // Block size  == IV size == 16 in BouncyCastle for AES
            //c.Init(true, spec1);

            AesEngine engine = new AesEngine();
            CbcBlockCipher blockCipher = new CbcBlockCipher(engine); //CBC

            PaddedBufferedBlockCipher cipher = new PaddedBufferedBlockCipher(blockCipher); //Default scheme is PKCS5/PKCS7

            KeyParameter keyParam = new KeyParameter(masterPw);
            ParametersWithIV keyParamWithIV = new ParametersWithIV(keyParam, AndroidBackup.randomBytes(blockCipher.GetBlockSize() * 8), 0, blockCipher.GetBlockSize());
            // Encrypt
            cipher.Init(true, keyParamWithIV);

            Stream finalOutput = new CipherStream(ofstream, null, cipher);
            //  line 4: name of encryption algorithm
            headerbuf.Append(ENCRYPTION_ALGORITHM_NAME);
            headerbuf.Append('\n');
            //  line 5: user password salt [hex]
            headerbuf.Append(AndroidBackup.toHex(newUserSalt));
            headerbuf.Append('\n');
            //  line 6: master key checksum salt [hex]
            headerbuf.Append(AndroidBackup.toHex(checksumSalt));
            headerbuf.Append('\n');
            //  line 7: number of PBKDF2 rounds used [decimal]
            headerbuf.Append(PBKDF2_HASH_ROUNDS);
            headerbuf.Append('\n');
            //  line 8: IV of the user key [hex]
            //IBufferedCipher mkC = CipherUtilities.GetCipher(ENCRYPTION_MECHANISM);
            //Cipher mkC = Cipher.getInstance(ENCRYPTION_MECHANISM);
            //mkC.init(Cipher.ENCRYPT_MODE, userKey);


            AesEngine engine2 = new AesEngine();
            CbcBlockCipher blockCipher2 = new CbcBlockCipher(engine2); //CBC
            PaddedBufferedBlockCipher mkC = new PaddedBufferedBlockCipher(blockCipher2); //Default scheme is PKCS5/PKCS7
            KeyParameter keyParam2 = new KeyParameter(userKey);
            ParametersWithIV keyParamWithIV2 = new ParametersWithIV(keyParam2, AndroidBackup.randomBytes(blockCipher.GetBlockSize() * 8), 0, blockCipher2.GetBlockSize());
            // Encrypt
            mkC.Init(true, keyParamWithIV2);


            byte[] IV = keyParamWithIV2.GetIV();



            headerbuf.Append(AndroidBackup.toHex(IV));
            headerbuf.Append('\n');
            //  line 9: master IV + key blob, encrypted by the user key [hex]. Blob
            //  format:
            //  [byte] IV Length = Niv
            //  [array of Niv bytes] IV itself
            //  [byte] master key Length = Nmk
            //  [array of Nmk bytes] master key itself
            //  [byte] MK checksum hash Length = Nck
            //  [array of Nck bytes] master key checksum hash
            // 
            //  The checksum is the (master key + checksum salt), run through the
            //  stated number of PBKDF2 rounds
            IV = keyParamWithIV.GetIV();
            byte[] mk = keyParam.GetKey();
            byte[] checksum = AndroidBackup.makeKeyChecksum(mk, checksumSalt, PBKDF2_HASH_ROUNDS,
                useUtf8);



            MemoryStream mkOut = new MemoryStream(IV.Length + (mk.Length + (checksum.Length + 3)));
            //DataOutputStream mkOut = new DataOutputStream(blob);

            mkOut.WriteByte((byte)IV.Length);
            mkOut.Write(IV, 0, IV.Length);
            mkOut.WriteByte((byte)mk.Length);
            mkOut.Write(mk, 0, mk.Length);
            mkOut.WriteByte((byte)checksum.Length);
            mkOut.Write(checksum, 0, checksum.Length);
            mkOut.Flush();
            byte[] encryptedMk = mkC.DoFinal(mkOut.GetBuffer());
            headerbuf.Append(AndroidBackup.toHex(encryptedMk));
            headerbuf.Append('\n');
            return finalOutput;
        }

        public static String toHex(byte[] bytes)
        {
            StringBuilder buff = new StringBuilder();
            foreach (byte b in bytes)
            {
                buff.Append(String.Format("{0:X02}", b));
            }

            return buff.ToString();
        }

        private static String readHeaderLine(Stream inp)
        {
            int c;
            StringBuilder buffer = new StringBuilder(80);
            byte[] inbyte = new byte[1];
            while ((inp.Read(inbyte, 0, 1)) >= 0)
            {
                if (inbyte[0] == '\n')
                {
                    break;
                }

                //  consume and discard the newlines
                buffer.Append(((char)inbyte[0]));
            }

            return buffer.ToString();
        }

        public static byte[] hexToByteArray(string hex)
        {
            return Enumerable.Range(0, hex.Length)
                             .Where(x => x % 2 == 0)
                             .Select(x => Convert.ToByte(hex.Substring(x, 2), 16))
                             .ToArray();
        }

        public static byte[] makeKeyChecksum(byte[] pwBytes, byte[] salt, int rounds, bool useUtf8)
        {
            if (DEBUG)
            {
                Console.WriteLine(("key bytes: " + AndroidBackup.toHex(pwBytes)));
                Console.WriteLine(("salt bytes: " + AndroidBackup.toHex(salt)));
            }

            // From https://github.com/lclevy/ab_decrypt

            /***
                   because of byte to Java char before using password data as PBKDF2 key, special handling is required
                   from: https://android.googlesource.com/platform/frameworks/base/+/master/services/backup/java/com/android/server/backup/BackupManagerService.java  
                   private byte[] makeKeyChecksum(byte[] pwBytes, byte[] salt, int rounds)
                       {
                           char[] mkAsChar = new char[pwBytes.length];
                           for (int i = 0; i < pwBytes.length; i++)
                           {
                               mkAsChar[i] = (char)pwBytes[i];               <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<< HERE
                           }
                           Key checksum = buildCharArrayKey(mkAsChar, salt, rounds);
                           return checksum.getEncoded();
                       }

                       Java byte to char conversion(as "Widening and Narrowing Primitive Conversion") is defined here:
                       https://docs.oracle.com/javase/specs/jls/se8/html/jls-5.html#jls-5.1.4
                       First, the byte is converted to an int via widening primitive conversion(chapter 5.1.2), 
                       and then the resulting int is converted to a char by narrowing primitive conversion(chapter 5.1.3)
            ***/

            // Widening Primitive Conversion : https://docs.oracle.com/javase/specs/jls/se8/html/jls-5.html#jls-5.1.2
            sbyte[] mkAsSigned = new sbyte[pwBytes.Length];  //sign extension
            for (int i = 0; (i < pwBytes.Length); i++)
            {
                mkAsSigned[i] = ((sbyte)(pwBytes[i]));
            }

            // Narrowing Primitive Conversion : https://docs.oracle.com/javase/specs/jls/se8/html/jls-5.html#jls-5.1.3
            ushort[] unSigned16Bits = new ushort[mkAsSigned.Length];
            for (int i = 0; (i < mkAsSigned.Length); i++)
            {
                unSigned16Bits[i] = (ushort)((mkAsSigned[i]) & 0xffff);
            }

            /***
            The Java programming language represents text in sequences of 16 - bit code UNITS, using the UTF-16 encoding.
            https://docs.oracle.com/javase/specs/jls/se8/html/jls-3.html#jls-3.1
            ***/
            var byteArray = unSigned16Bits.SelectMany(x => BitConverter.GetBytes(x)).ToArray();


            /***
            https://developer.android.com/reference/javax/crypto/spec/PBEKeySpec.html
            \"Different PBE mechanisms may consume different bits of each password character. 
            For example, the PBE mechanism defined in PKCS #5 looks at only the low order 8 bits of each character, 
            whereas PKCS #12 looks at all 16 bits of each character. \"  
            ***/
            var curr = Encoding.Convert(Encoding.Unicode, Encoding.UTF8, byteArray);

            // COnverting to char array
            char[] mkAsChar = new char[curr.Length];
            for (int i = 0; (i < curr.Length); i++)
            {
                mkAsChar[i] = ((char)(curr[i]));
            }


            if (DEBUG)
            {
                Console.WriteLine(String.Format("MK as string: {0}\n", new String(mkAsChar)));
            }

            byte[] checksum = AndroidBackup.buildCharArrayKey(mkAsChar, salt, rounds, useUtf8);

            if (DEBUG)
            {
                Console.WriteLine(("Key format: " + toHex(checksum)));
            }

            return checksum;
        }

        public static byte[] buildCharArrayKey(char[] pwArray, byte[] salt, int rounds, bool useUtf8)
        {
            //  Original code from BackupManagerService
            //  this produces different results when run with Sun/Oracale Java SE
            //  which apparently treats password bytes as UTF-8 (16?)
            //  (the encoding is left unspecified in PKCS#5)
            //  try {
            //  byte[]Factory keyFactory = byte[]Factory
            //  .getInstance("PBKDF2WithHmacSHA1");
            //  KeySpec ks = new PBEKeySpec(pwArray, salt, rounds, PBKDF2_KEY_SIZE);
            //  return keyFactory.generateSecret(ks);
            //  } catch (InvalidKeySpecException e) {
            //  throw new RuntimeException(e);
            //  } catch (NoSuchAlgorithmException e) {
            //  throw new RuntimeException(e);
            //  } catch (NoSuchProviderException e) {
            //  throw new RuntimeException(e);
            //  }
            //  return null;
            return AndroidBackup.androidPBKDF2(pwArray, salt, rounds, useUtf8);
        }

        public static byte[] androidPBKDF2(char[] pwArray, byte[] salt, int rounds, bool useUtf8)
        {
            PbeParametersGenerator generator = new Pkcs5S2ParametersGenerator();
            //  Android treats password bytes as ASCII, which is obviously
            //  not the case when an AES key is used as a 'password'.
            //  Use the same method for compatibility.
            //  Android 4.4 however uses all char bytes
            //  useUtf8 needs to be true for KitKat
            byte[] pwBytes = useUtf8 ? PbeParametersGenerator.Pkcs5PasswordToUtf8Bytes(pwArray)
                : PbeParametersGenerator.Pkcs5PasswordToBytes(pwArray);
            generator.Init(pwBytes, salt, rounds);

            KeyParameter param = (KeyParameter)generator.GenerateDerivedParameters("AES256", PBKDF2_KEY_SIZE);

            return param.GetKey();
            //return new byte[])(params.getKey(), "AES");
        }

        private static byte[] buildPasswordKey(String pw, byte[] salt, int rounds, bool useUtf8)
        {
            return AndroidBackup.buildCharArrayKey(pw.ToCharArray(), salt, rounds, useUtf8);
        }

        public static string ReadPassword(char mask)
        {
            const int ENTER = 13, BACKSP = 8, CTRLBACKSP = 127;
            int[] FILTERED = { 0, 27, 9, 10 /*, 32 space, if you care */ }; // const

            var pass = new Stack<char>();
            char chr = (char)0;

            while ((chr = System.Console.ReadKey(true).KeyChar) != ENTER)
            {
                if (chr == BACKSP)
                {
                    if (pass.Count > 0)
                    {
                        System.Console.Write("\b \b");
                        pass.Pop();
                    }
                }
                else if (chr == CTRLBACKSP)
                {
                    while (pass.Count > 0)
                    {
                        System.Console.Write("\b \b");
                        pass.Pop();
                    }
                }
                else if (FILTERED.Count(x => chr == x) > 0) { }
                else
                {
                    pass.Push((char)chr);
                    System.Console.Write(mask);
                }
            }

            System.Console.WriteLine();

            return new string(pass.Reverse().ToArray());
        }
    }
}