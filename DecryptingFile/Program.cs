using DidiSoft.Pgp;
using Org.BouncyCastle.Bcpg.OpenPgp;
using Org.BouncyCastle.Utilities.IO;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace DecryptingFile
{
    public class Program
    {
        public static void Main(string[] args)
        {
            //DecryptFile(
            //    @"C:\Users\kumar.pradhan\OneDrive - EY\Documents\Projects\Novartis\Output\KPMG_CIT_20210728163208.csv.pgp",
            //    @"C:\Users\kumar.pradhan\OneDrive - EY\Documents\Projects\Novartis\EY NVS-Private.asc",
            //    "".ToCharArray(),
            //    @"C:\Users\kumar.pradhan\OneDrive - EY\Documents\Projects\Novartis\Output\"
            //);
            

















            string inputFileName = @"C:\Users\kumar.pradhan\OneDrive - EY\Documents\Projects\Novartis\Output\test2.xlsx.pgp";
            string keyFileName = @"C:\Users\kumar.pradhan\OneDrive - EY\Documents\Projects\Novartis\EY NVS-Private.asc";
            char[] passwd = "".ToCharArray();
            string defaultFileName = @"C:\Users\kumar.pradhan\OneDrive - EY\Documents\Projects\Novartis\Output\";
            using (Stream inputStream = File.OpenRead(inputFileName),
                               keyIn = File.OpenRead(keyFileName))
            {
                Stream input = PgpUtilities.GetDecoderStream(inputStream);
                try
                {
                    PgpObjectFactory pgpObjF = new PgpObjectFactory(input);
                    PgpEncryptedDataList enc;
                    PgpObject obj = pgpObjF.NextPgpObject();
                    if (obj is PgpEncryptedDataList)
                    {
                        enc = (PgpEncryptedDataList)obj;
                    }
                    else
                    {
                        enc = (PgpEncryptedDataList)pgpObjF.NextPgpObject();
                    }
                    //var akp = new AsymmetricKeyParameter(true);

                    PgpPrivateKey privKey = null;
                    //Stream keyIn = File.OpenRead(privateKeyPath);
                    PgpSecretKeyRingBundle pgpSec = new PgpSecretKeyRingBundle(
                        PgpUtilities.GetDecoderStream(keyIn));
                    //PgpPublicKeyEncryptedData pbe = null;
                    foreach (PgpPublicKeyEncryptedData pked in enc.GetEncryptedDataObjects())
                    {
                        PgpSecretKey pgpSecKey = pgpSec.GetSecretKey(pked.KeyId);
                        if (pgpSecKey == null)
                        {
                            privKey = null;
                        }
                        else
                        {
                            privKey = pgpSecKey.ExtractPrivateKey(passwd);
                        }
                        if (privKey != null)
                        {
                            //pbe = pked;
                            break;
                        }
                    }
                    if (privKey == null)
                    {
                        throw new ArgumentException("secret key for message not found.");
                    }
                    PgpPublicKeyEncryptedData pbe = enc.GetEncryptedDataObjects().Cast<PgpPublicKeyEncryptedData>().First();
                    Stream clear;
                    clear = pbe.GetDataStream(privKey);
                    PgpObjectFactory plainFact = new PgpObjectFactory(clear);
                    PgpObject message = plainFact.NextPgpObject();
                    if (message is PgpCompressedData)
                    {
                        PgpCompressedData cData = (PgpCompressedData)message;
                        Stream compDataIn = cData.GetDataStream();
                        PgpObjectFactory o = new PgpObjectFactory(compDataIn);
                        message = o.NextPgpObject();
                        if (message is PgpOnePassSignatureList)
                        {
                            message = o.NextPgpObject();
                            PgpLiteralData Ld = null;
                            Ld = (PgpLiteralData)message;
                            Stream output = File.Create(defaultFileName + "\\" + Ld.FileName);
                            Stream unc = Ld.GetInputStream();
                            Streams.PipeAll(unc, output);
                        }
                        else
                        {
                            PgpLiteralData Ld = null;
                            Ld = (PgpLiteralData)message;
                            //Stream output = File.Create(outputpath + "\\" + Ld.FileName);
                            Stream output = File.Create(defaultFileName);
                            Stream unc = Ld.GetInputStream();
                            Streams.PipeAll(unc, output);
                        }
                    }
                }
                catch (Exception e)
                {
                    throw new Exception(e.Message);
                }
            }





            //Demo();
            //string inputFileName = @"C:\Users\kumar.pradhan\OneDrive - EY\Documents\Projects\Novartis\Output\KPMG_CIT_20210728163208.csv.pgp";
            //string keyFileName = @"C:\Users\kumar.pradhan\OneDrive - EY\Documents\Projects\Novartis\EY NVS-Private.asc";
            //char[] passwd = "".ToCharArray();
            //string defaultFileName = @"C:\Users\kumar.pradhan\OneDrive - EY\Documents\Projects\Novartis\Output\Output1234.csv";
            //using (Stream inputStream = File.OpenRead(inputFileName),
            //                   keyIn = File.OpenRead(keyFileName))
            //{
            //    Stream input = PgpUtilities.GetDecoderStream(inputStream);

            //    PgpObjectFactory pgpF = new PgpObjectFactory(input);
            //    PgpEncryptedDataList enc;

            //    PgpObject o = pgpF.NextPgpObject();
            //    //
            //    // the first object might be a PGP marker packet.
            //    //
            //    if (o is PgpEncryptedDataList)
            //    {
            //        enc = (PgpEncryptedDataList)o;
            //    }
            //    else
            //    {
            //        enc = (PgpEncryptedDataList)pgpF.NextPgpObject();
            //    }

            //    //
            //    // find the secret key
            //    //
            //    PgpPrivateKey sKey = null;
            //    PgpPublicKeyEncryptedData pbe = null;
            //    PgpSecretKeyRingBundle pgpSec = new PgpSecretKeyRingBundle(
            //        PgpUtilities.GetDecoderStream(keyIn));

            //    foreach (PgpPublicKeyEncryptedData pked in enc.GetEncryptedDataObjects())
            //    {
            //        if (pked.KeyId > 0)
            //        {
            //            PgpSecretKey pgpSecKey = pgpSec.GetSecretKey(pked.KeyId);

            //            if (pgpSecKey == null)
            //            {
            //                sKey = null;
            //            }
            //            else
            //                sKey = pgpSecKey.ExtractPrivateKey(passwd);

            //            if (sKey != null)
            //            {
            //                pbe = pked;
            //                break;
            //            }
            //        }
            //    }

            //    if (sKey == null)
            //    {
            //        throw new ArgumentException("secret key for message not found.");
            //    }

            //    Stream clear = pbe.GetDataStream(sKey);

            //    PgpObjectFactory plainFact = new PgpObjectFactory(clear);

            //    PgpObject message = plainFact.NextPgpObject();

            //    if (message is PgpCompressedData)
            //    {
            //        PgpCompressedData cData = (PgpCompressedData)message;
            //        PgpObjectFactory pgpFact = new PgpObjectFactory(cData.GetDataStream());

            //        message = pgpFact.NextPgpObject();
            //    }

            //    if (message is PgpLiteralData)
            //    {
            //        PgpLiteralData ld = (PgpLiteralData)message;

            //        string outFileName = ld.FileName;
            //        outFileName = defaultFileName;


            //        Stream fOut = File.Create(outFileName);
            //        Stream unc = ld.GetInputStream();
            //        Streams.PipeAll(unc, fOut);
            //        fOut.Close();
            //    }
            //    else if (message is PgpOnePassSignatureList)
            //    {
            //        throw new PgpException("encrypted message contains a signed message - not literal data.");
            //    }
            //    else
            //    {
            //        throw new PgpException("message is not a simple encrypted file - type unknown.");
            //    }

            //    if (pbe.IsIntegrityProtected())
            //    {
            //        if (!pbe.Verify())
            //        {
            //            Console.Error.WriteLine("message failed integrity check");
            //        }
            //        else
            //        {
            //            Console.Error.WriteLine("message integrity check passed");
            //        }
            //    }
            //    else
            //    {
            //        Console.Error.WriteLine("no message integrity check");
            //    }
            //}








            //Demo();

        }
        public static void Demo()
        {
            // initialize the library
            PGPLib pgp = new PGPLib();

            //    @"C:\Users\kumar.pradhan\OneDrive - EY\Documents\Projects\Novartis\EY NVS-Private.asc",
            //    "".ToCharArray(),
            //    @"C:\Users\kumar.pradhan\OneDrive - EY\Documents\Projects\Novartis\Output\Output12.csv"
            string inputFileLocation = @"C:\Users\kumar.pradhan\OneDrive - EY\Documents\Projects\Novartis\Output\KPMG_CIT_20210728163208.csv.pgp";
            string privateKeyLocation = @"C:\Users\kumar.pradhan\OneDrive - EY\Documents\Projects\Novartis\EY NVS-Private.asc";
            string privateKeyPassword = "";
            string outputFile = @"C:\Users\kumar.pradhan\OneDrive - EY\Documents\Projects\Novartis\Output\Output.csv";

            // decrypt and obtain the original file name
            // of the decrypted file
            string originalFileName =
                        pgp.DecryptFile(inputFileLocation,
                                    privateKeyLocation,
                                    privateKeyPassword,
                                    outputFile);
            Console.ReadLine();
        }
        private static void DecryptFile(
    string inputFileName,
    string keyFileName,
    char[] passwd,
    string defaultFileName)
        {
            using (Stream input = File.OpenRead(inputFileName),
                   keyIn = File.OpenRead(keyFileName))
            {
                //DecryptFile(input, keyIn, passwd, defaultFileName);
                Decrypt(input, defaultFileName, keyFileName);
            }
        }

        private static void DecryptFile(
            Stream inputStream,
            Stream keyIn,
            char[] passwd,
            string defaultFileName)
        {
            inputStream = PgpUtilities.GetDecoderStream(inputStream);

            try
            {
                PgpObjectFactory pgpF = new PgpObjectFactory(inputStream);
                PgpEncryptedDataList enc;

                PgpObject o = pgpF.NextPgpObject();
                //
                // the first object might be a PGP marker packet.
                //
                if (o is PgpEncryptedDataList)
                {
                    enc = (PgpEncryptedDataList)o;
                }
                else
                {
                    enc = (PgpEncryptedDataList)pgpF.NextPgpObject();
                }

                //
                // find the secret key
                //
                PgpPrivateKey sKey = null;
                PgpPublicKeyEncryptedData pbe = null;
                PgpSecretKeyRingBundle pgpSec = new PgpSecretKeyRingBundle(
                    PgpUtilities.GetDecoderStream(keyIn));

                foreach (PgpPublicKeyEncryptedData pked in enc.GetEncryptedDataObjects())
                {
                    sKey = FindSecretKey(pgpSec, pked.KeyId, passwd);

                    if (sKey != null)
                    {
                        pbe = pked;
                        break;
                    }
                }

                if (sKey == null)
                {
                    throw new ArgumentException("secret key for message not found.");
                }

                Stream clear = pbe.GetDataStream(sKey);

                PgpObjectFactory plainFact = new PgpObjectFactory(clear);

                PgpObject message = plainFact.NextPgpObject();

                if (message is PgpCompressedData)
                {
                    PgpCompressedData cData = (PgpCompressedData)message;
                    PgpObjectFactory pgpFact = new PgpObjectFactory(cData.GetDataStream());

                    message = pgpFact.NextPgpObject();
                }

                if (message is PgpLiteralData)
                {
                    PgpLiteralData ld = (PgpLiteralData)message;

                    string outFileName = ld.FileName;
                    outFileName = defaultFileName;

                    Stream fOut = File.Create(outFileName);
                    Stream unc = ld.GetInputStream();
                    Streams.PipeAll(unc, fOut);
                    fOut.Close();
                }
                else if (message is PgpOnePassSignatureList)
                {
                    //Stream encodedFile = PgpUtilities.GetDecoderStream(inputStream);
                    //PgpObjectFactory factory = new PgpObjectFactory(encodedFile);
                    //PgpObject pgpObject = factory.NextPgpObject();

                    //PgpEncryptedDataList encryptedDataList;

                    //if (pgpObject is PgpEncryptedDataList)
                    //{
                    //    encryptedDataList = (PgpEncryptedDataList)pgpObject;
                    //}
                    //else
                    //{
                    //    encryptedDataList = (PgpEncryptedDataList)factory.NextPgpObject();
                    //}
                    //PgpPublicKeyEncryptedData publicKeyED = null;
                    //foreach (PgpPublicKeyEncryptedData privateKeyED in encryptedDataList.GetEncryptedDataObjects())
                    //{
                    //    if (privateKeyED != null)
                    //    {
                    //        publicKeyED = privateKeyED;
                    //        break;
                    //    }
                    //}
                    ////if (encryptionKeys == null)
                    ////{
                    ////    throw new ArgumentNullException("encryptionKeys", "encryptionKeys is null.");
                    ////}

                    ////mEncryptionKeys = encryptionKeys;
                    //Stream clearStream = publicKeyED.GetDataStream(sKey);
                    //PgpObjectFactory clearFactory = new PgpObjectFactory(clearStream);
                    //PgpObject messages = clearFactory.NextPgpObject();
                    //PgpCompressedData compressedData = (PgpCompressedData)messages;
                    //Stream compressedDataStream = compressedData.GetDataStream();
                    //PgpObjectFactory compressedFactory = new PgpObjectFactory(compressedDataStream);
                    //message = checkforOnePassSignatureList(message, compressedFactory);
                    //PgpLiteralData ld = (PgpLiteralData)messages;

                    //string outFileName = ld.FileName;
                    //PgpLiteralData literalData = (PgpLiteralData)messages;
                    //using (Stream outputFile = File.Create(outFileName))
                    //{
                    //    using (Stream literalDataStream = literalData.GetInputStream())
                    //    {
                    //        Streams.PipeAll(literalDataStream, outputFile);
                    //    }
                    //}
                    throw new PgpException("encrypted message contains a signed message - not literal data.");
                }
                else
                {
                    throw new PgpException("message is not a simple encrypted file - type unknown.");
                }

                if (pbe.IsIntegrityProtected())
                {
                    if (!pbe.Verify())
                    {
                        Console.Error.WriteLine("message failed integrity check");
                    }
                    else
                    {
                        Console.Error.WriteLine("message integrity check passed");
                    }
                }
                else
                {
                    Console.Error.WriteLine("no message integrity check");
                }
            }
            catch (PgpException e)
            {
                Console.Error.WriteLine(e);

                Exception underlyingException = e.InnerException;
                if (underlyingException != null)
                {
                    Console.Error.WriteLine(underlyingException.Message);
                    Console.Error.WriteLine(underlyingException.StackTrace);
                }
            }
        }

        private static PgpPrivateKey FindSecretKey(PgpSecretKeyRingBundle pgpSec, long keyID, char[] pass)
        {
            PgpSecretKey pgpSecKey = pgpSec.GetSecretKey(keyID);

            if (pgpSecKey == null)
            {
                return null;
            }

            return pgpSecKey.ExtractPrivateKey(pass);
        }
        private static PgpObject checkforOnePassSignatureList(PgpObject message, PgpObjectFactory compressedFactory)
        {
            message = compressedFactory.NextPgpObject();
            if (message is PgpOnePassSignatureList)
            {
                message = compressedFactory.NextPgpObject();
            }
            return message;
        }
        private static PgpPrivateKey GetPrivateKey(string privateKeyPath)
        {
            using (Stream keyIn = File.OpenRead(privateKeyPath))
            using (Stream inputStream = PgpUtilities.GetDecoderStream(keyIn))
            {
                PgpSecretKeyRingBundle secretKeyRingBundle = new PgpSecretKeyRingBundle(inputStream);

                PgpSecretKey key = null;
                foreach (PgpSecretKeyRing kRing in secretKeyRingBundle.GetKeyRings())
                {
                    foreach (PgpSecretKey secretKey in kRing.GetSecretKeys())
                    {
                        PgpPrivateKey privKey = secretKey.ExtractPrivateKey("".ToCharArray());

                        if (privKey.Key.GetType() ==
                            typeof(Org.BouncyCastle.Crypto.Parameters.ElGamalPrivateKeyParameters))
                        //Org.BouncyCastle.Crypto.Parameters.ElGamalPrivateKeyParameters
                        {
                            return privKey;
                        }
                    }

                }
            }

            return null;
        }





        public static void Decrypt(Stream input, string outputpath, String privateKeyPath)
        {
            input = PgpUtilities.GetDecoderStream(input);
            try
            {
                PgpObjectFactory pgpObjF = new PgpObjectFactory(input);
                PgpEncryptedDataList enc;
                PgpObject obj = pgpObjF.NextPgpObject();
                if (obj is PgpEncryptedDataList)
                {
                    enc = (PgpEncryptedDataList)obj;
                }
                else
                {
                    enc = (PgpEncryptedDataList)pgpObjF.NextPgpObject();
                }

                //var akp = new AsymmetricKeyParameter(true);



                PgpPrivateKey privKey = null;
                Stream keyIn = File.OpenRead(privateKeyPath);
                PgpSecretKeyRingBundle pgpSec = new PgpSecretKeyRingBundle(
                    PgpUtilities.GetDecoderStream(keyIn));
                //PgpPublicKeyEncryptedData pbe = null;
                foreach (PgpPublicKeyEncryptedData pked in enc.GetEncryptedDataObjects())
                {
                    privKey = FindSecretKey(pgpSec, pked.KeyId, "".ToCharArray());

                    if (privKey != null)
                    {
                        //pbe = pked;
                        break;
                    }
                }

                if (privKey == null)
                {
                    throw new ArgumentException("secret key for message not found.");
                }
                PgpPublicKeyEncryptedData pbe = enc.GetEncryptedDataObjects().Cast<PgpPublicKeyEncryptedData>().First();
                Stream clear;
                clear = pbe.GetDataStream(privKey);
                PgpObjectFactory plainFact = new PgpObjectFactory(clear);
                PgpObject message = plainFact.NextPgpObject();
                if (message is PgpCompressedData)
                {
                    PgpCompressedData cData = (PgpCompressedData)message;
                    Stream compDataIn = cData.GetDataStream();
                    PgpObjectFactory o = new PgpObjectFactory(compDataIn);
                    message = o.NextPgpObject();
                    if (message is PgpOnePassSignatureList)
                    {
                        message = o.NextPgpObject();
                        PgpLiteralData Ld = null;
                        Ld = (PgpLiteralData)message;
                        Stream output = File.Create(outputpath + "\\" + Ld.FileName);
                        Stream unc = Ld.GetInputStream();
                        Streams.PipeAll(unc, output);
                    }
                    else
                    {
                        PgpLiteralData Ld = null;
                        Ld = (PgpLiteralData)message;
                        //Stream output = File.Create(outputpath + "\\" + Ld.FileName);
                        Stream output = File.Create(outputpath);
                        Stream unc = Ld.GetInputStream();
                        Streams.PipeAll(unc, output);
                    }
                }
            }
            catch (Exception e)
            {
                throw new Exception(e.Message);
            }
        }

    }
}
