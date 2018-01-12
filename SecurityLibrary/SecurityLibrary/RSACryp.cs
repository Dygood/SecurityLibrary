using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace Miraclesoft.SecurityLibrary
{
    /**
     * ############################################################################## 
     * RSA 方式加密及RSA验证
     * 说明KEY必须是XML的行式,返回的是字符串
     * 有一点需要说明！！该加密方式有 长度 限制的！！ 
     * ############################################################################## 
     */
    /**
     * .Net Framework中提供的RSA算法规定,每次加密的字节数,不能超过密钥的长度值减去11,
     * 每次加密得到的密文长度,刚好是密钥的长度.所以,如果要加密较长的数据,可以采用数据截取的方法,分段加密.
     * 解密时肯定也要使用分段解密
     */
    /// <summary>
    /// RSA加密解密及RSA签名和验证
    /// 使用加密服务提供程序 (CSP) 提供的 System.Security.Cryptography.RSA 算法的实现执行非对称加密和解密
    /// </summary>
    public class RSACryp
    {
        #region RSA 的密钥产生 

        /// <summary>
        /// RSA 的密钥产生 产生私钥和公钥
        /// </summary>
        /// <param name="XmlPrivateKey">当前RSA对象的密匙XML字符串(包括专用参数)--私钥</param>
        /// <param name="XmlPublicKey">当前RSA对象的密匙XML字符串(不包括专用参数)--公钥</param>
        public static void RSAKey(out string XmlPrivateKey, out string XmlPublicKey)
        {
            var rsa = new RSACryptoServiceProvider();
            XmlPrivateKey = rsa.ToXmlString(true);
            XmlPublicKey = rsa.ToXmlString(false);
        }

        #endregion

        #region RSA的加密函数 

        /// <summary>
        /// 使用RSA的加密String(该方法存在长度限制)
        /// </summary>
        /// <param name="XmlPublicKey">当前RSA对象的密匙XML字符串(不包括专用参数)--公钥</param>
        /// <param name="Plaintext">需要进行加密的字符串</param>
        /// <returns>加密后的字符串</returns>
        public static string RSAEncrypt(string XmlPublicKey, string Plaintext) =>
            Convert.ToBase64String(RSAEncrypt(XmlPublicKey, new UnicodeEncoding().GetBytes(Plaintext)));

        /// <summary>
        /// 使用RSA的加密byte[](该方法存在长度限制)
        /// </summary>
        /// <param name="XmlPublicKey">当前RSA对象的密匙XML字符串(不包括专用参数)--公钥</param>
        /// <param name="Plaintext">需要进行加密的字节数组</param>
        /// <returns>加密后的字节数组</returns>
        public static byte[] RSAEncrypt(string XmlPublicKey, byte[] Plaintext)
        {
            var rsa = new RSACryptoServiceProvider();
            rsa.FromXmlString(XmlPublicKey);
            return rsa.Encrypt(Plaintext, false);
        }

        #endregion

        #region RSA的解密函数 

        /// <summary>
        /// RSA解密String(该方法存在长度限制)
        /// </summary>
        /// <param name="XmlPrivateKey">当前RSA对象的密匙XML字符串(包括专用参数)--私钥</param>
        /// <param name="Ciphertext">需要进行解密的字符串</param>
        /// <returns>解密后的字符串</returns>
        public static string RSADecrypt(string XmlPrivateKey, string Ciphertext) =>
            new UnicodeEncoding().GetString(RSADecrypt(XmlPrivateKey, Convert.FromBase64String(Ciphertext)));

        /// <summary>
        /// RSA解密byte[](该方法存在长度限制)
        /// </summary>
        /// <param name="XmlPrivateKey">当前RSA对象的密匙XML字符串(包括专用参数)--私钥</param>
        /// <param name="Ciphertext">需要进行解密的字节数组</param>
        /// <returns>解密后的字节数组</returns>
        public static byte[] RSADecrypt(string XmlPrivateKey, byte[] Ciphertext)
        {
            var rsa = new RSACryptoServiceProvider();
            rsa.FromXmlString(XmlPrivateKey);
            return rsa.Decrypt(Ciphertext, false);
        }

        #endregion

        #region 获取Hash描述表 

        /// <summary>
        /// 从字符串中取得Hash描述字节数组
        /// </summary>
        /// <param name="source">源字符串</param>
        /// <exception cref="ArgumentException"></exception>
        /// <returns>Hash字节数组</returns>
        public static byte[] GetHashByte(string source)
        {
            if (string.IsNullOrEmpty(source))
                throw new ArgumentException("源字符串不能为空", nameof(source));
            return HashAlgorithm.Create("MD5").ComputeHash(Encoding.GetEncoding("GB2312").GetBytes(source));
        }

        /// <summary>
        /// 从字符串中取得Hash描述字符串
        /// </summary>
        /// <param name="source">源字符串</param>
        /// <returns>Hash字符串</returns>
        public static string GetHashString(string source) => Convert.ToBase64String(GetHashByte(source));

        /// <summary>
        /// 从文件中取得Hash描述字节数组
        /// </summary>
        /// <param name="objFile">文件流</param>
        /// <exception cref="ArgumentNullException"></exception>
        /// <returns>Hash字节数组</returns>
        public static byte[] GetFileHashByte(FileStream objFile)
        {
            if (objFile == null)
                throw new ArgumentNullException(nameof(objFile));
            var arry = HashAlgorithm.Create("MD5").ComputeHash(objFile);
            objFile.Close();
            return arry;
        }

        /// <summary>
        /// 从文件中取得Hash描述字符串
        /// </summary>
        /// <param name="objFile"></param>
        /// <returns></returns>
        public static string GetFileHashString(FileStream objFile) =>
            Convert.ToBase64String(GetFileHashByte(objFile));

        #endregion

        #region RSA签名

        /// <summary>
        /// RSA签名
        /// </summary>
        /// <param name="XmlPrivateKey">当前RSA对象的密匙XML字符串(包括专用参数)--私钥</param>
        /// <param name="HashbyteSignature">需要签名的字节数组数据</param>
        /// <param name="EncryptedSignatureByte">签名后的字节数组数据</param>
        public static void SignatureFormatter(string XmlPrivateKey, byte[] HashbyteSignature, ref byte[] EncryptedSignatureByte)
        {
            var RSA = new RSACryptoServiceProvider();
            RSA.FromXmlString(XmlPrivateKey);
            var RSAFormatter = new RSAPKCS1SignatureFormatter(RSA);
            //设置签名的算法为MD5 
            RSAFormatter.SetHashAlgorithm("MD5");
            //执行签名 
            EncryptedSignatureByte = RSAFormatter.CreateSignature(HashbyteSignature);
        }

        /// <summary>
        /// RSA签名 
        /// </summary>
        /// <param name="XmlPrivateKey">当前RSA对象的密匙XML字符串(包括专用参数)--私钥</param>
        /// <param name="HashbyteSignature">需要签名的字节数组数据</param>
        /// <param name="EncryptedSignatureString">签名后字符串</param>
        public static void SignatureFormatter(string XmlPrivateKey, byte[] HashbyteSignature, ref string EncryptedSignatureString)
        {
            byte[] EncryptedSignatureData = null;
            SignatureFormatter(XmlPrivateKey, HashbyteSignature, ref EncryptedSignatureData);
            EncryptedSignatureString = Convert.ToBase64String(EncryptedSignatureData);
        }

        /// <summary>
        /// RSA签名
        /// </summary>
        /// <param name="XmlPrivateKey">当前RSA对象的密匙XML字符串(包括专用参数)--私钥</param>
        /// <param name="HashStringSignature">需要签名的字符串</param>
        /// <param name="EncryptedSignatureByte">签名后的字节数组数据</param>
        /// <returns></returns>
        public static void SignatureFormatter(string XmlPrivateKey, string HashStringSignature, ref byte[] EncryptedSignatureByte) =>
            SignatureFormatter(XmlPrivateKey, Convert.FromBase64String(HashStringSignature), ref EncryptedSignatureByte);

        /// <summary>
        /// RSA签名
        /// </summary>
        /// <param name="XmlPrivateKey">当前RSA对象的密匙XML字符串(包括专用参数)--私钥</param>
        /// <param name="HashStringSignature">需要签名的字符串</param>
        /// <param name="EncryptedSignatureString">签名后字符串</param>
        public static void SignatureFormatter(string XmlPrivateKey, string HashStringSignature, ref string EncryptedSignatureString) =>
            SignatureFormatter(XmlPrivateKey, Convert.FromBase64String(HashStringSignature), ref EncryptedSignatureString);

        #endregion

        #region RSA 签名验证 

        /// <summary>
        /// RSA 签名验证 
        /// </summary>
        /// <param name="XmlPublicKey">当前RSA对象的密匙XML字符串(不包括专用参数)--公钥</param>
        /// <param name="HashByteVerification">用RSA签名的字节数组数据</param>
        /// <param name="SignatureByte">要为该数据验证的签名字节数组</param>
        /// <returns> 如果 HashByteVerification 与使用指定的哈希算法和密钥在 SignatureByte 上计算出的签名匹配,则为 true;否则为 false.</returns>
        public static bool SignatureVerification(string XmlPublicKey, byte[] HashByteVerification, byte[] SignatureByte)
        {
            var RSA = new RSACryptoServiceProvider();
            RSA.FromXmlString(XmlPublicKey);
            var RSADeformatter = new RSAPKCS1SignatureDeformatter(RSA);
            //指定解密的时候HASH算法为MD5 
            RSADeformatter.SetHashAlgorithm("MD5");
            return RSADeformatter.VerifySignature(HashByteVerification, SignatureByte);
        }

        /// <summary>
        /// RSA 签名验证
        /// </summary>
        /// <param name="XmlPublicKey">当前RSA对象的密匙XML字符串(不包括专用参数)--公钥</param>
        /// <param name="HashStringVerification">用RSA签名的字符串数据</param>
        /// <param name="SignatureByte">要为该数据验证的签名字节数组</param>
        /// <returns>如果 HashStringVerification 与使用指定的哈希算法和密钥在 SignatureByte 上计算出的签名匹配,则为 true;否则为 false.</returns>
        public static bool SignatureVerification(string XmlPublicKey, string HashStringVerification, byte[] SignatureByte) =>
            SignatureVerification(XmlPublicKey, Convert.FromBase64String(HashStringVerification), SignatureByte);

        /// <summary>
        /// RSA 签名验证
        /// </summary>
        /// <param name="XmlPublicKey">当前RSA对象的密匙XML字符串(不包括专用参数)--公钥</param>
        /// <param name="HashByteVerification">用RSA签名的字节数组数据</param>
        /// <param name="SignatureString">要为该数据验证的签名字符串</param>
        /// <returns>如果 HashByteVerification 与使用指定的哈希算法和密钥在 SignatureString 上计算出的签名匹配,则为 true;否则为 false.</returns>
        public static bool SignatureVerification(string XmlPublicKey, byte[] HashByteVerification, string SignatureString) =>
            SignatureVerification(XmlPublicKey, HashByteVerification, Convert.FromBase64String(SignatureString));

        /// <summary>
        /// RSA 签名验证
        /// </summary>
        /// <param name="XmlPublicKey">当前RSA对象的密匙XML字符串(不包括专用参数)--公钥</param>
        /// <param name="HashStringVerification">用RSA签名的字符串数据</param>
        /// <param name="SignatureString">要为该数据验证的签名字符串</param>
        /// <returns>如果 HashStringVerification 与使用指定的哈希算法和密钥在 SignatureString 上计算出的签名匹配,则为 true;否则为 false.</returns>
        public static bool SignatureVerification(string XmlPublicKey, string HashStringVerification, string SignatureString) =>
            SignatureVerification(XmlPublicKey, HashStringVerification, Convert.FromBase64String(SignatureString));

        #endregion

        #region 不限长度

        /// <summary>
        /// RSA加密 不限长度的加密版本
        /// </summary>
        /// <param name="XmlPublicKey">公匙</param>
        /// <param name="Plaintext">需要进行加密的字符串</param>
        /// <param name="Ciphertext">加密后的字符串</param>
        public static void RSAEncrypt(string XmlPublicKey, string Plaintext, ref string Ciphertext)
        {
            if (string.IsNullOrEmpty(Plaintext))
                throw new Exception("加密字符串不能为空.");
            if (string.IsNullOrWhiteSpace(XmlPublicKey))
                throw new ArgumentException("错误的公匙");
            using (var rsaProvider = new RSACryptoServiceProvider())
            {
                var inputBytes = Convert.FromBase64String(Plaintext); //有含义的字符串转化为字节流
                rsaProvider.FromXmlString(XmlPublicKey); //载入公钥
                var bufferSize = (rsaProvider.KeySize / 8) - 11; //单块最大长度
                var buffer = new byte[bufferSize];
                using (MemoryStream inputStream = new MemoryStream(inputBytes), outputStream = new MemoryStream())
                {
                    while (true)
                    {
                        //分段加密
                        var readSize = inputStream.Read(buffer, 0, bufferSize);
                        if (readSize <= 0)
                            break;
                        var temp = new byte[readSize];
                        Array.Copy(buffer, 0, temp, 0, readSize);
                        var encryptedBytes = rsaProvider.Encrypt(temp, false);
                        outputStream.Write(encryptedBytes, 0, encryptedBytes.Length);
                    }
                    Ciphertext = Convert.ToBase64String(outputStream.ToArray()); //转化为字节流方便传输
                }
            }
        }

        /// <summary>
        /// RSA解密 不限长度的解密版本
        /// </summary>
        /// <param name="XmlPrivateKey">私匙</param>
        /// <param name="Ciphertext">需要进行解密的字符串</param>
        /// <param name="Plaintext">解密后的字符串</param>
        public static void RSADecrypt(string XmlPrivateKey, string Ciphertext, ref string Plaintext)
        {
            if (string.IsNullOrEmpty(Ciphertext))
                throw new Exception("解密字符串不能为空.");
            if (string.IsNullOrWhiteSpace(XmlPrivateKey))
                throw new ArgumentException("错误的私匙");
            using (var rsaProvider = new RSACryptoServiceProvider())
            {
                var inputBytes = Convert.FromBase64String(Ciphertext);
                rsaProvider.FromXmlString(XmlPrivateKey);
                var bufferSize = rsaProvider.KeySize / 8;
                var buffer = new byte[bufferSize];
                using (MemoryStream inputStream = new MemoryStream(inputBytes), outputStream = new MemoryStream())
                {
                    while (true)
                    {
                        var readSize = inputStream.Read(buffer, 0, bufferSize);
                        if (readSize <= 0)
                            break;
                        var temp = new byte[readSize];
                        Array.Copy(buffer, 0, temp, 0, readSize);
                        var rawBytes = rsaProvider.Decrypt(temp, false);
                        outputStream.Write(rawBytes, 0, rawBytes.Length);
                    }
                    Plaintext = new UnicodeEncoding().GetString((outputStream.ToArray()));
                }
            }
        }

        #endregion
    }
}