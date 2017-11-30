using System;
using System.Security.Cryptography;
using System.Text;

/// <summary>
/// So魚丸丷
/// </summary>
namespace YuWan
{
    /// <summary>
    /// 加密解密类库
    /// </summary>
    namespace SecurityLibrary
    {
        /// <summary>
        /// 使用加密服务提供程序 (CSP) 版本 System.Security.Cryptography.TripleDES 算法
        /// </summary>
        public static class TripleDESCryp
        {
            #region 使用 缺省密钥字符串 加密/解密String
            /// <summary>
            /// 使用缺省密钥字符串(yuwan.net)加密String
            /// </summary>
            /// <param name="original">明文</param>
            /// <returns>密文</returns>
            public static string Encrypt(string original) => Encrypt(original, "yuwan.net");

            /// <summary>
            /// 使用缺省密钥字符串(yuwan.net)解密String
            /// </summary>
            /// <param name="original">密文</param>
            /// <returns>明文</returns>
            public static string Decrypt(string original) => Decrypt(original, "yuwan.net", Encoding.Default);
            #endregion

            #region 使用 给定密钥字符串 加密/解密String
            /// <summary>
            /// 使用给定密钥字符串加密String
            /// </summary>
            /// <param name="original">原始文字</param>
            /// <param name="key">密钥</param>
            /// <param name="encoding">字符编码方案</param>
            /// <returns>密文</returns>
            public static string Encrypt(string original, string key) => Convert.ToBase64String(Encrypt(Encoding.Default.GetBytes(original), Encoding.Default.GetBytes(key)));

            /// <summary>
            /// 使用给定密钥字符串解密string
            /// </summary>
            /// <param name="original">密文</param>
            /// <param name="key">密钥</param>
            /// <returns>明文</returns>
            public static string Decrypt(string original, string key) => Decrypt(original, key, Encoding.Default);

            /// <summary>
            /// 使用给定密钥字符串解密string,返回指定编码方式明文
            /// </summary>
            /// <param name="encrypted">密文</param>
            /// <param name="key">密钥</param>
            /// <param name="encoding">字符编码方案</param>
            /// <returns>明文</returns>
            public static string Decrypt(string encrypted, string key, Encoding encoding) => encoding.GetString(Decrypt(Convert.FromBase64String(encrypted), Encoding.Default.GetBytes(key)));
            #endregion

            #region 使用 缺省密钥字符串 加密/解密/byte[]
            /// <summary>
            /// 使用缺省密钥字符串(MiracleSoft)解密Byte[]
            /// </summary>
            /// <param name="encrypted">密文Byte[]</param>
            /// <returns>明文</returns>
            public static byte[] Decrypt(byte[] encrypted) => Decrypt(encrypted, Encoding.Default.GetBytes("MiracleSoft"));

            /// <summary>
            /// 使用缺省密钥字符串(MiracleSoft)加密
            /// </summary>
            /// <param name="original">明文</param>
            /// <returns>密文</returns>
            public static byte[] Encrypt(byte[] original) => Encrypt(original, Encoding.Default.GetBytes("MiracleSoft"));
            #endregion

            #region  使用 给定密钥 加密/解密/byte[]
            /// <summary>
            /// 生成MD5摘要
            /// </summary>
            /// <param name="original">元数据</param>
            /// <returns>MD5摘要</returns>
            public static byte[] MakeMD5(byte[] original) => new MD5CryptoServiceProvider().ComputeHash(original);

            /// <summary>
            /// 使用给定密钥加密
            /// </summary>
            /// <param name="original">明文</param>
            /// <param name="key">密钥</param>
            /// <returns>密文</returns>
            public static byte[] Encrypt(byte[] original, byte[] key)
            {
                TripleDESCryptoServiceProvider des = new TripleDESCryptoServiceProvider
                {
                    Key = MakeMD5(key),
                    Mode = CipherMode.ECB
                };
                return des.CreateEncryptor().TransformFinalBlock(original, 0, original.Length);
            }

            /// <summary>
            /// 使用给定密钥解密数据
            /// </summary>
            /// <param name="encrypted">密文</param>
            /// <param name="key">密钥</param>
            /// <returns>明文</returns>
            public static byte[] Decrypt(byte[] encrypted, byte[] key)
            {
                TripleDESCryptoServiceProvider des = new TripleDESCryptoServiceProvider
                {
                    Key = MakeMD5(key),
                    Mode = CipherMode.ECB
                };
                return des.CreateDecryptor().TransformFinalBlock(encrypted, 0, encrypted.Length);
            }
            #endregion
        }
    }
}