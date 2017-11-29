using System;
using System.IO;
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
        /// 使用加密服务提供程序 (CSP) 版本的数据加密标准 (System.Security.Cryptography.DES) 算法
        /// </summary>
        public static class DESCryp
        {
            #region 加密
            /// <summary>
            /// 使用默认密码(MiracleSoft)加密字符串
            /// </summary>
            /// <param name="str">明文字符串</param>
            /// <returns>密文字符串</returns>
            public static string Encrypt(string str) => Encrypt(str, "MiracleSoft");

            /// <summary> 
            /// 加密数据 
            /// </summary> 
            /// <param name="str">明文字符串</param> 
            /// <param name="key">密码</param> 
            /// <returns>密文字符串</returns> 
            public static string Encrypt(string str, string key)
            {
                DESCryptoServiceProvider des = new DESCryptoServiceProvider
                {
                    Key = Encoding.ASCII.GetBytes(GetMD5(key)),
                    IV = Encoding.ASCII.GetBytes(GetMD5(key))
                };
                byte[] inputByteArray = Encoding.Default.GetBytes(str);
                MemoryStream ms = new MemoryStream();
                CryptoStream cs = new CryptoStream(ms, des.CreateEncryptor(), CryptoStreamMode.Write);
                cs.Write(inputByteArray, 0, inputByteArray.Length);
                cs.FlushFinalBlock();
                StringBuilder ret = new StringBuilder();
                foreach (byte b in ms.ToArray())
                {
                    ret.AppendFormat("{0:X2}", b);
                }
                return ret.ToString();
            }
            #endregion

            #region 解密
            /// <summary>
            /// 使用默认密码(MiracleSoft)解密字符串
            /// </summary>
            /// <param name="str">密文字符串</param>
            /// <returns>明文</returns>
            public static string Decrypt(string str) => Decrypt(str, "MiracleSoft");
            /// <summary> 
            /// 解密数据 
            /// </summary> 
            /// <param name="Text"></param> 
            /// <param name="key"></param> 
            /// <returns></returns> 
            public static string Decrypt(string str, string key)
            {
                DESCryptoServiceProvider des = new DESCryptoServiceProvider
                {
                    Key = Encoding.ASCII.GetBytes(GetMD5(key)),
                    IV = Encoding.ASCII.GetBytes(GetMD5(key))
                };
                int len = str.Length / 2;
                byte[] inputByteArray = new byte[len];
                for (int i = 0; i < len; i++)
                {
                    inputByteArray[i] = (byte)Convert.ToInt32(str.Substring(i * 2, 2), 16);
                }
                MemoryStream ms = new MemoryStream();
                CryptoStream cs = new CryptoStream(ms, des.CreateDecryptor(), CryptoStreamMode.Write);
                cs.Write(inputByteArray, 0, inputByteArray.Length);
                cs.FlushFinalBlock();
                return Encoding.Default.GetString(ms.ToArray());
            }
            #endregion

            #region MD5
            /// <summary>
            /// 获取MD5字符串
            /// </summary>
            /// <param name="str">传入的字符串</param>
            /// <returns>MD5</returns>
            private static string GetMD5(string str)
            {
                MD5 md5 = new MD5CryptoServiceProvider();
                #region ///MD5CryptoServiceProvider  类MSDN详解
                //https://msdn.microsoft.com/zh-cn/library/system.security.cryptography.md5cryptoserviceprovider(v=vs.110).aspx
                #endregion
                byte[] md5char = md5.ComputeHash(Encoding.Unicode.GetBytes(str));
                string result = null;
                for (int i = 0; i < md5char.Length; i++)
                {
                    result += md5char[i].ToString("x2");
                }
                return result.ToUpper();
            }
            #endregion
        }
    }
}