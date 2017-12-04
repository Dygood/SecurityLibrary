using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace YuWan
{
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
                var des = new DESCryptoServiceProvider
                {
                    Key = Encoding.ASCII.GetBytes(GetMD5(key)),
                    IV = Encoding.ASCII.GetBytes(GetMD5(key))
                };
                var inputByteArray = Encoding.Default.GetBytes(str);
                using (var ms = new MemoryStream())
                {
                    using (var cs = new CryptoStream(ms, des.CreateEncryptor(), CryptoStreamMode.Write))
                    {
                        cs.Write(inputByteArray, 0, inputByteArray.Length);
                        cs.FlushFinalBlock();
                        var ret = new StringBuilder();
                        foreach (var b in ms.ToArray())
                            ret.AppendFormat($"{b:X2}");
                        return ret.ToString();
                    }
                }
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
            /// <param name="str"></param> 
            /// <param name="key"></param> 
            /// <returns></returns> 
            public static string Decrypt(string str, string key)
            {
                var des = new DESCryptoServiceProvider
                {
                    Key = Encoding.ASCII.GetBytes(GetMD5(key)),
                    IV = Encoding.ASCII.GetBytes(GetMD5(key))
                };
                var len = str.Length / 2;
                var inputByteArray = new byte[len];
                for (var i = 0; i < len; i++)
                    inputByteArray[i] = (byte) Convert.ToInt32(str.Substring(i * 2, 2), 16);
                using (var ms = new MemoryStream())
                {
                    using (var cs = new CryptoStream(ms, des.CreateDecryptor(), CryptoStreamMode.Write))
                    {
                        cs.Write(inputByteArray, 0, inputByteArray.Length);
                        cs.FlushFinalBlock();
                        return Encoding.Default.GetString(ms.ToArray());
                    }
                }
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

                var md5char = md5.ComputeHash(Encoding.Unicode.GetBytes(str));
                var result = md5char.Aggregate<byte, string>(null, (current, t) => current + t.ToString("x2"));
                return result.ToUpper();
            }

            #endregion
        }
    }
}