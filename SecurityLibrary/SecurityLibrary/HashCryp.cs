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
        /// 得到随机哈希加密字符串,该加密不可逆.
        /// </summary>
        public static class HashCryp
        {
            /// <summary>
            /// 得到随机哈希加密字符串
            /// </summary>
            /// <returns></returns>
            public static string Security => HashEncoding();

            ///<summary>
            ///生成随机长度随机字符串(10-64的长度)
            ///</summary>
            ///<param name="length">目标字符串的长度</param>
            ///<param name="useNum">是否包含数字,true=包含,默认包含</param>
            ///<param name="useLow">是否包含小写字母,true=包含,默认包含</param>
            ///<param name="useUpp">是否包含大写字母,true=包含,默认包含</param>
            ///<param name="useSpe">是否包含特殊字符,true=包含,默认不包含</param>
            ///<param name="custom">要包含的自定义字符</param>
            ///<returns>指定长度的随机字符串</returns>
            private static string GetRandomString(bool useNum = true, bool useLow = true, bool useUpp = true, bool useSpe = true, string custom = "")
            {
                byte[] b = new byte[4];
                new RNGCryptoServiceProvider().GetBytes(b);
                Random rad = new Random(BitConverter.ToInt32(b, 0));
                int length = rad.Next(10, 64);
                string result = null;
                if (useNum == true)
                    custom += "0123456789";
                if (useLow == true)
                    custom += "abcdefghijklmnopqrstuvwxyz";
                if (useUpp == true)
                    custom += "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
                if (useSpe == true)
                    custom += "!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~";
                for (int i = 0; i < length; i++)
                {
                    result += custom.Substring(rad.Next(0, custom.Length - 1), 1);
                }
                return result;
            }

            /// <summary>
            /// 哈希加密一个字符串
            /// </summary>
            /// <param name="Security"></param>
            /// <returns></returns>
            public static string HashEncoding()
            {
                string security = GetRandomString();
                SHA512Managed sHA512 = new SHA512Managed();
                UnicodeEncoding unicodeEncoding = new UnicodeEncoding();
                byte[] value = sHA512.ComputeHash(unicodeEncoding.GetBytes(security));
                string result = "";
                foreach (byte o in value)
                {
                    result += (int)o + "O";
                }
                return result;
            }
        }
    }
}