using Neo.IO.Json;
using Neo.Wallets;
using System;
using System.Text;

namespace Neo.Implementations.Wallets.NEP6
{
    internal class NEP6Account : WalletAccount
    {
        private readonly NEP6Wallet wallet;
        private readonly string nep2key;// 公钥
        private KeyPair key;
        public JObject Extra;

        public bool Decrypted => nep2key == null || key != null;
        public override bool HasKey => nep2key != null;

        public NEP6Account(NEP6Wallet wallet, UInt160 scriptHash, string nep2key = null)
            : base(scriptHash)
        {
            //Console.WriteLine($"NEP6Account: {nep2key}"); // 20180423 TODO
            this.wallet = wallet;
            this.nep2key = nep2key;
        }

        public NEP6Account(NEP6Wallet wallet, UInt160 scriptHash, KeyPair key, string password)
            : this(wallet, scriptHash, key.Export(password, wallet.Scrypt.N, wallet.Scrypt.R, wallet.Scrypt.P))
        {
            //Console.WriteLine($"NEP6Account Key: {key.PublicKey.}"); // 20180423 TODO
            this.key = key;
        }


        /// <summary>
        /// 测试16进制公钥导出WIF公钥
        /// </summary>
        public void TestExportNep2(NEP6Wallet wallet)
        {
            //string publicKey = "02883118351f8f47107c83ab634dc7e4ffe29d274e7d3dcf70159c8935ff769beb";//公钥
            //KeyPair keyPair = new KeyPair();
            //var key = keyPair.Export(password, wallet.Scrypt.N, wallet.Scrypt.R, wallet.Scrypt.P);
        }



        public static NEP6Account FromJson(JObject json, NEP6Wallet wallet)
        {
            return new NEP6Account(wallet, Wallet.ToScriptHash(json["address"].AsString()), json["key"]?.AsString())
            {
                Label = json["label"]?.AsString(),
                IsDefault = json["isDefault"].AsBoolean(),
                Lock = json["lock"].AsBoolean(),
                Contract = NEP6Contract.FromJson(json["contract"]),
                Extra = json["extra"]
            };
        }

        public override KeyPair GetKey()
        {
            if (nep2key == null) return null;
            if (key == null)
            {
                key = wallet.DecryptKey(nep2key);
            }
            return key;
        }

        public KeyPair GetKey(string password)
        {
            if (nep2key == null) return null;
            if (key == null)
            {
                if (string.IsNullOrEmpty(password))
                {
                    // Add code 无密码的验证
                    //Console.WriteLine($"NEP6Account nep2key: {nep2key}");
                    key = new KeyPair(Wallet.GetPrivateKeyFromNEP2(nep2key, wallet.Scrypt.N, wallet.Scrypt.R, wallet.Scrypt.P));
                }
                else
                {
                    key = new KeyPair(Wallet.GetPrivateKeyFromNEP2(nep2key, password, wallet.Scrypt.N, wallet.Scrypt.R, wallet.Scrypt.P));
                }
            }
            //Console.WriteLine($"GetKey Key: {key.Export()}");
            return key;
        }

        /// <summary>
        /// 将账号转成json对象
        /// </summary>
        /// <returns></returns>
        public JObject ToJson()
        {
            JObject account = new JObject();
            account["address"] = Wallet.ToAddress(ScriptHash);
            account["label"] = Label;
            account["isDefault"] = IsDefault;
            account["lock"] = Lock;
            account["key"] = nep2key;
            account["contract"] = ((NEP6Contract)Contract)?.ToJson();
            account["extra"] = Extra;
            //account["pKey"] = key.PrivateKey.ToString(); // 输出私钥 add code
            return account;
        }

        /// <summary>
        /// 打印账号信息
        /// AddCode
        /// </summary>
        public override void Print()
        {
            Console.WriteLine($"            prikey: {GetPrivateKey()} ");
            Console.WriteLine($"            wifkey: {GetWIFKey()} ");
            Console.WriteLine($"           nep2key: {nep2key}");
            Console.WriteLine($"            pubkey: {(key?.PublicKey.EncodePoint(true).ToHexString())}");
            Console.WriteLine($"           address: {Wallet.ToAddress(ScriptHash)}");
            Console.WriteLine($"   contract script: {((NEP6Contract)Contract)?.Script.ToHexString()}");
        }
        

        public bool VerifyPassword(string password)
        {
            try
            {
                if (string.IsNullOrEmpty(password))
                {
                    // Add Code 无密码的验证
                    Wallet.GetPrivateKeyFromNEP2(nep2key, wallet.Scrypt.N, wallet.Scrypt.R, wallet.Scrypt.P);
                }
                else
                {
                    Wallet.GetPrivateKeyFromNEP2(nep2key, password, wallet.Scrypt.N, wallet.Scrypt.R, wallet.Scrypt.P);
                }
                return true;
            }
            catch (FormatException)
            {
                return false;
            }
        }

        /// <summary>
        /// 获取 16 进制私钥
        /// Add Code 
        /// </summary>
        /// <returns></returns>
        public override string GetPrivateKey()
        {
            //return "hello";
            //return Encoding.Default.GetString(key.PrivateKey);
            //return key.Export();
            return key.PrivateKey.ToHexString();
        }

        /// <summary>
        /// 获取 WIF 私钥 (对外使用的)
        /// Add Code
        /// </summary>
        /// <returns>WIF 私钥</returns>
        public override string GetWIFKey()
        {
            return key.Export();
        }

        
    }
}
