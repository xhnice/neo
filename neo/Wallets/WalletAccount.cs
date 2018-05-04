using Neo.IO.Json;
using Neo.SmartContract;

namespace Neo.Wallets
{
    public abstract class WalletAccount
    {
        public readonly UInt160 ScriptHash;
        public string Label;
        public bool IsDefault;
        public bool Lock;
        public Contract Contract;

        public string Address => Wallet.ToAddress(ScriptHash);
        public abstract bool HasKey { get; }
        /// <summary>
        /// 是否无合约 Contract true 否  false 是
        /// </summary>
        public bool WatchOnly => Contract == null;

        public abstract KeyPair GetKey();

        public abstract string GetPrivateKey();

        public abstract string GetWIFKey();

        public abstract void Print();

        /// <summary>
        /// 对外输出账号信息 private key and address
        /// AddCode
        /// </summary>
        /// <returns>private key and address</returns>
        public abstract JObject OutputJson();

        protected WalletAccount(UInt160 scriptHash)
        {
            this.ScriptHash = scriptHash;
        }
    }
}
