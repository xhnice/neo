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
        public bool WatchOnly => Contract == null;

        public abstract KeyPair GetKey();

        public abstract string GetPrivateKey();

        public abstract string GetWIFKey();

        public abstract void Print();

        protected WalletAccount(UInt160 scriptHash)
        {
            this.ScriptHash = scriptHash;
        }
    }
}
