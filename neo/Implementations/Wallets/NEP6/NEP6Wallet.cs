using Neo.Core;
using Neo.IO.Json;
using Neo.SmartContract;
using Neo.Wallets;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using UserWallet = Neo.Implementations.Wallets.EntityFramework.UserWallet;

namespace Neo.Implementations.Wallets.NEP6
{
    public class NEP6Wallet : Wallet, IDisposable
    {
        public override event EventHandler<BalanceEventArgs> BalanceChanged;

        private readonly string path;
        private string password;
        private string name;
        private Version version;
        private readonly int type;// 账号类型 同钱包文件的保存方式相关 AddCode
        public readonly ScryptParameters Scrypt;
        private readonly Dictionary<UInt160, NEP6Account> accounts;// 钱包地址列表

        private readonly JObject extra;
        private readonly Dictionary<UInt256, Transaction> unconfirmed = new Dictionary<UInt256, Transaction>();

        public override string Name => name;
        public override Version Version => version;
        public override uint WalletHeight => WalletIndexer.IndexHeight;

        public NEP6Wallet(string path, string name = null)
        {
            this.type = 0;
            // 以文件的形式打开钱包
            this.path = path;
            //Console.WriteLine($"NEP6Wallet Path: {this.path}");
            if (File.Exists(path)) // 通过文件加载钱包
            {
                //Console.WriteLine($"NEP6Wallet Path: {this.path}");
                JObject wallet;
                using (StreamReader reader = new StreamReader(path))
                {
                    wallet = JObject.Parse(reader);
                }
                //Console.WriteLine($"Wallet Name: {wallet["version"].AsString()}");
                this.name = wallet["name"]?.AsString();
                this.version = Version.Parse(wallet["version"].AsString());
                this.Scrypt = ScryptParameters.FromJson(wallet["scrypt"]);
                // 把文件中的账号信息转换成 NEP6Account 并加入到 accounts  键名是  ScriptHash
                this.accounts = ((JArray)wallet["accounts"]).Select(p => NEP6Account.FromJson(p, this)).ToDictionary(p => p.ScriptHash);
                //foreach (UInt160 key in this.accounts.Keys)
                //{
                //    this.accounts[key].GetKey();
                //}
                this.extra = wallet["extra"];
                WalletIndexer.RegisterAccounts(accounts.Keys);
            }
            else
            {
                this.name = name;
                this.version = Version.Parse("1.0");
                this.Scrypt = ScryptParameters.Default;
                this.accounts = new Dictionary<UInt160, NEP6Account>();
                this.extra = JObject.Null;
            }
            WalletIndexer.BalanceChanged += WalletIndexer_BalanceChanged;
        }

        /// <summary>
        /// 使用wifkey或nep2key初始化钱包
        /// AddCode
        /// </summary>
        /// <param name="wifKey"></param>
        /// <param name="nep2key"></param>
        /// <param name="password"></param>
        /// <param name="name"></param>
        public NEP6Wallet(string wifKey, string nep2key, string password, string name = null)
        {
            this.type = 0;
            this.name = name;
            this.version = Version.Parse("1.0");
            this.accounts = new Dictionary<UInt160, NEP6Account>();
            this.Scrypt = ScryptParameters.Default;
            this.extra = JObject.Null;
            // 以Wif私钥的方式打开钱包 add code
            if (!string.IsNullOrEmpty(wifKey))
            {
                var account = Import(wifKey, password);
                account.GetKey();
                account.Print();
                WalletIndexer.RegisterAccounts(accounts.Keys);
                WalletIndexer.BalanceChanged += WalletIndexer_BalanceChanged;

            }
            else if (!string.IsNullOrEmpty(nep2key))
            {
                this.password = password;
                //Console.WriteLine($"password: {password}");
                var account = Import(nep2key, password);
                account.GetKey();
                account.Print();
                WalletIndexer.RegisterAccounts(accounts.Keys);
                WalletIndexer.BalanceChanged += WalletIndexer_BalanceChanged;
            }
        }

        /// <summary>
        /// 使用公钥初始化钱包
        /// Add Code
        /// </summary>
        /// <param name="publicKey"></param>
        /// <param name="address"></param>
        /// <param name="name"></param>
        public NEP6Wallet(string publicKey, string address, string name)
        {
            this.type = 0;
            this.name = name;
            this.version = Version.Parse("1.0");
            this.accounts = new Dictionary<UInt160, NEP6Account>();
            this.Scrypt = ScryptParameters.Default;
            this.extra = JObject.Null;
            var accout = ImportFromPublicKey(publicKey);
            //account.GetKey();
            WalletIndexer.RegisterAccounts(accounts.Keys);
            WalletIndexer.BalanceChanged += WalletIndexer_BalanceChanged;
        }

        /// <summary>
        /// 无参默认构造函数 无任何实现代码
        /// Add Code
        /// </summary>
        public NEP6Wallet()
        {
            this.type = 0;
            // 设置默认path
            //this.path = "E";
        }

        /// <summary>
        /// 使用钱包文件初始化钱包
        /// 
        /// Add Code
        /// </summary>
        /// <param name="path">钱包文件路径</param>
        /// <param name="password">密码</param>
        /// <param name="type">账号类型</param>
        public NEP6Wallet(string path, string password, int type = 0)
        {
            this.type = type;
            this.path = path;
            // 钱包文件是否存在
            if (!File.Exists(path))
            {
                throw new FileNotFoundException();
            }
            // 打开钱包
            JObject wallet;
            using (StreamReader reader = new StreamReader(path))
            {
                wallet = JObject.Parse(reader);
            }
            //Console.WriteLine($"Wallet Name: {wallet["version"].AsString()}");
            this.name = wallet["name"]?.AsString();
            this.version = Version.Parse(wallet["version"].AsString());
            this.Scrypt = ScryptParameters.FromJson(wallet["scrypt"]);
            // 把文件中的账号信息转换成 NEP6Account 并加入到 accounts  键名是  ScriptHash
            this.accounts = ((JArray)wallet["accounts"]).Select(p => NEP6Account.fromJson(p, this)).ToDictionary(p => p.ScriptHash);
            //foreach (UInt160 key in this.accounts.Keys)
            //{
            //    this.accounts[key].GetKey();
            //}
            this.extra = wallet["extra"];
            WalletIndexer.RegisterAccounts(accounts.Keys);
        }

        private void AddAccount(NEP6Account account, bool is_import)
        {
            lock (accounts)
            {
                if (accounts.TryGetValue(account.ScriptHash, out NEP6Account account_old))
                {
                    account.Label = account_old.Label;
                    account.IsDefault = account_old.IsDefault;
                    account.Lock = account_old.Lock;
                    if (account.Contract == null)
                    {
                        account.Contract = account_old.Contract;
                    }
                    else
                    {
                        NEP6Contract contract_old = (NEP6Contract)account_old.Contract;
                        if (contract_old != null)
                        {
                            NEP6Contract contract = (NEP6Contract)account.Contract;
                            contract.ParameterNames = contract_old.ParameterNames;
                            contract.Deployed = contract_old.Deployed;
                        }
                    }
                    account.Extra = account_old.Extra;
                }
                else
                {
                    WalletIndexer.RegisterAccounts(new[] { account.ScriptHash }, is_import ? 0 : Blockchain.Default?.Height ?? 0);
                }
                accounts[account.ScriptHash] = account;
            }
        }

        public override void ApplyTransaction(Transaction tx)
        {
            lock (unconfirmed)
            {
                unconfirmed[tx.Hash] = tx;
            }
            BalanceChanged?.Invoke(this, new BalanceEventArgs
            {
                Transaction = tx,
                RelatedAccounts = tx.Scripts.Select(p => p.ScriptHash).Union(tx.Outputs.Select(p => p.ScriptHash)).Where(p => Contains(p)).ToArray(),
                Height = null,
                Time = DateTime.UtcNow.ToTimestamp()
            });
        }

        public override bool Contains(UInt160 scriptHash)
        {
            lock (accounts)
            {
                return accounts.ContainsKey(scriptHash);
            }
        }

        public override WalletAccount CreateAccount(byte[] privateKey)
        {
            KeyPair key = new KeyPair(privateKey);
            NEP6Contract contract = new NEP6Contract
            {
                Script = Contract.CreateSignatureRedeemScript(key.PublicKey),
                ParameterList = new[] { ContractParameterType.Signature },
                ParameterNames = new[] { "signature" },
                Deployed = false
            };
            NEP6Account account = new NEP6Account(this, contract.ScriptHash, key, password)
            {
                Contract = contract
            };
            AddAccount(account, false);
            return account;
        }

        public override WalletAccount CreateAccount(Contract contract, KeyPair key = null)
        {
            NEP6Contract nep6contract = contract as NEP6Contract;
            if (nep6contract == null)
            {
                nep6contract = new NEP6Contract
                {
                    Script = contract.Script,
                    ParameterList = contract.ParameterList,
                    ParameterNames = contract.ParameterList.Select((p, i) => $"parameter{i}").ToArray(),
                    Deployed = false
                };
            }
            NEP6Account account;
            if (key == null)
                account = new NEP6Account(this, nep6contract.ScriptHash);
            else
                account = new NEP6Account(this, nep6contract.ScriptHash, key, password);
            account.Contract = nep6contract;
            AddAccount(account, false);
            return account;
        }

        public override WalletAccount CreateAccount(UInt160 scriptHash)
        {
            NEP6Account account = new NEP6Account(this, scriptHash);
            AddAccount(account, true);
            return account;
        }

        public KeyPair DecryptKey(string nep2key)
        {
            //return new KeyPair(GetPrivateKeyFromNEP2(nep2key, password, Scrypt.N, Scrypt.R, Scrypt.P));
            // 增加无密码分支  AddCode
            if (string.IsNullOrEmpty(password))
            {
                return new KeyPair(GetPrivateKeyFromNEP2(nep2key, Scrypt.N, Scrypt.R, Scrypt.P));
            }
            else
            {
                return new KeyPair(GetPrivateKeyFromNEP2(nep2key, password, Scrypt.N, Scrypt.R, Scrypt.P));
            }
        }

        public override bool DeleteAccount(UInt160 scriptHash)
        {
            bool removed;
            lock (accounts)
            {
                removed = accounts.Remove(scriptHash);
            }
            if (removed)
            {
                WalletIndexer.UnregisterAccounts(new[] { scriptHash });
            }
            return removed;
        }

        public void Dispose()
        {
            WalletIndexer.BalanceChanged -= WalletIndexer_BalanceChanged;
        }

        public override Coin[] FindUnspentCoins(UInt256 asset_id, Fixed8 amount, UInt160[] from)
        {
            return FindUnspentCoins(FindUnspentCoins(from).ToArray().Where(p => GetAccount(p.Output.ScriptHash).Contract.IsStandard), asset_id, amount) ?? base.FindUnspentCoins(asset_id, amount, from);
        }

        public override WalletAccount GetAccount(UInt160 scriptHash)
        {
            lock (accounts)
            {
                accounts.TryGetValue(scriptHash, out NEP6Account account);
                return account;
            }
        }

        public override IEnumerable<WalletAccount> GetAccounts()
        {
            lock (accounts)
            {
                foreach (NEP6Account account in accounts.Values)
                    yield return account;
            }
        }

        /// <summary>
        /// 获取余额
        /// </summary>
        /// <param name="accounts">ScriptHash</param>
        /// <returns></returns>
        public override IEnumerable<Coin> GetCoins(IEnumerable<UInt160> accounts)
        {
            if (unconfirmed.Count == 0)
                return WalletIndexer.GetCoins(accounts);
            else
                return GetCoinsInternal();
            IEnumerable<Coin> GetCoinsInternal()
            {
                HashSet<CoinReference> inputs, claims;
                Coin[] coins_unconfirmed;
                lock (unconfirmed)
                {
                    inputs = new HashSet<CoinReference>(unconfirmed.Values.SelectMany(p => p.Inputs));
                    claims = new HashSet<CoinReference>(unconfirmed.Values.OfType<ClaimTransaction>().SelectMany(p => p.Claims));
                    coins_unconfirmed = unconfirmed.Values.Select(tx => tx.Outputs.Select((o, i) => new Coin
                    {
                        Reference = new CoinReference
                        {
                            PrevHash = tx.Hash,
                            PrevIndex = (ushort)i
                        },
                        Output = o,
                        State = CoinState.Unconfirmed
                    })).SelectMany(p => p).ToArray();
                }
                foreach (Coin coin in WalletIndexer.GetCoins(accounts))
                {
                    if (inputs.Contains(coin.Reference))
                    {
                        if (coin.Output.AssetId.Equals(Blockchain.GoverningToken.Hash))
                            yield return new Coin
                            {
                                Reference = coin.Reference,
                                Output = coin.Output,
                                State = coin.State | CoinState.Spent
                            };
                        continue;
                    }
                    else if (claims.Contains(coin.Reference))
                    {
                        continue;
                    }
                    yield return coin;
                }
                HashSet<UInt160> accounts_set = new HashSet<UInt160>(accounts);
                foreach (Coin coin in coins_unconfirmed)
                {
                    if (accounts_set.Contains(coin.Output.ScriptHash))
                        yield return coin;
                }
            }
        }

        public override IEnumerable<UInt256> GetTransactions()
        {
            foreach (UInt256 hash in WalletIndexer.GetTransactions(accounts.Keys))
                yield return hash;
            lock (unconfirmed)
            {
                foreach (UInt256 hash in unconfirmed.Keys)
                    yield return hash;
            }
        }

        public override WalletAccount Import(X509Certificate2 cert)
        {
            KeyPair key;
            using (ECDsa ecdsa = cert.GetECDsaPrivateKey())
            {
                key = new KeyPair(ecdsa.ExportParameters(true).D);
            }
            NEP6Contract contract = new NEP6Contract
            {
                Script = Contract.CreateSignatureRedeemScript(key.PublicKey),
                ParameterList = new[] { ContractParameterType.Signature },
                ParameterNames = new[] { "signature" },
                Deployed = false
            };
            NEP6Account account = new NEP6Account(this, contract.ScriptHash, key, password)
            {
                Contract = contract
            };
            AddAccount(account, true);
            return account;
        }

        /// <summary>
        /// 使用Wif Key 私钥导入钱包
        /// </summary>
        /// <param name="wif">Wif key</param>
        /// <returns>钱包账号</returns>
        public override WalletAccount Import(string wif)
        {
            KeyPair key = new KeyPair(GetPrivateKeyFromWIF(wif));
            NEP6Contract contract = new NEP6Contract
            {
                Script = Contract.CreateSignatureRedeemScript(key.PublicKey),
                ParameterList = new[] { ContractParameterType.Signature },
                ParameterNames = new[] { "signature" },
                Deployed = false
            };
            NEP6Account account = new NEP6Account(this, contract.ScriptHash, key, password)
            {
                Contract = contract
            };
            AddAccount(account, true);
            return account;
        }

        /// <summary>
        /// 使用Nep2key 和 密码 导入钱包
        /// </summary>
        /// <param name="nep2">nep2key</param>
        /// <param name="passphrase">密码</param>
        /// <returns>钱包账号</returns>
        public override WalletAccount Import(string nep2, string passphrase)
        {
            //KeyPair key = new KeyPair(GetPrivateKeyFromNEP2(nep2, passphrase));
            // 增加无密码分支  AddCode
            //Console.WriteLine("Import 1");
            KeyPair key;
            if (string.IsNullOrEmpty(passphrase))
            {
                key = new KeyPair(GetPrivateKeyFromNEP2(nep2));
            } else
            {
                key = new KeyPair(GetPrivateKeyFromNEP2(nep2, passphrase));
            }
            //Console.WriteLine("Import 2");
            NEP6Contract contract = new NEP6Contract
            {
                Script = Contract.CreateSignatureRedeemScript(key.PublicKey),
                ParameterList = new[] { ContractParameterType.Signature },
                ParameterNames = new[] { "signature" },
                Deployed = false
            };
            //Console.WriteLine("Import 3");
            //Console.WriteLine($"ScriptHash: {contract.ScriptHash}");
            NEP6Account account;
            if (Scrypt.N == 16384 && Scrypt.R == 8 && Scrypt.P == 8)
                account = new NEP6Account(this, contract.ScriptHash, nep2);
            else
                account = new NEP6Account(this, contract.ScriptHash, key, passphrase);
            account.Contract = contract;
            AddAccount(account, true);
            return account;
        }

        /// <summary>
        /// 从公钥导入钱包  使用一个假的私钥
        /// Add Code
        /// </summary>
        /// <param name="publicKey">公钥</param>
        /// <returns>钱包账号</returns>
        public WalletAccount ImportFromPublicKey(string publicKey)
        {
            //Console.WriteLine($"ScriptHash1: {publicKey}");
            KeyPair key = new KeyPair(publicKey);
            //Console.WriteLine($"ScriptHash2: {publicKey}");
            NEP6Contract contract = new NEP6Contract
            {
                Script = Contract.CreateSignatureRedeemScript(key.PublicKey),
                ParameterList = new[] { ContractParameterType.Signature },
                ParameterNames = new[] { "signature" },
                Deployed = false
            };
            //Console.WriteLine("Import 3");
            //Console.WriteLine($"ScriptHash: {contract.ScriptHash}");
            NEP6Account account;
            if (Scrypt.N == 16384 && Scrypt.R == 8 && Scrypt.P == 8)
                account = new NEP6Account(this, contract.ScriptHash);
            else
                account = new NEP6Account(this, contract.ScriptHash, key, null);
            account.Contract = contract;
            AddAccount(account, true);
            return account;
        }

        /// <summary>
        /// 注册本地钱包
        /// Add Code
        /// </summary>
        /// <param name="publicKey">公钥</param>
        public void RegisterLocalWallet(string publicKey)
        {
            KeyPair key = new KeyPair(publicKey);
            NEP6Contract contract = new NEP6Contract
            {
                Script = Contract.CreateSignatureRedeemScript(key.PublicKey),
                ParameterList = new[] { ContractParameterType.Signature },
                ParameterNames = new[] { "signature" },
                Deployed = false
            };
            Dictionary<UInt160, UInt160> keys = new Dictionary<UInt160, UInt160>();
            keys.Add(contract.ScriptHash, contract.ScriptHash);
            Console.WriteLine($"ScriptHash: {contract.ScriptHash.ToString()}");
            WalletIndexer.RegisterAccounts(keys.Keys);
        }

        internal void Lock()
        {
            password = null;
        }

        public static NEP6Wallet Migrate(string path, string db3path, string password)
        {
            using (UserWallet wallet_old = UserWallet.Open(db3path, password))
            {
                NEP6Wallet wallet_new = new NEP6Wallet(path, wallet_old.Name);
                using (wallet_new.Unlock(password))
                {
                    foreach (WalletAccount account in wallet_old.GetAccounts())
                    {
                        wallet_new.CreateAccount(account.Contract, account.GetKey());
                    }
                }
                return wallet_new;
            }
        }

        /// <summary>
        /// 存储钱包信息到 Json
        /// </summary>
        public void Save()
        {
            if (this.type == 0) // 钱包保存方式  默认
            {
                JObject wallet = new JObject();
                wallet["name"] = name;
                wallet["version"] = version.ToString();
                wallet["scrypt"] = Scrypt.ToJson();
                wallet["accounts"] = new JArray(accounts.Values.Select(p => p.ToJson()));
                wallet["extra"] = extra;
                File.WriteAllText(path, wallet.ToString());
            } else
            {
                save();
            }
        }

        /// <summary>
        /// 存储钱包信息到JSON
        /// AddCode
        /// </summary>
        public void save()
        {
            JObject wallet = new JObject();
            wallet["name"] = name;
            wallet["version"] = version.ToString();
            wallet["scrypt"] = Scrypt.ToJson();
            wallet["accounts"] = new JArray(accounts.Values.Select(p => p.toJson()));
            wallet["extra"] = extra;
            File.WriteAllText(path, wallet.ToString());
        }

        /// <summary>
        /// 解锁钱包文件  主要用于密码验证
        /// </summary>
        /// <param name="password"></param>
        /// <returns></returns>
        public IDisposable Unlock(string password)
        {
            if (!VerifyPassword(password))
                throw new CryptographicException();
            this.password = password;
            //Console.WriteLine($"Unlock password: {password}");
            return new WalletLocker(this);
        }

        /// <summary>
        /// 验证密码是否有效
        /// </summary>
        /// <param name="password"></param>
        /// <returns></returns>
        public override bool VerifyPassword(string password)
        {
            lock (accounts)
            {
                NEP6Account account = accounts.Values.FirstOrDefault(p => !p.Decrypted);
                if (account == null)
                {
                    account = accounts.Values.FirstOrDefault(p => p.HasKey);
                }
                if (account == null) return true;
                //Console.WriteLine($"NEP6 VerifyPassword password: {password}");
                if (account.Decrypted)
                {
                    //Console.WriteLine($"NEP6 VerifyPassword password1: {password}");
                    return account.VerifyPassword(password);
                }
                else
                {
                    try
                    {
                        //Console.WriteLine($"NEP6Wallet account: {account.ToJson().AsString()}");
                        //Console.WriteLine($"Account Key: {account.Address}");
                        //Console.WriteLine($"NEP6 VerifyPassword password2: {password}");
                        //Console.WriteLine($"WIFKey: {account.GetWIFKey()}");
                        account.GetKey(password); // 获取私钥
                        //Console.WriteLine($"WIFKey: {account.GetWIFKey()}");
                        return true;
                    }
                    catch (FormatException)
                    {
                        //Console.WriteLine($"NEP6 VerifyPassword password2 Exception: {password}");
                        return false;
                    }
                }
            }
        }

        /// <summary>
        /// 钱包全额索引更新
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="e"></param>
        private void WalletIndexer_BalanceChanged(object sender, BalanceEventArgs e)
        {
            lock (unconfirmed)
            {
                unconfirmed.Remove(e.Transaction.Hash);
            }
            UInt160[] relatedAccounts;
            lock (accounts)
            {
                relatedAccounts = e.RelatedAccounts.Where(p => accounts.ContainsKey(p)).ToArray();
            }
            if (relatedAccounts.Length > 0)
            {
                BalanceChanged?.Invoke(this, new BalanceEventArgs
                {
                    Transaction = e.Transaction,
                    RelatedAccounts = relatedAccounts,
                    Height = e.Height,
                    Time = e.Time
                });
            }
        }

        /// <summary>
        /// 打开钱包
        /// </summary>
        public void OpenWallet(string path)
        {
            // 设置钱包文件目录
            //string walletPath = this.path;
            //if (string.IsNullOrEmpty(this.path))
            //{
            //    walletPath = "wallet.json";
            //}
            // 钱包文件是否存在
            if (!File.Exists(path))
            {
                throw new FileNotFoundException();
            }
            
        }
    }
}
