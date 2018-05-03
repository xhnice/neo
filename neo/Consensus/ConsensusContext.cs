using Neo.Core;
using Neo.Cryptography;
using Neo.Cryptography.ECC;
using Neo.IO;
using Neo.Network.Payloads;
using Neo.Wallets;
using System.Collections.Generic;
using System.Linq;

namespace Neo.Consensus
{
    internal class ConsensusContext
    {
        public const uint Version = 0;
        public ConsensusState State;
        public UInt256 PrevHash;
        public uint BlockIndex;
        public byte ViewNumber;
        public ECPoint[] Validators;
        public int MyIndex;
        public uint PrimaryIndex;
        public uint Timestamp;
        public ulong Nonce;
        public UInt160 NextConsensus;
        public UInt256[] TransactionHashes;
        public Dictionary<UInt256, Transaction> Transactions;
        public byte[][] Signatures;
        public byte[] ExpectedView;
        public KeyPair KeyPair;

        public int M => Validators.Length - (Validators.Length - 1) / 3;

        /// <summary>
        /// 更新共识视图
        /// </summary>
        /// <param name="view_number">新的视图编号</param>
        public void ChangeView(byte view_number)
        {
            int p = ((int)BlockIndex - view_number) % Validators.Length;
            // 设置共识状态为已发送签名
            State &= ConsensusState.SignatureSent;
            ViewNumber = view_number;
            // 议长编号
            PrimaryIndex = p >= 0 ? (uint)p : (uint)(p + Validators.Length);
            if (State == ConsensusState.Initial)
            {
                TransactionHashes = null;
                Signatures = new byte[Validators.Length][];
            }
            ExpectedView[MyIndex] = view_number;
            _header = null;
        }

        public ConsensusPayload MakeChangeView()
        {
            return MakePayload(new ChangeView
            {
                NewViewNumber = ExpectedView[MyIndex]
            });
        }

        private Block _header = null;
        public Block MakeHeader()
        {
            if (TransactionHashes == null) return null;
            if (_header == null)
            {
                _header = new Block
                {
                    Version = Version,
                    PrevHash = PrevHash,
                    MerkleRoot = MerkleTree.ComputeRoot(TransactionHashes),
                    Timestamp = Timestamp,
                    Index = BlockIndex,
                    ConsensusData = Nonce,
                    NextConsensus = NextConsensus,
                    Transactions = new Transaction[0]
                };
            }
            return _header;
        }

        private ConsensusPayload MakePayload(ConsensusMessage message)
        {
            message.ViewNumber = ViewNumber;
            return new ConsensusPayload
            {
                Version = Version,
                PrevHash = PrevHash,
                BlockIndex = BlockIndex,
                ValidatorIndex = (ushort)MyIndex,
                Timestamp = Timestamp,
                Data = message.ToArray()
            };
        }

        public ConsensusPayload MakePrepareRequest()
        {
            return MakePayload(new PrepareRequest
            {
                Nonce = Nonce,
                NextConsensus = NextConsensus,
                TransactionHashes = TransactionHashes,
                MinerTransaction = (MinerTransaction)Transactions[TransactionHashes[0]],
                Signature = Signatures[MyIndex]
            });
        }

        public ConsensusPayload MakePrepareResponse(byte[] signature)
        {
            return MakePayload(new PrepareResponse
            {
                Signature = signature
            });
        }

        /// <summary>
        /// 共识状态重置，准备发起新一轮共识
        /// </summary>
        /// <param name="wallet">钱包</param>
        public void Reset(Wallet wallet)
        {
            State = ConsensusState.Initial;// 共识状态为  Initial
            PrevHash = Blockchain.Default.CurrentBlockHash; // 获取上一个区块
            BlockIndex = Blockchain.Default.Height + 1; // 新区块下标
            ViewNumber = 0;// 初始状态 视图编号为0
            Validators = Blockchain.Default.GetValidators(); // 获取议员信息
            MyIndex = -1;// 当前议员下标初始化
            PrimaryIndex = BlockIndex % (uint)Validators.Length;// 确定议长 p = (h - v)mod n 此处 v = 0
            TransactionHashes = null;
            Signatures = new byte[Validators.Length][];
            ExpectedView = new byte[Validators.Length];// 用于保存众议员当前视图编号
            KeyPair = null;
            for (int i = 0; i < Validators.Length; i++)
            {
                // 获取自己的议员编号以及密钥
                WalletAccount account = wallet.GetAccount(Validators[i]);
                if (account?.HasKey == true)
                {
                    MyIndex = i;
                    KeyPair = account.GetKey();
                    break;
                }
            }
            _header = null;
        }
    }
}
