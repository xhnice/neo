using Neo.Core;
using Neo.IO;
using System;
using System.IO;

namespace Neo.Network.Payloads
{
    public class VersionPayload : ISerializable
    {
        public uint Version;// 协议版本
        public ulong Services;// 节点提供的服务
        public uint Timestamp;// 当前时间
        public ushort Port; // 监听的端口，如果不监听则为0
        public uint Nonce;// 用于区分相同公网IP的节点
        public string UserAgent;// 客户端标识
        public uint StartHeight;// 区块链高度
        public bool Relay;// 是否并转发

        public int Size => sizeof(uint) + sizeof(ulong) + sizeof(uint) + sizeof(ushort) + sizeof(uint) + UserAgent.GetVarSize() + sizeof(uint) + sizeof(bool);

        public static VersionPayload Create(int port, uint nonce, string userAgent)
        {
            return new VersionPayload
            {
                Version = LocalNode.ProtocolVersion,
                Services = NetworkAddressWithTime.NODE_NETWORK,
                Timestamp = DateTime.Now.ToTimestamp(),
                Port = (ushort)port,
                Nonce = nonce,
                UserAgent = userAgent,
                StartHeight = Blockchain.Default?.Height ?? 0,
                Relay = true
            };
        }

        void ISerializable.Deserialize(BinaryReader reader)
        {
            Version = reader.ReadUInt32();
            Services = reader.ReadUInt64();
            Timestamp = reader.ReadUInt32();
            Port = reader.ReadUInt16();
            Nonce = reader.ReadUInt32();
            UserAgent = reader.ReadVarString(1024);
            StartHeight = reader.ReadUInt32();
            Relay = reader.ReadBoolean();
        }

        void ISerializable.Serialize(BinaryWriter writer)
        {
            writer.Write(Version);
            writer.Write(Services);
            writer.Write(Timestamp);
            writer.Write(Port);
            writer.Write(Nonce);
            writer.WriteVarString(UserAgent);
            writer.Write(StartHeight);
            writer.Write(Relay);
        }
    }
}
