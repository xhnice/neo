using Neo.Core;

namespace Neo.Network
{
    public interface IInventory : IVerifiable
    {
        /// <summary>
        /// 存放签名的Hash值
        /// </summary>
        UInt256 Hash { get; }
        /// <summary>
        /// 账本消息类型用来保存消息类型及验证函数verify用来对消息进行验证
        /// </summary>
        InventoryType InventoryType { get; }
        /// <summary>
        /// 验证消息
        /// </summary>
        /// <returns></returns>
        bool Verify();
    }
}
