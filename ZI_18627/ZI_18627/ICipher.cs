using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace ZI_18627
{
    public interface ICipher
    {
        byte[] Encrypt(byte[] input, byte[] key);
        byte[] Decrypt(byte[] input, byte[] key);
    }
}
