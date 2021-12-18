from pypbc import *
from utils import hash_nosafe
import datetime

#这里的内容就可以换成pbc中param文件夹下的几种曲线参数了，但是“”“是要保留的哦。
stored_params = """type a
q 8780710799663312522437781984754049815806883199414208211028653399266475630880222957078625179422662221423155858769582317459277713367317481324925129998224791
h 12016012264891146079388821366740534204802954401251311822919615131047207289359704531102844802183906537786776
r 730750818665451621361119245571504901405976559617
exp2 159
exp1 107
sign1 1
sign0 1
"""

# 密钥生成算法，输入安全参数qbits和rbits，返回[params, g, pk, sk]
# def KeyGen(qbits=512, rbits=160):
def KeyGen():
    params = Parameters(param_string=stored_params)   #参数初始化
    pairing = Pairing(params)  # 根据参数实例化双线性对
    # 返回公共参数，PEKS是对称双线性对，G1=G2,二者的生成元是一样的，G1同样可以替换为G2
    g = Element.random(pairing, G1)  # g是G1的一个生成元
    sk = Element.random(pairing, Zr) # 私钥是一个素数域Zp内的随机数
    pk = Element(pairing, G1, value=g ** sk)   # 公钥是[g, h = g^α] α=sk
    return [params, g, sk, pk]

params = Parameters(param_string=stored_params)
pairing = Pairing(params)

class Pkeet(object):
    def __init__(self, g):
        self.params = params
        self.pairing =  pairing
        self.g = Element(self.pairing, G1, value=g)
        # self.sk = Element(self.pairing, Zr, value=int(sk, 16))
        # self.pk = Element(self.pairing, G1, value=pk)
        # 随机数r的长度
        self.r_len = 42
        # 随机数m的长度
        self.m_len = 130

    def enc(self, pk, data):
        m = str(data).encode('utf-8').hex()
        element_m = Element(self.pairing, G1, value=m.upper())

        r = Element.random(self.pairing, Zr)  # 定义一个Zp内的随机数r
        U = Element(self.pairing, G1, value = self.g ** r)
        V = Element(self.pairing, G1, value = element_m ** r)
        W = Element(self.pairing, G1, value = pk ** r)

        # hash_W是hex字符串
        hash_W = hash_nosafe(self.m_len+self.r_len, str(U), str(V), str(W))

        W_m = hex(int(hash_W, 16) ^ int(m, 16))

        W_r = hex(int(hash_W, 16) ^ int(str(r), 16))

        W = (W_m, W_r)

        # print("U:", U)
        # print("V:", U)
        # print("W:", W)
        # print(type(m))
        # print("m:", m)
        # print("r:", r)
        # print("element_m:", element_m)

        return (U, V, W)

    def dec(self, sk, data):
        U, V, W = data
        W_m, W_r = W
        # sk = Element(self.pairing, Zr, value=int(sk, 16))
        U_x = Element(self.pairing, G1, value = U ** sk)
        # hash_W = Element.from_hash(self.pairing, Zr, Hash((str(U) + str(V) + str(U_x)).encode('utf-8')).hexdigest())
        hash_W = hash_nosafe(self.m_len+self.r_len, str(U), str(V), str(U_x))
        # hash_W = str(hash_W)
        # form = '%%0%dx' % len(hash_W)
        dec_m = hex(int(hash_W, 16)^int(W_m, 16))
        dec_r = hex(int(hash_W, 16)^int(W_r, 16))
        dec_m_1 = str(dec_m)[2:]
        element_m = Element(self.pairing, G1, value = dec_m_1.upper())
        element_r = Element(self.pairing, Zr, value = int(dec_r, 16))

        U1 = Element(self.pairing, G1, value = self.g ** element_r)
        V1 = element_m ** element_r
        #
        # print("U:", U)
        # print("V:", U)
        # print("W:", W)
        # print(type(dec_m_1))
        # print("m:", dec_m_1)
        # print("r:", dec_r)
        # print("element_m:", element_m)
        # print("element_r:", element_r)

        # msg = bytes.fromhex(dec_m[2:]).decode('utf-8')
        # return msg

        # TODO V = m^r,这个程序里面不等于, 不知道为啥
        # if U == U1 and V == V1:
        if U == U1:
            msg = bytes.fromhex(dec_m[2:]).decode('utf-8')
            return msg
        return False

    def equal_test(self, C1, C2):
        U1, V1, W1 = C1
        U2, V2, W2 = C2
        rst1 = self.pairing.apply(U1, V2)
        rst2 = self.pairing.apply(U2, V1)
        if rst1 == rst2:
            return True
        return False

def test_enc_dec():
    g = "028F26225FB2AA1FD8A9AADD4427D5128A6A1094B734B504F5A674F7DCFC2F2EF27B9F17258FC83E6F1F3CFE74ADA806DB00625CCE3E7228550AB15060394D0C0E"
    sk = "0x5E9EB7186FAD03EAFA0C6AC20526B586052B81D9"
    pk = "034028ADA5F1498719F0A48D951908A6D5E13F1DCB128650D0B83EDB9E5CBDAD6CFF131B95E02F171FA0E7D1C45584D2B7E8A4EFC74DAEE34B59248031A5D0430B"

    sk = Element(pairing, Zr, value=int(sk, 16))

    pk = Element(pairing, G1, value=pk)
    # params = Parameters(param_string=stored_params)
    pkeet = Pkeet(g)
    #
    result = pkeet.enc(data="41.159664_-8.58573", pk=pk)
    rst = pkeet.dec(sk, result)
    # print(result)
    print("程序结束")
    print(rst)

def test_enc_dec1():
    [params1, g1, sk1, pk1] = KeyGen()
    pkeet1 = Pkeet(g1)
    result1 = pkeet1.enc(data="你好", pk=pk1)
    print(result1)
    result2 = pkeet1.dec(sk=sk1, data=result1)
    print(result2)

def test_enc_dec3():
    # g = "028F26225FB2AA1FD8A9AADD4427D5128A6A1094B734B504F5A674F7DCFC2F2EF27B9F17258FC83E6F1F3CFE74ADA806DB00625CCE3E7228550AB15060394D0C0E"
    # sk = "0x5E9EB7186FAD03EAFA0C6AC20526B586052B81D9"
    # pk = "034028ADA5F1498719F0A48D951908A6D5E13F1DCB128650D0B83EDB9E5CBDAD6CFF131B95E02F171FA0E7D1C45584D2B7E8A4EFC74DAEE34B59248031A5D0430B"
    #
    # sk = Element(pairing, Zr, value=int(sk, 16))
    #
    # pk = Element(pairing, G1, value=pk)
    # # params = Parameters(param_string=stored_params)
    # pkeet = Pkeet(g)
    # #
    # result = pkeet.enc(data="你好的烦烦烦烦烦烦烦烦烦烦烦烦烦烦烦烦烦烦", pk=pk)
    # rst = pkeet.dec(sk, result)
    # # print(result)
    # print("程序结束")
    # print(rst)
    data = "你好"
    m = str(data).encode('utf-8').hex()
    print(str(m))
    s = m.upper()
    print(s)
    print(type(s))
    element_m = Element(pairing, G1, value=s)
    print(element_m)

    element_m1 = Element(pairing, G1, value=s)
    print(element_m1)

    print(element_m1 == element_m)

def test_equal():
    now = datetime.datetime.now()
    [params, g, sk, pk] = KeyGen()
    end = datetime.datetime.now()
    print("KeyGen运行时间", end - now)


    pkeet1 = Pkeet(g)

    now = datetime.datetime.now()
    result1 = pkeet1.enc(data="你好", pk=pk)
    end = datetime.datetime.now()
    print("加密运行时间", end - now)

    now = datetime.datetime.now()
    pkeet1.dec(sk, result1)
    end = datetime.datetime.now()
    print("解密运行时间", end - now)

    # print(pkeet1.dec(sk, result1))

    [params, g, sk, pk] = KeyGen()
    pkeet2 = Pkeet(g)
    result2 = pkeet1.enc(data="你好", pk=pk)

    # print(pkeet1.dec(sk, result2))
    now = datetime.datetime.now()
    rst = pkeet2.equal_test(result1, result2)
    end = datetime.datetime.now()
    print("等值测试运行时间", end - now)

    print(rst)

if __name__ == '__main__':
    # test_enc_dec()
    test_equal()
    # test_enc_dec3()
    # test_enc_dec1()
    # r = Element.random(pairing, Zr)
    # print(len(str(r)))
    # print(r)
    # m = Element.random(pairing, G1)
    # print(len(str(m)))
    # print(m)
    # x = Element(pairing, G1, value=str(0xe4bda0e5a5bd))
    # print(x)
    # y = Element(pairing, G1, value = str(0xe4bda0e5a5bd))
    # print(y)
    # x1 = Element(pairing, G1, value = str(0xe4bda0e5a5bd))
    # print(x1)
    # y1 = Element(pairing, G1, value = "E4BDA0E5A5BD")
    # y2 = Element(pairing, G1, value = "E4BDA0E5A5BD")
    # y3 = Element(pairing, G1, value = "E4BDA0E5A5BD")
    # print(y1)
    # print(y2)
    # print(y3)
    # print(y2 == y3)
    # pk = "034028ADA5F1498719F0A48D951908A6D5E13F1DCB128650D0B83EDB9E5CBDAD6CFF131B95E02F171FA0E7D1C45584D2B7E8A4EFC74DAEE34B59248031A5D0430B"
    #
    # pk = Element(pairing, G1, value=pk)
    # y = Element(pairing, G1, value=pk)
    # z = Element(pairing, G1, value=pk)
    # print(pk)
    # print(y)
    # print(z)
    # print(y == z)


