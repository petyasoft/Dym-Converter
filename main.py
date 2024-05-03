from bip_utils import Bip39SeedGenerator, Bip44Coins, Bip44, Bip44Changes

ALPHABET = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l'
ALPHABET_MAP = {c: i for i, c in enumerate(ALPHABET)}

def polymod_step(pre):
    b = pre >> 25
    return (((pre & 0x1ffffff) << 5) ^
            (-((b >> 0) & 1) & 0x3b6a57b2) ^
            (-((b >> 1) & 1) & 0x26508e6d) ^
            (-((b >> 2) & 1) & 0x1ea119fa) ^
            (-((b >> 3) & 1) & 0x3d4233dd) ^
            (-((b >> 4) & 1) & 0x2a1462b3))

def prefix_chk(prefix):
    chk = 1
    for c in prefix:
        if ord(c) < 33 or ord(c) > 126:
            return f'Invalid prefix ({prefix})'
        chk = polymod_step(chk) ^ (ord(c) >> 5)
    chk = polymod_step(chk)
    for c in prefix:
        v = ord(c)
        chk = polymod_step(chk) ^ (v & 0x1f)
    return chk

def convert(data, in_bits, out_bits, pad):
    value = 0
    bits = 0
    max_v = (1 << out_bits) - 1
    result = []
    for d in data:
        value = (value << in_bits) | d
        bits += in_bits
        while bits >= out_bits:
            bits -= out_bits
            result.append((value >> bits) & max_v)
    if pad:
        if bits > 0:
            result.append((value << (out_bits - bits)) & max_v)
    else:
        if bits >= in_bits:
            return 'Excess padding'
        if (value << (out_bits - bits)) & max_v:
            return 'Non-zero padding'
    return result

def to_words(bytes):
    return convert(bytes, 8, 5, True)

def from_words(words):
    return convert(words, 5, 8, False)

def get_library_from_encoding(encoding):
    ENCODING_CONST = 1 if encoding == 'bech32' else 0x2bc830a3

    def encode(prefix, words, LIMIT=None):
        LIMIT = LIMIT or 90
        if len(prefix) + 7 + len(words) > LIMIT:
            raise TypeError('Exceeds length limit')
        prefix = prefix.lower()
        chk = prefix_chk(prefix)
        if isinstance(chk, str):
            raise ValueError(chk)
        result = prefix + '1'
        for x in words:
            if x >> 5 != 0:
                raise ValueError('Non 5-bit word')
            chk = polymod_step(chk) ^ x
            result += ALPHABET[x]
        for _ in range(6):
            chk = polymod_step(chk)
        chk ^= ENCODING_CONST
        for i in range(6):
            v = (chk >> ((5 - i) * 5)) & 0x1f
            result += ALPHABET[v]
        return result

    def decode(str, LIMIT=None):
        LIMIT = LIMIT or 90
        if len(str) < 8:
            return str + ' too short'
        if len(str) > LIMIT:
            return 'Exceeds length limit'
        lowered = str.lower()
        if str != lowered and str != str.upper():
            return 'Mixed-case string ' + str
        str = lowered
        split = str.rfind('1')
        if split == -1:
            return 'No separator character for ' + str
        if split == 0:
            return 'Missing prefix for ' + str
        prefix = str[:split]
        word_chars = str[split + 1:]
        if len(word_chars) < 6:
            return 'Data too short'
        chk = prefix_chk(prefix)
        if isinstance(chk, str):
            return chk
        words = []
        for c in word_chars:
            v = ALPHABET_MAP.get(c)
            if v is None:
                return 'Unknown character ' + c
            chk = polymod_step(chk) ^ v
            if len(word_chars) - len(words) <= 6:
                words.append(v)
        if chk != ENCODING_CONST:
            return 'Invalid checksum for ' + str
        return {'prefix': prefix, 'words': words}

    return {
        'decode': decode,
        'encode': encode
    }

def from_bech32_addr_to_bytes_addr(bech32_addr):
    return '0x' + ''.join(format(x, '02x') for x in from_words(get_library_from_encoding('bech32')['decode'](bech32_addr)['words'])).lower()

def from_evm_addr_to_bech32_addr(prefix, evm_addr):
    return get_library_from_encoding('bech32')['encode'](prefix, to_words(bytes.fromhex(evm_addr)))

bech32_account_addr_prefix = 'ethm'
bech32_validator_addr_prefix = f'{bech32_account_addr_prefix}valoper'
bech32_consensus_addr_prefix = f'{bech32_account_addr_prefix}valcons'
ens_tld = 'eth'

def is_cosmos_address(addr):
    return addr and isinstance(addr, str) and addr.startswith(bech32_account_addr_prefix)

def is_cosmos_address_with_prefix(addr, prefix):
    return addr and isinstance(addr, str) and addr.startswith(prefix + '1') and len(addr) >= len(prefix) + 1 + 32 + 6

def is_cosmos_address_of_type_account(addr):
    return is_cosmos_address_with_prefix(addr, bech32_account_addr_prefix)

def is_cosmos_address_of_type_validator(addr):
    return is_cosmos_address_with_prefix(addr, bech32_validator_addr_prefix)

def is_cosmos_address_of_type_consensus(addr):
    return is_cosmos_address_with_prefix(addr, bech32_consensus_addr_prefix)

def is_ens_domain(input_str):
    input_str = input_str.lower()
    if not input_str.endswith(f'.{ens_tld}') or len(input_str) < 3 + 1 + len(ens_tld):
        return False
    spl = input_str.split('.')
    for i, part in enumerate(spl[:-1]):
        if i == len(spl) - 2:
            if len(part) < 3:
                return False
        else:
            if len(part) < 1:
                return False
    return True

def from_evm_style_addr_to_cosmos_style_addr(prefix, evm_addr):
    return from_evm_addr_to_bech32_addr(prefix, evm_addr.lower())

# Используем функцию с корректным префиксом для преобразования адреса Ethereum в Cosmos адрес



class BlockChainAccount():
    def __init__(self, mnemonic, coin_type=Bip44Coins.ETHEREUM, password = '') -> None:
        self.mnemonic = mnemonic.strip()
        self.coin_type = coin_type
        self.password = password 

    def get_address(self,count):
        seed_bytes = Bip39SeedGenerator(self.mnemonic).Generate(self.password)
        bip44_mst_ctx = Bip44.FromSeed(seed_bytes, self.coin_type).Purpose().Coin().Account(0).Change(Bip44Changes.CHAIN_EXT).AddressIndex(count)
        return {"mnemonic" : self.mnemonic,
                "address" : bip44_mst_ctx.PublicKey().ToAddress(),
                "private" : f"0x{bip44_mst_ctx.PrivateKey().Raw().ToHex()}"}

    
with open("address.txt",'w') as file:
    pass
with open("private.txt",'w') as file:
    pass
with open("alldata.txt",'w') as file:
    pass

with open("mnemonics.txt",'r') as file:
    mnemonics = [mnemo.strip() for mnemo in file.readlines()]
for mnemonic in mnemonics:
    COINT_DERIVATION_PATH = 1
    for count in range(COINT_DERIVATION_PATH):
        try:
            keys = BlockChainAccount(mnemonic=mnemonic)
            info = keys.get_address(count)
            dym_address = from_evm_style_addr_to_cosmos_style_addr("dym", info['address'][2:])
            
            with open("address.txt",'a') as file:
                file.write(dym_address+'\n')
            with open("private.txt",'a') as file:
                file.write(info["private"]+'\n')
            with open("alldata.txt",'a') as file:
                file.write(info["mnemonic"]+' '+info["private"]+' '+dym_address+'\n')
            print(info,dym_address)
        except:
            continue


