import ssl
from kmip.pie.client import ProxyKmipClient, enums
from kmip.pie import objects

client = ProxyKmipClient(
    hostname='127.0.0.1',
    port=5696,
    cert='/etc/pykmip/certs/selfsigned.crt',
    key='/etc/pykmip/private/selfsigned.key',
    ca='/etc/pykmip/certs/selfsigned.crt',
    username='example_username',
    password='example_password',
    config='client',
    config_file='/etc/pykmip/pykmip.conf'
)

with client:
    key1 = objects.SymmetricKey(
        algorithm=enums.CryptographicAlgorithm.AES,
        length=256,
        value=(
            b'\x00\x01\x02\x03\x04\x05\x06\x07'
            b'\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F'
            b'\x10\x11\x12\x13\x14\x15\x16\x17'
            b'\x18\x19\x1A\x1B\x1C\x1D\x1E\x1F'
        ),
        masks=[
            enums.CryptographicUsageMask.WRAP_KEY,
        ]
    )
    key2 = objects.SymmetricKey(
        algorithm=enums.CryptographicAlgorithm.AES,
        length=256,
        value=(
            b'\x00\x11\x22\x33\x44\x55\x66\x77'
            b'\x88\x99\xAA\xBB\xCC\xDD\xEE\xFF'
            b'\x00\x01\x02\x03\x04\x05\x06\x07'
            b'\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F'
        ),
        masks=[
            enums.CryptographicUsageMask.WRAP_KEY,
        ]
    )
    key1_id = client.register(key1)
    key2_id = client.register(key2)

    client.activate(key1_id)
    client.activate(key2_id)

    replace_kek = client.get(
        key2_id,
        key_wrapping_specification={
            'wrapping_method': enums.WrappingMethod.ENCRYPT,
            'encryption_key_information': {
                'unique_identifier': key1_id,
                'cryptographic_parameters': {
                    'block_cipher_mode': enums.BlockCipherMode.NIST_KEY_WRAP
                }
            },
            'encoding_option': enums.EncodingOption.NO_ENCODING
        }
    )
    print(len(replace_kek.value))
    print(replace_kek.value)
    for index, key in enumerate(replace_kek.value):
        print(index, hex(key))

    """
    replace_kek = client.get(replace_kek_id).value
    print('replace_kek: ', replace_kek)
    data = client.encrypt(
        data=replace_kek,
        uid=plaintext_kek_id,
        cryptographic_parameters={
            'cryptographic_algorithm': enums.CryptographicAlgorithm.AES,
            'block_cipher_mode': enums.BlockCipherMode.GCM,
            'tag_length': 16,
        },
        iv_counter_nonce=(
            b'\x85\x1e\x87\x64\x77\x6e\x67\x96'
            b'\xaa\xb7\x22\xdb\xb6\x44\xac\xe8'
        )
    )

    print(data[0])
    print(data[1])


    # Wrapping Replace KEK Get
    replace_kek_id = client.create(
        enums.CryptographicAlgorithm.AES, 256,
        operation_policy_name='default',
        name='256_AES_Symmetric_Key',
        cryptographic_usage_mask=[
            enums.CryptographicUsageMask.ENCRYPT,
            enums.CryptographicUsageMask.DECRYPT,
            enums.CryptographicUsageMask.WRAP_KEY,
        ]
    )
    client.activate(replace_kek_id)
    replace_kek = client.get(
        replace_kek_id,
        key_wrapping_specification={
            'wrapping_method': enums.WrappingMethod.ENCRYPT,
            'encryption_key_information': {
                'unique_identifier': plaintext_kek_id,
                'cryptographic_parameters': {
                    'block_cipher_mode': enums.BlockCipherMode.NIST_KEY_WRAP
                }
            },
            'encoding_option': enums.EncodingOption.NO_ENCODING
        }
    )
    print('replace_kek_id: ', replace_kek_id)
    print('replace_kek: ', replace_kek)

    # Wrapping Inject Mek Get
    inject_kek_id = client.create(
        enums.CryptographicAlgorithm.AES, 256,
        operation_policy_name='default',
        name='256_AES_Symmetric_Key',
        cryptographic_usage_mask=[
            enums.CryptographicUsageMask.ENCRYPT,
            enums.CryptographicUsageMask.DECRYPT,
        ]
    )
    client.activate(inject_kek_id)
    inject_kek = client.get(
        inject_kek_id,
        key_wrapping_specification={
            'wrapping_method': enums.WrappingMethod.ENCRYPT,
            'encryption_key_information': {
                'unique_identifier': replace_kek_id,
                'cryptographic_parameters': {
                    'block_cipher_mode': enums.BlockCipherMode.NIST_KEY_WRAP
                }
            },
            'encoding_option': enums.EncodingOption.NO_ENCODING
        }
    )
    print('inject_kek_id: ', inject_kek_id)
    print('inject_kek: ', inject_kek)

"""
