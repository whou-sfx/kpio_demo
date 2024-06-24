import getopt
import sys
import re
import os

from build.lib.kmip.core.utils import BytearrayStream
from kmip.core import enums
from kmip.core import misc
from kmip.core import objects
from kmip.core import secrets
from kmip.core import primitives
from kmip.core.messages import contents
from kmip.core.messages import messages
from kmip.core.messages import payloads

from kmip.pie.client import ProxyKmipClient
from kmip.core.utils import BytearrayStream


def kpio_key_wrapping_data_object(key_wrapping_data):
    object = objects.KeyWrappingData(
        wrapping_method=key_wrapping_data['wrapping_method'],
        encryption_key_information=objects.EncryptionKeyInformation(
            unique_identifier=key_wrapping_data['encryption_key_information']['unique_identifier'],
            cryptographic_parameters=objects.CryptographicParameters(
                cryptographic_algorithm=key_wrapping_data['encryption_key_information']
                ['cryptographic_parameters']['cryptographic_algorithm'],
                block_cipher_mode=key_wrapping_data['encryption_key_information']
                ['cryptographic_parameters']['block_cipher_mode']
            )
        ),
        iv_counter_nonce=key_wrapping_data['iv_counter_nonce']
    )
    return object


class KpioKekInjectRequestPayload(payloads.ImportRequestPayload):
    def __init__(self, kmip_kek_uid, tcg_kek_uid, kek_value, key_wrapping_data=None):
        if key_wrapping_data is None:
            key_value = objects.KeyValue(
                key_material=objects.KeyMaterial(
                    value=kek_value
                )
            )
            self._key_wrapping_data = None
        else:
            key_value = primitives.ByteString(
                value=kek_value,
                tag=enums.Tags.KEY_VALUE
            )
            self._key_wrapping_data = kpio_key_wrapping_data_object(key_wrapping_data)
        super().__init__(
            unique_identifier='%s' % kmip_kek_uid,
            object_type=enums.ObjectType.SYMMETRIC_KEY,
            attributes=[
                objects.CryptographicParameters(
                    key_role_type=enums.KeyRoleType.KEK,
                    cryptographic_algorithm=enums.CryptographicAlgorithm.AES,
                    cryptographic_length=256
                ),
                objects.VendorAttribute(
                    vendor_identification='TCG-SWG',
                    attribute_name='UID',
                    attribute_value=tcg_kek_uid
                )
            ],
            symmetric_key=secrets.SymmetricKey(
                key_block=objects.KeyBlock(
                    key_format_type=misc.KeyFormatType(enums.KeyFormatType.RAW),
                    key_value=key_value,
                    key_wrapping_data=self._key_wrapping_data
                )
            )
        )


class KpioMekInjectRequestPayload(payloads.ImportRequestPayload):
    def __init__(self, kmip_mek_uid, mek_value, ns_id, key_tag, key_wrapping_data):
        super().__init__(
            unique_identifier='%s' % kmip_mek_uid,
            object_type=enums.ObjectType.SYMMETRIC_KEY,
            attributes=[
                objects.CryptographicParameters(
                    key_role_type=enums.KeyRoleType.DEK,
                    cryptographic_algorithm=enums.CryptographicAlgorithm.AES,
                    cryptographic_length=256
                ),
                objects.VendorAttribute(
                    vendor_identification='TCG-SWG',
                    attribute_name='NamespaceID',
                    attribute_value=ns_id
                ),
                objects.VendorAttribute(
                    vendor_identification='TCG-SWG',
                    attribute_name='KeyTag',
                    attribute_value=key_tag
                ),
                objects.Link(
                    link_type=enums.LinkType.NEXT_LINK,
                    link_object_identifier='UNIQUE_IDENTIFIER_MEK_KEY_2'
                )
            ],
            symmetric_key=secrets.SymmetricKey(
                key_block=objects.KeyBlock(
                    key_format_type=misc.KeyFormatType(enums.KeyFormatType.RAW),
                    key_value=primitives.ByteString(
                        value=mek_value,
                        tag=enums.Tags.KEY_VALUE
                    ),
                    key_wrapping_data=kpio_key_wrapping_data_object(key_wrapping_data)
                )
            )
        )


class KpioRequestBatchItem(messages.RequestBatchItem):
    def __init__(self, request_payload):
        super().__init__(
            operation=contents.Operation(enums.Operation.IMPORT),
            unique_batch_item_id=primitives.ByteString(
                value=b'\x01',
                tag=enums.Tags.UNIQUE_BATCH_ITEM_ID
            ),
            request_payload=request_payload
        )


class KpioRequestMessage(messages.RequestMessage):
    def __init__(self, batch_items):
        super().__init__(
            request_header=messages.RequestHeader(
                protocol_version=contents.ProtocolVersion(2, 1),
                batch_count=contents.BatchCount(len(batch_items))
            ),
            batch_items=batch_items
        )


class KpioPlainTextKekInject(KpioRequestMessage):
    def __init__(self, client, uid):
        self.kek_object = client.get(uid)
        super().__init__(
            batch_items=[
                KpioRequestBatchItem(
                    request_payload=KpioKekInjectRequestPayload(
                        kmip_kek_uid=uid,
                        tcg_kek_uid=b'\x00\x00\x12\x02\x00\x01\x00\x01',
                        kek_value=self.kek_object.value
                    )
                )
            ]
        )


class KpioWrappingKekInject(KpioRequestMessage):
    def __init__(self, client, kek_uid, wrap_key_uid):
        self.kek_object = client.get(
            kek_uid,
            key_wrapping_specification={
                'wrapping_method': enums.WrappingMethod.ENCRYPT,
                'encryption_key_information': {
                    'unique_identifier': wrap_key_uid,
                    'cryptographic_parameters': {
                        'cryptographic_algorithm': enums.CryptographicAlgorithm.AES,
                        'block_cipher_mode': enums.BlockCipherMode.NIST_KEY_WRAP
                    }
                },
                'encoding_option': enums.EncodingOption.NO_ENCODING
            }
        )
        print('Get Kek from KMS by uid :', kek_uid)
        super().__init__(
            batch_items=[
                KpioRequestBatchItem(
                    request_payload=KpioKekInjectRequestPayload(
                        kmip_kek_uid=kek_uid,
                        tcg_kek_uid=b'\x00\x00\x12\x02\x00\x01\x00\x01',
                        kek_value=self.kek_object.value,
                        key_wrapping_data=self.kek_object.key_wrapping_data
                    )
                )
            ]
        )


class KpioWrappingMekInject(KpioRequestMessage):
    def __init__(self, client, mek_uid, ns_id, key_tag, wrap_key_uid):
        self.mek_object = client.get(
            mek_uid,
            key_wrapping_specification={
                'wrapping_method': enums.WrappingMethod.ENCRYPT,
                'encryption_key_information': {
                    'unique_identifier': wrap_key_uid,
                    'cryptographic_parameters': {
                        'cryptographic_algorithm': enums.CryptographicAlgorithm.AES,
                        'block_cipher_mode': enums.BlockCipherMode.NIST_KEY_WRAP,
                    }
                },
                'encoding_option': enums.EncodingOption.NO_ENCODING
            }
        )
        print('Get Mek from KMS by uid :', mek_uid)
        super().__init__(
            batch_items=[
                KpioRequestBatchItem(
                    request_payload=KpioMekInjectRequestPayload(
                        kmip_mek_uid=mek_uid,
                        mek_value=self.mek_object.value,
                        ns_id=ns_id,
                        key_tag=key_tag,
                        key_wrapping_data=self.mek_object.key_wrapping_data
                    )
                )
            ]
        )


class KpioSedutil:
    def __init__(self):
        self.sedutil = './sedutil-cli'
        if not os.path.exists(self.sedutil):
            sys.exit('%s not exist' % self.sedutil)

    def setup(self, dev, password):
        os.system('%s --initialSetup %s %s' % (self.sedutil, password, dev))

    def revert(self, dev, password):
        os.system('%s --revertTper %s %s' % (self.sedutil, password, dev))

    def sendKmip(self, dev, object):
        tmp_file = '/tmp/%s' % object.__class__.__name__
        if os.path.exists(tmp_file):
            os.remove(tmp_file)
        with open(tmp_file, 'wb') as fd:
            tstream = BytearrayStream()
            object.write(tstream, kmip_version=enums.KMIPVersion.KMIP_2_0)
            fd.write(tstream.buffer)
        os.system('%s --sendKmipCommand %s %s' % (self.sedutil, tmp_file, dev))

    def clearMek(self, dev, key_tag, ns_id):
        os.system('%s --clearKpioMek %s %s %s' % (self.sedutil, key_tag, ns_id, dev))


class KpioNvmeCli:
    def __init__(self):
        self.nvme_cli = './nvme'
        if not os.path.exists(self.nvme_cli):
            sys.exit('%s not exist' % self.nvme_cli)

    def read_write(self, dev, start, count, size, file_name, key_tag, write=False):
        if write:
            os.system('%s write -s %s -c %s -z %s -d %s -D %s %s'
                      % (self.nvme_cli, start, count, size, file_name, key_tag, dev))
        else:
            os.system('%s read -s %s -c %s -z %s -d %s -D %s %s'
                      % (self.nvme_cli, start, count, size, file_name, key_tag, dev))


class KpioTool:
    def __init__(self):
        self.kpio_version = "sfx-kpio version 1.0\n"
        self.kpio_help = "usage: sfx-kpio <command> [<device>] [<args>]\n\n" \
                         "The '<device>' may be either an NVMe character device (ex: /dev/nvme0) or an\n" \
                         "nvme block device (ex: /dev/nvme0n1).\n\n" \
                         "The following are all implemented sub-commands:\n" \
                         "  setup             setup kpio\n" \
                         "  revert            revert kpio\n" \
                         "  create-key        create key and info key uid\n" \
                         "  inject-kek        inject plain-text | wrapping kek into device\n" \
                         "  inject-mek        inject wrapping mek into device\n" \
                         "  clear-mek         clear wrapping mek in device\n" \
                         "  read-write-data   read/write data with key-tag\n" \
                         "See 'sfx-kpio <command>' for more information on a specific command\n"

        self.setup_help = "setup: invalid argument\n" \
                          "usage: sfx-kpio setup [OPTIONS]\n\n" \
                          "Options:\n" \
                          "  [  --password=<STR>, -p <STR> ]   --- password for tcg\n"

        self.revert_help = "revert: invalid argument\n" \
                           "usage: sfx-kpio revert [OPTIONS]\n\n" \
                           "Options:\n" \
                           "  [  --password=<STR>, -p <STR> ]   --- password for tcg\n"

        self.create_key_help = "create-key: invalid argument\n" \
                               "usage: sfx-kpio create_key\n\n"

        self.inject_kek_help = "inject-kek: invalid argument\n" \
                               "usage: sfx-kpio inject-kek [OPTIONS]\n\n" \
                               "Options:\n" \
                               "  [  --id=<NUM>, -i <NUM> ]   --- kek id for tcg\n" \
                               "  [  --uid=<NUM>, -u <NUM> ]  --- kek uid for kmip\n" \
                               "  [  --wrap=<NUM>, -w <NUM> ] --- (optional)wrap key uid for kmip\n"

        self.inject_mek_help = "inject-mek: invalid argument\n" \
                               "usage: sfx-kpio inject-mek [OPTIONS]\n\n" \
                               "Options:\n" \
                               "  [  --uid=<NUM>, -u <NUM> ]     --- mek uid for kmip\n" \
                               "  [  --ns-id=<NUM>, -n <NUM> ]   --- mek namespace id\n" \
                               "  [  --key-tag=<NUM>, -t <NUM> ] --- mek key tag\n" \
                               "  [  --wrap=<NUM>, -w <NUM> ]    --- wrap key uid for kmip\n"

        self.clear_mek_help = "clear-mek: invalid argument\n" \
                              "usage: sfx-kpio clear-mek [OPTIONS]\n\n" \
                              "Options:\n" \
                              "  [  --key-tag=<NUM>, -t <NUM> ] --- mek key tag(default all meks)\n" \
                              "  [  --ns-id=<NUM>, -n <NUM> ]   --- mek namespace id(default all namespaces)\n"

        self.read_write_data_help = "read-write-data: invalid argument\n" \
                                    "usage: sfx-kpio read-write-data [OPTIONS]\n\n" \
                                    "Options:\n" \
                                    "  [  --start=<NUM>, -s <NUM> ]   --- start block\n" \
                                    "  [  --count=<NUM>, -c <NUM> ]   --- block count\n" \
                                    "  [  --size=<NUM>, -z <NUM> ]    --- block size\n" \
                                    "  [  --file=<FILE>, -f <NUM> ]   --- data file\n" \
                                    "  [  --key-tag=<NUM>, -t <NUM> ] --- mek key tag\n" \
                                    "  [  --write, -w ]               --- write data(default read)\n"

        self.command_dict = {'setup': [self.setup_exec, self.setup_help],
                             'revert': [self.revert_exec, self.revert_help],
                             'create-key': [self.create_key_exec, self.create_key_help],
                             'inject-kek': [self.inject_kek_exec, self.inject_kek_help],
                             'inject-mek': [self.inject_mek_exec, self.inject_mek_help],
                             'clear-mek': [self.clear_mek_exec, self.clear_mek_help],
                             'read-write-data': [self.read_write_data_exec, self.read_write_data_help]}

        self.kpio_sedutil = KpioSedutil()
        self.kpio_nvme_cli = KpioNvmeCli()
        self.kpio_enable = False
        self.kpio_client = ProxyKmipClient(
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

        argc = len(sys.argv)
        argv = sys.argv
        if argc >= 3:
            self.command = argv[1]
            if self.command not in self.command_dict.keys():
                self.do_help(log="ERROR: Invalid command '%s' for sfx-kpio\n" % self.command)
            self.dev = self.dev_check(argv[2])
            if argc > 3:
                if argv[3][0] == '-':
                    self.args = argv[3:]
                    self.command_dict.get(self.command)[0]()
                else:
                    self.do_help(command=self.command)
            else:
                if self.command == 'create-key' or self.command == 'clear-mek':
                    self.command_dict.get(self.command)[0]()
                else:
                    self.do_help(command=self.command)
        else:
            self.do_help()

    def dev_check(self, dev):
        if dev not in os.popen('ls %s 2>&1' % dev).read().split():
            self.do_help(log="%s: No such file or directory\n" % dev)
        elif re.match('/dev/nvme[0-9]', dev, flags=0) is None and \
                re.match('/dev/nvme[0-9]n[0-9]', dev, flags=0) is None:
            sys.exit(1)
        else:
            return dev

    def do_help(self, command=None, log=None):
        if command is None:
            help_str = self.kpio_help
        else:
            help_str = self.command_dict.get(self.command)[1]
        if log is not None:
            help_str = ('%s%s' % (log, help_str))
        sys.exit(help_str)

    def setup_exec(self):
        password = None
        try:
            opts, args = getopt.getopt(self.args, '-p:', ['--password='])
            for opt_name, opt_value in opts:
                if opt_name in ('-p', '--password'):
                    password = opt_value
                else:
                    self.do_help(command=self.command)
        except:
            self.do_help(command=self.command)
        self.kpio_sedutil.setup(self.dev, password)

    def revert_exec(self):
        password = None
        try:
            opts, args = getopt.getopt(self.args, '-p:', ['--password='])
            for opt_name, opt_value in opts:
                if opt_name in ('-p', '--password'):
                    password = opt_value
                else:
                    self.do_help(command=self.command)
        except:
            self.do_help(command=self.command)
        self.kpio_sedutil.revert(self.dev, password)

    def create_key_exec(self):
        with self.kpio_client:
            key_uid = self.kpio_client.create(
                enums.CryptographicAlgorithm.AES, 256,
                operation_policy_name='default',
                name='256_AES_Symmetric_Key',
                cryptographic_usage_mask=[
                    enums.CryptographicUsageMask.WRAP_KEY
                ]
            )
            self.kpio_client.activate(key_uid)
            print('key %s created' % key_uid)

    def inject_kek_exec(self):
        kek_id = None
        kek_uid = None
        wrap_key_uid = None
        try:
            opts, args = getopt.getopt(self.args, '-i:-u:-w:', ['--id=', '--uid=', '--wrap='])
            for opt_name, opt_value in opts:
                if opt_name in ('-i', '--id'):
                    kek_id = opt_value
                elif opt_name in ('-u', '--uid'):
                    kek_uid = opt_value
                elif opt_name in ('-w', '--wrap'):
                    wrap_key_uid = opt_value
                else:
                    self.do_help(command=self.command)
        except:
            self.do_help(command=self.command)
        if kek_id is None or kek_uid is None:
            self.do_help(command=self.command)
        elif int(kek_id) != 0x1:
            sys.exit('kpio only support kek1 now')
        else:
            with self.kpio_client:
                if wrap_key_uid is None:
                    self.kpio_sedutil.sendKmip(self.dev, KpioPlainTextKekInject(self.kpio_client, kek_uid))
                else:
                    self.kpio_sedutil.sendKmip(self.dev, KpioWrappingKekInject(self.kpio_client, kek_uid, wrap_key_uid))
        print('inject kek done')

    def inject_mek_exec(self):
        mek_uid = None
        ns_id = None
        key_tag = None
        wrap_key_uid = None
        try:
            opts, args = getopt.getopt(self.args, '-u:-n:-t:-w:', ['--uid=', '--ns-id=', '--key-tag=', '--wrap='])
            for opt_name, opt_value in opts:
                if opt_name in ('-u', '--uid'):
                    mek_uid = opt_value
                elif opt_name in ('-n', '--ns-id'):
                    ns_id = int(opt_value)
                elif opt_name in ('-t', '--key-tag'):
                    key_tag = int(opt_value)
                elif opt_name in ('-w', '--wrap'):
                    wrap_key_uid = opt_value
                else:
                    self.do_help(command=self.command)
        except:
            self.do_help(command=self.command)
        if mek_uid is None or ns_id is None or key_tag is None or wrap_key_uid is None:
            self.do_help(command=self.command)
        else:
            with self.kpio_client:
                self.kpio_sedutil.sendKmip(self.dev, KpioWrappingMekInject(self.kpio_client, mek_uid,
                                                                           ns_id, key_tag, wrap_key_uid))
        print('inject mek done')

    def read_write_data_exec(self):
        start = None
        count = None
        size = None
        file = None
        key_tag = None
        write = False
        try:
            opts, args = getopt.getopt(self.args, '-s:-c:-z:-f:-t:-w', ['--start=', '--count=', '--size=', '--file=',
                                                                        '--key-tag=', '--write'])
            for opt_name, opt_value in opts:
                if opt_name in ('-s', '--start'):
                    start = opt_value
                elif opt_name in ('-c', '--count'):
                    count = int(opt_value)
                elif opt_name in ('-z', '--size'):
                    size = int(opt_value)
                elif opt_name in ('-f', '--file'):
                    file = opt_value
                elif opt_name in ('-t', '--key-tag'):
                    key_tag = opt_value
                elif opt_name in ('-w', '--write'):
                    write = True
                else:
                    self.do_help(command=self.command)
        except:
            self.do_help(command=self.command)
        if start is None or count is None or size is None or file is None or key_tag is None:
            self.do_help(command=self.command)
        else:
            self.kpio_nvme_cli.read_write(self.dev, start, count, size, file, key_tag, write)

    def clear_mek_exec(self):
        key_tag = None
        ns_id = None
        try:
            opts, args = getopt.getopt(self.args, '-t:-n:', ['--key-tag=', '--ns_id='])
            for opt_name, opt_value in opts:
                if opt_name in ('-t', '--key-tag'):
                    key_tag = int(opt_value)
                elif opt_name in ('-n', '--ns_id'):
                    ns_id = int(opt_value)
                else:
                    self.do_help(command=self.command)
        except:
            pass
        if key_tag is None:
            key_tag = 65535  # 0xffff
        if ns_id is None:
            ns_id = 4294967295  # 0xffffffff
        self.kpio_sedutil.clearMek(self.dev, key_tag, ns_id)


if __name__ == '__main__':
    KpioTool()
