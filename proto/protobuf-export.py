import struct
import ida_ida
import ida_bytes
import ida_idaapi
from enum import Enum, Flag

class ProtobufCFieldFlag(Flag):
    PROTOBUF_C_FIELD_FLAG_PACKED = 1 << 0  # Set if the field is repeated and marked with the `packed` option.
    PROTOBUF_C_FIELD_FLAG_DEPRECATED = 1 << 1  # Set if the field is marked with the `deprecated` option.
    PROTOBUF_C_FIELD_FLAG_ONEOF = 1 << 2  # Set if the field is a member of a oneof (union).


class ProtobufCLabel(Enum):
    '''
    A well-formed message must have exactly one of this field.
    '''
    PROTOBUF_C_LABEL_REQUIRED = 0
    '''
    A well-formed message can have zero or one of this field (but not more than one).
	'''
    PROTOBUF_C_LABEL_OPTIONAL = 1
    '''
    This field can be repeated any number of times (including zero) in a
    well-formed message. The order of the repeated values will be preserved.
    '''
    PROTOBUF_C_LABEL_REPEATED = 2
    '''
    This field has no label. This is valid only in proto3 and is
	equivalent to OPTIONAL but no "has" quantifier will be consulted.
    '''
    PROTOBUF_C_LABEL_NONE = 3


class ProtobufCLabel(Enum):
    PROTOBUF_C_LABEL_REQUIRED = 0  # A well-formed message must have exactly one of this field.
    PROTOBUF_C_LABEL_OPTIONAL = 1  # A well-formed message can have zero or one of this field (but not more than one).
    PROTOBUF_C_LABEL_REPEATED = 2  # This field can be repeated any number of times (including zero) in a well-formed message. The order of the repeated values will be preserved.
    PROTOBUF_C_LABEL_NONE = 3  # This field has no label. This is valid only in proto3 and is equivalent to OPTIONAL but no "has" quantifier will be consulted.


label_mapping = {
    'PROTOBUF_C_LABEL_REQUIRED': 'required',
    'PROTOBUF_C_LABEL_OPTIONAL': 'optional',
    'PROTOBUF_C_LABEL_REPEATED': 'repeated',
    'PROTOBUF_C_LABEL_NONE': '',
}


class ProtobufCType(Enum):
    PROTOBUF_C_TYPE_INT32 = 0  # int32
    PROTOBUF_C_TYPE_SINT32 = 1  # signed int32
    PROTOBUF_C_TYPE_SFIXED32 = 2  # signed int32 (4 bytes)
    PROTOBUF_C_TYPE_INT64 = 3  # int64
    PROTOBUF_C_TYPE_SINT64 = 4  # signed int64
    PROTOBUF_C_TYPE_SFIXED64 = 5  # signed int64 (8 bytes)
    PROTOBUF_C_TYPE_UINT32 = 6  # unsigned int32
    PROTOBUF_C_TYPE_FIXED32 = 7  # unsigned int32 (4 bytes)
    PROTOBUF_C_TYPE_UINT64 = 8  # unsigned int64
    PROTOBUF_C_TYPE_FIXED64 = 9  # unsigned int64 (8 bytes)
    PROTOBUF_C_TYPE_FLOAT = 10  # float
    PROTOBUF_C_TYPE_DOUBLE = 11  # double
    PROTOBUF_C_TYPE_BOOL = 12  # boolean
    PROTOBUF_C_TYPE_ENUM = 13  # enumerated type
    PROTOBUF_C_TYPE_STRING = 14  # UTF-8 or ASCII string
    PROTOBUF_C_TYPE_BYTES = 15  # arbitrary byte sequence
    PROTOBUF_C_TYPE_MESSAGE = 16  # nested message


type_mapping = {
    'PROTOBUF_C_TYPE_INT32': 'int32',  # int32
    'PROTOBUF_C_TYPE_SINT32': 'sint32',  # signed int32
    'PROTOBUF_C_TYPE_SFIXED32': 'sfixed32',  # signed int32 (4 bytes)
    'PROTOBUF_C_TYPE_INT64': 'int64',  # int64
    'PROTOBUF_C_TYPE_SINT64': 'sint64',  # signed int64
    'PROTOBUF_C_TYPE_SFIXED64': 'sfixed64',  # signed int64 (8 bytes)
    'PROTOBUF_C_TYPE_UINT32': 'uint32',  # unsigned int32
    'PROTOBUF_C_TYPE_FIXED32': 'fixed32',  # unsigned int32 (4 bytes)
    'PROTOBUF_C_TYPE_UINT64': 'uint64',  # unsigned int64
    'PROTOBUF_C_TYPE_FIXED64': 'fixed64',  # unsigned int64 (8 bytes)
    'PROTOBUF_C_TYPE_FLOAT': 'float',  # float
    'PROTOBUF_C_TYPE_DOUBLE': 'double',  # double
    'PROTOBUF_C_TYPE_BOOL': 'bool',  # boolean
    'PROTOBUF_C_TYPE_ENUM': 'enum',  # enumerated type
    'PROTOBUF_C_TYPE_STRING': 'string',  # UTF-8 or ASCII string
    'PROTOBUF_C_TYPE_BYTES': 'bytes',  # arbitrary byte sequence
    'PROTOBUF_C_TYPE_MESSAGE': 'message',  # nested message
}

def read_bytes(addr, size):
    return ida_bytes.get_bytes(addr, size)

def read_string(offset, encoding='utf-8'):
    result = bytearray()
    while True:
        byte = read_bytes(offset, 1)
        if not byte or byte == b'\x00':
            break
        result.extend(byte)
        offset += 1
    return result.decode(encoding)

class ProtobufCEnumDescriptor:
    def __init__(self, data):
        attr_names = [
            'magic', 'name', 'short_name', 'c_name', 'package_name',
            'n_values', 'values', 'n_value_names', 'values_by_name',
            'n_value_ranges', 'value_ranges', 'reserved1', 'reserved2',
            'reserved3', 'reserved4'
        ]

        for name, value in zip(attr_names, struct.unpack("PPPPPQQPIPIPPPPP", data.ljust(0x80, b'\x00'))):
            setattr(self, name, value)

        self.name = read_string(self.name)

        self.short_name = read_string(self.short_name)
        self.c_name = read_string(self.c_name)
        self.package_name = read_string(self.package_name)

        self.values_struct = [None] * self.n_values
        offset = self.values - 0x18

        for i in range(self.n_values):
            self.values_struct[i] = ProtobufCEnumValueIndex(read_bytes(offset := offset + 0x18, 0x18))

class ProtobufCEnumValueIndex:
    def __init__(self, data):
        attr_names = [
            'name', 'c_name', 'value'
        ]
        for name, value in zip(attr_names, struct.unpack("PPP", data)):
            setattr(self, name, value)

        self.name = read_string(self.name)
        self.c_name = read_string(self.c_name)

class ProtobufCMessageDescriptor:
    def __init__(self, data, load_field = True):
        attr_names = [
            'magic', 'name', 'short_name', 'c_name', 'package_name', 'nop',
            'n_values', 'values', 'n_value_names', 'values_by_name',
            'n_value_ranges', 'value_ranges', 'reserved1', 'reserved2',
            'reserved3', 'reserved4'
        ]
        for name, value in zip(attr_names, struct.unpack("PPPPPQQPIPIPPPPP", data.ljust(0x80, b'\x00'))):
            setattr(self, name, value)

        self.name = read_string(self.name)

        self.short_name = read_string(self.short_name)
        self.c_name = read_string(self.c_name)
        self.package_name = read_string(self.package_name)

        self.values_struct = [None] * self.n_values
        offset = self.values - 0x48

        if load_field:
            for i in range(self.n_values):
                self.values_struct[i] = ProtobufCFieldDescriptor(read_bytes(offset := offset + 0x48, 0x48))

class ProtobufCFieldDescriptor:
    def __init__(self, data):
        attr_names = [
            'name', 'id', 'label', 'type', 'quantifier_offset',
            'offset', 'descriptor', 'default_value', 'flags',
            'reserved_flags', 'reserved2', 'reserved3'
        ]
        for name, value in zip(attr_names, struct.unpack("PIIIIIPPIIPP", data)):
            setattr(self, name, value)

        self.name = read_string(self.name)

        if self.type == 16 or self.type == 13:
            desc = ida_bytes.get_bytes(self.descriptor, 0x78)
            message = ProtobufCMessageDescriptor(desc, False)
            self.type_name = message.short_name

def get_messages_descriptor_list():
    ea = ida_ida.inf_get_min_ea()
    offset = 0
    result = []
    
    while offset != ida_idaapi.BADADDR:
        offset = ida_bytes.find_bytes(b'\xF9\xEE\xAA\x28\x00\x00\x00\x00', ea)
        ea = offset + 8
        if offset != ida_idaapi.BADADDR:
            result.append(offset)
    
    return result
    
def get_enums_descriptor_list():
    ea = ida_ida.inf_get_min_ea()
    offset = 0
    result = []
    
    while offset != ida_idaapi.BADADDR:
        offset = ida_bytes.find_bytes(b'\xAF\x15\x43\x11\x00\x00\x00\x00', ea)
        ea = offset + 8
        if offset != ida_idaapi.BADADDR:
            result.append(offset)
    
    return result

def extract_messages(path):
    descriptor_list = get_messages_descriptor_list()
    for descriptor in descriptor_list:
        data = ida_bytes.get_bytes(descriptor, 0x78)
        message = ProtobufCMessageDescriptor(data)

        output = f'''syntax = "proto3";

package {message.package_name if message.package_name else message.name};

message {message.short_name} {{
'''

        for i in range(message.n_values):
            if message.values_struct[i].type == 16 or message.values_struct[i].type == 13:
                output += f'    {label_mapping[ProtobufCLabel(message.values_struct[i].label).name]} {message.values_struct[i].type_name} {message.values_struct[i].name} = {message.values_struct[i].id};\n'
            else:
                output += f'    {label_mapping[ProtobufCLabel(message.values_struct[i].label).name]} {type_mapping[ProtobufCType(message.values_struct[i].type).name]} {message.values_struct[i].name} = {message.values_struct[i].id};\n'
        output += '}\n'

        outfile = path + "\\" + message.short_name + ".proto"

        print(outfile)

        open(outfile, 'w').write(output)

def extract_enums(path):
    descriptor_list = get_enums_descriptor_list()
    for descriptor in descriptor_list:
        data = ida_bytes.get_bytes(descriptor, 0x78)
        enum = ProtobufCEnumDescriptor(data)

        output = f'''syntax = "proto3";

package {enum.package_name if enum.package_name else enum.name};

enum {enum.short_name} {{
'''
        for i in range(enum.n_values):
            output += f'    {enum.values_struct[i].name} = {enum.values_struct[i].value};\n'
        output += '}\n'

        outfile = path + "\\" + enum.short_name + ".proto"

        print(outfile)

        open(outfile, 'w').write(output)

output_path = "./"
extract_messages(output_path)
extract_enums(output_path)