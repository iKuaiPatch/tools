import audit_pb2
from google.protobuf import json_format

with open("ik_audit2.bin", 'rb') as f:
    data = f.read()

audit = audit_pb2.IkAuditData()
audit.ParseFromString(data)
print(audit)
json_str = json_format.MessageToJson(audit, preserving_proto_field_name=True)
with open("ik_audit2.json", 'w', encoding='utf-8') as f:
    f.write(json_str)
