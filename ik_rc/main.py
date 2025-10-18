import rc_decrypt
import rc_pb2
import gzip
import re

data = "" # rc data
data = bytes.fromhex(data)
key = b'' # rc key

rc_data = rc_decrypt.decrypt_rc_data(data, key)

for rc in rc_data:
    sid = rc.session_id
    data_type = rc.data_type
    raw_data = rc.data
    print(f"SID: {hex(sid)}, Type: {data_type}, Length: {len(raw_data)}")
    msg = None
    match data_type:
        case rc_decrypt.DataType.HEARTBEAT_REQ, rc_decrypt.DataType.HEARTBEAT_RESP:
            msg = raw_data
        case rc_decrypt.DataType.AUTH_REQ:
            msg = rc_pb2.AuthReq()
            msg.ParseFromString(raw_data)
        case rc_decrypt.DataType.AUTH_RESP:
            msg = rc_pb2.AuthResp()
            msg.ParseFromString(raw_data)
        case rc_decrypt.DataType.REST_CTRL_REQ:
            msg = rc_pb2.RestCtrlReq()
            msg.ParseFromString(raw_data)
            msg = msg.req
        case rc_decrypt.DataType.REST_CTRL_RESP:
            msg = rc_pb2.RestCtrlResp()
            msg.ParseFromString(raw_data)
            msg = msg.resp
        case rc_decrypt.DataType.DISCONN_REQ:
            msg = rc_pb2.DisconnReq()
            msg.ParseFromString(raw_data)
        case rc_decrypt.DataType.SESSION_END:
            msg = rc_pb2.SessionEnd()
            msg.ParseFromString(raw_data)

    if msg:
        if type(msg) == bytes:
            if msg.find(b'\r\n\r\n') != -1:
                header, body = msg.split(b'\r\n\r\n', 1)
                if body.startswith(b'\x1f\x8b'):
                    body = gzip.decompress(body)
                
                # replace Content-Length
                header = re.sub(b'Content-Length: \\d+', b'Content-Length: ' + str(len(body)).encode(), header)

                msg = header + b'\r\n\r\n' + body
            print(msg.decode())
        else:
            print(msg)
    else:
        print("Unknown type", data_type)
        print(raw_data.hex())
    
    print()
