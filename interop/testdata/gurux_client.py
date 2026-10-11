# Copyright 2026 Abhinav Gautam
# SPDX-License-Identifier: Apache-2.0
"""Reads a DLMS/COSEM meter with the Gurux DLMS library for Python.

Written for SigmaM2M's interop tests (interop_test.go next to this
directory), which install the gurux-dlms package in a container and run
this script there against the dlms-sim meter. It drives Gurux's client
classes directly over a socket and prints one JSON object per line: one
per check, {"check": ..., "ok": ..., "detail": ...}. The process exits 0
when every check passed.
"""

import argparse
import datetime
import json
import socket
import sys
import traceback

from gurux_dlms import GXByteBuffer, GXDLMSClient, GXReplyData
from gurux_dlms.enums import Authentication, InterfaceType, ObjectType, Security
from gurux_dlms.objects import GXDLMSData, GXDLMSProfileGeneric
from gurux_dlms.secure import GXDLMSSecureClient

AUTH = {
    "none": Authentication.NONE,
    "low": Authentication.LOW,
    "hls": Authentication.HIGH,
    "gmac": Authentication.HIGH_GMAC,
}
SECURITY = {
    "none": Security.NONE,
    "auth": Security.AUTHENTICATION,
    "enc": Security.ENCRYPTION,
    "authenc": Security.AUTHENTICATION_ENCRYPTION,
}

failed = False


def report(check, ok, detail=""):
    global failed
    if not ok:
        failed = True
    print(json.dumps({"check": check, "ok": ok, "detail": str(detail)}), flush=True)


class Link:
    """One TCP connection carrying the client's frames (wrapper or HDLC)."""

    def __init__(self, client, host, port):
        self.client = client
        self.sock = socket.create_connection((host, port), 10)
        self.sock.settimeout(20)

    def close(self):
        self.sock.close()

    def exchange(self, frame, reply):
        if frame is not None:
            self.sock.sendall(bytes(frame))
        notify = GXReplyData()
        rd = GXByteBuffer()
        while not self.client.getData(rd, reply, notify):
            chunk = self.sock.recv(65536)
            if not chunk:
                raise IOError("the meter closed the connection")
            rd.set(chunk)
        if reply.error != 0:
            raise IOError("the meter answered error %d" % reply.error)

    def request(self, frames, reply):
        """Sends a request (one frame or several) and follows blocks."""
        if isinstance(frames, list):
            for f in frames:
                reply.clear()
                self.request(f, reply)
            return
        self.exchange(frames, reply)
        while reply.isMoreData():
            frame = None if reply.isStreaming() else self.client.receiverReady(reply)
            self.exchange(frame, reply)


def new_client(args, client_address, auth, security):
    iface = InterfaceType.WRAPPER if args.iface == "wrapper" else InterfaceType.HDLC
    c = GXDLMSSecureClient(True, client_address, 1, auth, args.password or None, iface)
    if security != Security.NONE or auth == Authentication.HIGH_GMAC:
        c.ciphering.security = security
        c.ciphering.systemTitle = bytes.fromhex(args.system_title)
        c.ciphering.blockCipherKey = bytes.fromhex(args.block_key)
        c.ciphering.authenticationKey = bytes.fromhex(args.auth_key)
    return c


def associate(c, link):
    reply = GXReplyData()
    frame = c.snrmRequest()
    if frame:
        link.request(frame, reply)
        c.parseUAResponse(reply.data)
        reply.clear()
    link.request(c.aarqRequest(), reply)
    c.parseAareResponse(reply.data)
    reply.clear()
    if c.authentication > Authentication.LOW:
        for f in c.getApplicationAssociationRequest():
            link.exchange(f, reply)
        c.parseApplicationAssociationResponse(reply.data)


def release(c, link):
    reply = GXReplyData()
    try:
        link.request(c.releaseRequest(), reply)
    except Exception:  # some meters close at once
        pass
    try:
        frame = c.disconnectRequest()
        if frame:
            reply.clear()
            link.request(frame, reply)
    except Exception:
        pass
    link.close()


def read(c, link, obj, attr):
    reply = GXReplyData()
    link.request(c.read(obj, attr), reply)
    if obj.getDataType(attr) == 0 and reply.valueType:
        obj.setDataType(attr, reply.valueType)
    return c.updateValue(obj, attr, reply.value)


def read_invocation_counter(args):
    """Reads the meter's frame counter for us through the public client."""
    c = new_client(args, 16, Authentication.NONE, Security.NONE)
    link = Link(c, args.host, args.port)
    associate(c, link)
    d = GXDLMSData(args.ic)
    read(c, link, d, 2)
    release(c, link)
    return int(d.value)


def show(v):
    if isinstance(v, (bytes, bytearray)):
        return v.hex()
    return str(v)


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--host", required=True)
    p.add_argument("--port", type=int, required=True)
    p.add_argument("--iface", choices=["wrapper", "hdlc"], default="wrapper")
    p.add_argument("--client", type=int, default=16)
    p.add_argument("--auth", choices=sorted(AUTH), default="none")
    p.add_argument("--password", default="")
    p.add_argument("--security", choices=sorted(SECURITY), default="none")
    p.add_argument("--system-title", default="4D4D4D0000000001")
    p.add_argument("--block-key", default="")
    p.add_argument("--auth-key", default="")
    p.add_argument("--ic", default="", help="invocation counter object read through the public client")
    p.add_argument("--get", action="append", default=[], help="class:obis:attribute")
    p.add_argument("--profile", default="", help="profile generic to read whole, by entry and by range")
    p.add_argument("--range-hours", type=int, default=6)
    args = p.parse_args()

    auth, security = AUTH[args.auth], SECURITY[args.security]
    c = new_client(args, args.client, auth, security)
    try:
        if args.ic:
            c.ciphering.invocationCounter = read_invocation_counter(args) + 1
        link = Link(c, args.host, args.port)
        associate(c, link)
        report("associate", True, "client %d auth %s security %s over %s" % (args.client, args.auth, args.security, args.iface))
    except Exception as e:
        report("associate", False, "%s: %s" % (type(e).__name__, e))
        traceback.print_exc(file=sys.stderr)
        return 1

    for g in args.get:
        cls, obis, attr = g.split(":")
        try:
            obj = GXDLMSClient.createObject(ObjectType(int(cls)))
            obj.logicalName = obis
            v = read(c, link, obj, int(attr))
            detail = show(v)
            if int(cls) == 3 and int(attr) == 3:
                detail = "scaler %s unit %s" % (obj.scaler, int(obj.unit))
            report("get " + g, True, detail)
        except Exception as e:
            report("get " + g, False, "%s: %s" % (type(e).__name__, e))
            traceback.print_exc(file=sys.stderr)

    if args.profile:
        pg = GXDLMSProfileGeneric(args.profile)
        try:
            read(c, link, pg, 3)
            report("profile capture objects", len(pg.captureObjects) > 0,
                   ", ".join("%d/%s/%d" % (k.objectType, k.logicalName, v.attributeIndex) for k, v in pg.captureObjects))
        except Exception as e:
            report("profile capture objects", False, "%s: %s" % (type(e).__name__, e))
        try:
            read(c, link, pg, 2)
            rows = list(pg.buffer)
            report("profile whole buffer", len(rows) > 0, "%d rows, last %s" % (len(rows), [show(x) for x in rows[-1]] if rows else None))
        except Exception as e:
            report("profile whole buffer", False, "%s: %s" % (type(e).__name__, e))
            traceback.print_exc(file=sys.stderr)
        try:
            reply = GXReplyData()
            link.request(c.readRowsByEntry(pg, 1, 2), reply)
            c.updateValue(pg, 2, reply.value)
            report("profile by entry 1..2", len(pg.buffer) == 2, "%d rows" % len(pg.buffer))
        except Exception as e:
            report("profile by entry 1..2", False, "%s: %s" % (type(e).__name__, e))
            traceback.print_exc(file=sys.stderr)
        try:
            end = datetime.datetime.now(datetime.timezone.utc)
            start = end - datetime.timedelta(hours=args.range_hours)
            reply = GXReplyData()
            link.request(c.readRowsByRange(pg, start, end), reply)
            c.updateValue(pg, 2, reply.value)
            rows = list(pg.buffer)
            report("profile by range", len(rows) > 0, "%d rows from %s to %s, first %s" % (
                len(rows), start.isoformat(), end.isoformat(), [show(x) for x in rows[0]] if rows else None))
        except Exception as e:
            report("profile by range", False, "%s: %s" % (type(e).__name__, e))
            traceback.print_exc(file=sys.stderr)

    try:
        release(c, link)
        report("release", True)
    except Exception as e:
        report("release", False, e)
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
