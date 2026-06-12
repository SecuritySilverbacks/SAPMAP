#!/usr/bin/env python3
"""Tests for SOAP RFC client — envelope building and response parsing."""

import sys
import os
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from sap_soap_rfc import (
    _build_envelope,
    _parse_response,
    SOAPRFCClient,
)


class TestEnvelopeBuilding:

    def test_simple_string_param(self):
        env = _build_envelope("BAPI_PING", USERNAME="DDIC")
        assert "<urn:BAPI_PING>" in env
        assert "<USERNAME>DDIC</USERNAME>" in env
        assert "</urn:BAPI_PING>" in env

    def test_dict_param_nested(self):
        env = _build_envelope(
            "BAPI_USER_CREATE1",
            USERNAME="SAPMAP00",
            PASSWORD={"BAPIPWD": "Secret!"},
        )
        assert "<PASSWORD><BAPIPWD>Secret!</BAPIPWD></PASSWORD>" in env

    def test_list_param_as_items(self):
        env = _build_envelope(
            "BAPI_USER_PROFILES_ASSIGN",
            USERNAME="X",
            PROFILES=[
                {"BAPIPROF": "SAP_ALL"},
                {"BAPIPROF": "SAP_NEW"},
            ],
        )
        assert "<PROFILES>" in env
        assert env.count("<item>") == 2
        assert "<BAPIPROF>SAP_ALL</BAPIPROF>" in env
        assert "<BAPIPROF>SAP_NEW</BAPIPROF>" in env

    def test_xml_escape_in_value(self):
        env = _build_envelope("X", NOTE="<bad>&value")
        assert "&lt;bad&gt;&amp;value" in env

    def test_bool_serialization(self):
        env = _build_envelope("X", FLAG=True)
        assert "<FLAG>X</FLAG>" in env
        env_f = _build_envelope("X", FLAG=False)
        assert "<FLAG> </FLAG>" in env_f

    def test_none_value(self):
        env = _build_envelope("X", VAL=None)
        assert "<VAL/>" in env


class TestResponseParsing:

    def test_parse_simple_response(self):
        raw = """<?xml version="1.0"?>
        <soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
          <soap:Body>
            <urn:BAPI_PING.Response xmlns:urn="urn:sap-com">
              <RESULT>OK</RESULT>
            </urn:BAPI_PING.Response>
          </soap:Body>
        </soap:Envelope>"""
        out = _parse_response(raw, "BAPI_PING")
        assert out.get("RESULT") == "OK"

    def test_parse_return_struct(self):
        raw = """<?xml version="1.0"?>
        <soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
          <soap:Body>
            <urn:BAPI_USER_CREATE1.Response xmlns:urn="urn:sap-com">
              <RETURN>
                <TYPE>S</TYPE>
                <MESSAGE>User created</MESSAGE>
              </RETURN>
            </urn:BAPI_USER_CREATE1.Response>
          </soap:Body>
        </soap:Envelope>"""
        out = _parse_response(raw, "BAPI_USER_CREATE1")
        assert "RETURN" in out
        assert out["RETURN"]["TYPE"] == "S"
        assert out["RETURN"]["MESSAGE"] == "User created"

    def test_parse_no_response_suffix(self):
        """Some kernels return the FM body without .Response suffix."""
        raw = """<soap:Body xmlns:soap="x">
          <urn:BAPI_X xmlns:urn="urn:sap-com">
            <VAL>hi</VAL>
          </urn:BAPI_X>
        </soap:Body>"""
        out = _parse_response(raw, "BAPI_X")
        assert out.get("VAL") == "hi"

    def test_parse_empty_response(self):
        raw = "<soap:Envelope></soap:Envelope>"
        out = _parse_response(raw, "BAPI_X")
        assert out == {}


class TestSOAPRFCClientInit:

    def test_endpoint_construction_https(self):
        c = SOAPRFCClient(host="twt", port=44300, use_https=True,
                          ticket_cookie="ABC", client="000")
        assert c.endpoint == \
            "https://twt:44300/sap/bc/soap/rfc?sap-client=000"

    def test_endpoint_construction_http(self):
        c = SOAPRFCClient(host="twt", port=8000, use_https=False,
                          ticket_cookie="ABC")
        assert c.endpoint == "http://twt:8000/sap/bc/soap/rfc"

    def test_headers_include_cookie(self):
        c = SOAPRFCClient(host="x", port=1, use_https=True,
                          ticket_cookie="MYTICKET")
        h = c._headers_base()
        assert h["Cookie"] == "MYSAPSSO2=MYTICKET"
