import unittest

import httpx

import httpx_ntlm
from tests.test_utils import domain, username, password, password_md4


class TestHttpxNtlm(unittest.TestCase):
    def setUp(self):
        self.test_server_url = "http://localhost:5000/"
        self.test_server_username = "%s\\%s" % (domain, username)
        self.test_server_password = password
        self.auth_types = ["ntlm", "negotiate", "both"]

    def test_httpx_ntlm(self):
        for auth_type in self.auth_types:
            res = httpx.get(
                url=self.test_server_url + auth_type,
                auth=httpx_ntlm.HttpNtlmAuth(
                    self.test_server_username, self.test_server_password
                ),
            )

            self.assertEqual(res.status_code, 200, msg="auth_type " + auth_type)

    def test_requests_ntlm_hash(self):
        # Test authenticating using an NTLM hash
        for auth_type in self.auth_types:
            res = httpx.get(
                url=self.test_server_url + auth_type,
                auth=httpx_ntlm.HttpNtlmAuth(
                    self.test_server_username,
                    "0" * 32 + ":" + password_md4
                )
            )

            self.assertEqual(res.status_code, 200, msg="auth_type " + auth_type)

    def test_history_is_preserved(self):
        for auth_type in self.auth_types:
            res = httpx.get(
                url=self.test_server_url + auth_type,
                auth=httpx_ntlm.HttpNtlmAuth(
                    self.test_server_username, self.test_server_password
                ),
            )

            self.assertEqual(len(res.history), 2)
