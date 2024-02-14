from __future__ import division, print_function, unicode_literals

__copyright__ = '''\
Copyright (C) m-click.aero GmbH

Permission to use, copy, modify, and/or distribute this software for any
purpose with or without fee is hereby granted, provided that the above
copyright notice and this permission notice appear in all copies.

THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
'''

import OpenSSL.crypto
import requests.adapters
import ssl
from urllib3.contrib.pyopenssl import PyOpenSSLContext

try:
    # For Python 3.6 and above, PROTOCOL_TLS chooses the highest protocol version
    # that both the client and server support.
    # This is the recommended method of selecting the SSL/TLS protocol version.
    default_ssl_protocol = ssl.PROTOCOL_TLS
except AttributeError:
    # Fallback for Python versions before 3.6 that might not have PROTOCOL_TLS,
    # but this case is increasingly unlikely as older versions of Python are phased out.
    # PROTOCOL_TLSv1_2 could be a more secure fallback than PROTOCOL_SSLv23,
    # as it does not allow older, insecure versions like SSLv2 or SSLv3.
    try:
        default_ssl_protocol = ssl.PROTOCOL_TLSv1_2
    except AttributeError:
        # If PROTOCOL_TLSv1_2 is also not available, as a last resort, fall back to PROTOCOL_SSLv23.
        # Be aware that using PROTOCOL_SSLv23 can be insecure due to the possibility of using SSLv2 or SSLv3,
        # so this should be avoided if at all possible.
        default_ssl_protocol = ssl.PROTOCOL_SSLv23


class CustomPyOpenSSLContext(PyOpenSSLContext):
    def set_certificate(self, cert):
        """Set the certificate for the SSL context."""
        self._ctx.use_certificate(OpenSSL.crypto.X509.from_cryptography(cert))

    def set_private_key(self, private_key):
        """Set the private key for the SSL context."""
        self._ctx.use_privatekey(OpenSSL.crypto.PKey.from_cryptography_key(private_key))

    def add_ca_certificates(self, ca_certs):
        """Add CA certificates to the SSL context."""
        for ca_cert in ca_certs:
            self._ctx.add_extra_chain_cert(OpenSSL.crypto.X509.from_cryptography(ca_cert))


def create_pyopenssl_sslcontext(pkcs12_data, pkcs12_password_bytes, ssl_protocol):
    from cryptography.hazmat.primitives.serialization import pkcs12
    private_key, cert, ca_certs = pkcs12.load_key_and_certificates(
        pkcs12_data, pkcs12_password_bytes
    )

    ssl_context = CustomPyOpenSSLContext(ssl_protocol)
    ssl_context.set_certificate(cert)
    if ca_certs:
        ssl_context.add_ca_certificates(ca_certs)
    ssl_context.set_private_key(private_key)

    return ssl_context


class Pkcs12Adapter(requests.adapters.HTTPAdapter):

    def __init__(self, *args, **kwargs):
        pkcs12_data = kwargs.pop('pkcs12_data', None)
        pkcs12_filename = kwargs.pop('pkcs12_filename', '')
        pkcs12_password = kwargs.pop('pkcs12_password', '')
        ssl_protocol = kwargs.pop('ssl_protocol', default_ssl_protocol)
        if pkcs12_data is None and pkcs12_filename is None:
            raise ValueError('Both arguments "pkcs12_data" and "pkcs12_filename" are missing')
        if pkcs12_data is not None and pkcs12_filename is not None:
            raise ValueError('Argument "pkcs12_data" conflicts with "pkcs12_filename"')
        if pkcs12_password is None:
            raise ValueError('Argument "pkcs12_password" is missing')
        if pkcs12_filename is not None:
            with open(pkcs12_filename, 'rb') as pkcs12_file:
                pkcs12_data = pkcs12_file.read()
        if isinstance(pkcs12_password, bytes):
            pkcs12_password_bytes = pkcs12_password
        else:
            pkcs12_password_bytes = str(pkcs12_password).encode('utf8')
        self.ssl_context = create_pyopenssl_sslcontext(pkcs12_data, pkcs12_password_bytes, ssl_protocol)
        super(Pkcs12Adapter, self).__init__(*args, **kwargs)

    def init_poolmanager(self, *args, **kwargs):
        if self.ssl_context:
            kwargs['ssl_context'] = self.ssl_context
        return super(Pkcs12Adapter, self).init_poolmanager(*args, **kwargs)

    def proxy_manager_for(self, *args, **kwargs):
        if self.ssl_context:
            kwargs['ssl_context'] = self.ssl_context
        return super(Pkcs12Adapter, self).proxy_manager_for(*args, **kwargs)


def request(*args, **kwargs):
    pkcs12_data = kwargs.pop('pkcs12_data', None)
    pkcs12_filename = kwargs.pop('pkcs12_filename', None)
    pkcs12_password = kwargs.pop('pkcs12_password', None)
    ssl_protocol = kwargs.pop('ssl_protocol', default_ssl_protocol)
    if pkcs12_data is None and pkcs12_filename is None and pkcs12_password is None:
        return requests.request(*args, **kwargs)
    if 'cert' in kwargs:
        raise ValueError('Argument "cert" conflicts with "pkcs12_*" arguments')
    with requests.Session() as session:
        pkcs12_adapter = Pkcs12Adapter(
            pkcs12_data=pkcs12_data,
            pkcs12_filename=pkcs12_filename,
            pkcs12_password=pkcs12_password,
            ssl_protocol=ssl_protocol,
        )
        session.mount('https://', pkcs12_adapter)
        return session.request(*args, **kwargs)


def delete(*args, **kwargs):
    return request('delete', *args, **kwargs)


def get(*args, **kwargs):
    kwargs.setdefault('allow_redirects', True)
    return request('get', *args, **kwargs)


def head(*args, **kwargs):
    kwargs.setdefault('allow_redirects', False)
    return request('head', *args, **kwargs)


def options(*args, **kwargs):
    kwargs.setdefault('allow_redirects', True)
    return request('options', *args, **kwargs)


def patch(*args, **kwargs):
    return request('patch', *args, **kwargs)


def post(*args, **kwargs):
    return request('post', *args, **kwargs)


def put(*args, **kwargs):
    return request('put', *args, **kwargs)
