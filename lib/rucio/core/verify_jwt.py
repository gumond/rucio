#!/usr/bin/env python
"""
 Copyright European Organization for Nuclear Research (CERN)

 Licensed under the Apache License, Version 2.0 (the "License");
 You may not use this file except in compliance with the License.
 You may obtain a copy of the License at
                       http://www.apache.org/licenses/LICENSE-2.0

 Authors:
 - Jaroslav Guenther, <jaroslav.guenther@cern.ch>, 2019

"""

import sys
import traceback
import requests
from jose import jwt


def get_issuer_public_keys(issuer, request_config=False):
    """
    Extracts the dictionary of public keys from the issuer URL unless known already.

    :param issuer: url string of the issuer
    :param request_config: If True, triggers a lookup of public_keys via a universal URL path same for all Identity Providers.

    :returns: dictionary of issuers public keys. Raises an exception otherwise.

    """
    # TO-BE-DONE: check for known public_keys and issuers should be made against a DB
    # TO-BE-DONE: in case public keys stop being valid (to-be-done) daemon updating this information (every few hours ?) needs to be implemented
    known_public_keys = {'https://iam.extreme-datacloud.eu/': {"keys": [{"kty": "RSA", "e": "AQAB", "kid": "rsa1", "n": "\
                         xWV7EnSAhAxR7Pq8SkWRzzNqdJCiV8CczLle93subSzpTtT_i_s7lXNha2Jee78Yp2aF6yYJ8gUTAlAr2y6FmHG6qElo__mj\
                         6beLFq4Q1qPllzuCDRA7b3Gc8Y1mv96Y4jCQ8XEuDLnvs-EyKF9d05Kl0tXnN5h8nv0OrDnjItE"}]}}

    if not request_config:
        if issuer in known_public_keys:
            if known_public_keys[issuer]:
                return known_public_keys[issuer]
            else:
                return get_issuer_public_keys(issuer, True)
        else:
            return get_issuer_public_keys(issuer, True)
    else:
        config_res = requests.get(issuer + ".well-known/openid-configuration")
        if config_res:
            jwks_uri = config_res.json()['jwks_uri']
            resks = requests.get(jwks_uri)
            if resks:
                return resks.json()
            else:
                raise Exception("Unable to extract public keys from issuer's endpoint '%s'" % jwks_uri)
        else:
            raise Exception("Unable to extract OpenID Configuration from issuer's endpoint '%s'" % (issuer + ".well-known/openid-configuration"))


class InvalidJWT(Exception):
    def __init__(self, details):
        super(Exception, self).__init__('Invalid JSON Web Token: ' + details)


def get_jwt_issuer(json_web_token):
    """
    Decodes the unverified claims of the JWT to extract and return the issuers domain url string.

    :param json_web_token: JSON Web Token string

    :returns: url string of the issuer. Raises an exception otherwise.

    """
    try:
        headers = jwt.get_unverified_claims(json_web_token)
    except:
        raise InvalidJWT(traceback.format_exc())
    if not headers:
        raise InvalidJWT('missing claims to recognise issuer.')
    try:
        return headers['iss']
    except KeyError:
        raise InvalidJWT('missing claims to recognise issuer.')


def get_jwt_kid(json_web_token):
    """
    Decodes the unverified headers of the JWT to extract and return the key ID (kid).

    :param json_web_token: JSON Web Token string

    :returns: kid string. Raises an exception otherwise.

    """
    try:
        headers = jwt.get_unverified_header(json_web_token)
    except:
        raise InvalidJWT(traceback.format_exc())
    if not headers:
        raise InvalidJWT('missing headers.')
    try:
        return headers['kid']
    except KeyError:
        raise InvalidJWT('missing kid.')


def get_jwk_matching_jwt_kid(jwt_kid, issuer_public_keys):
    """
    Loops through the public key set from the issuer and looks for the key ID (kid)
    which corresponds to the kid in the headers of the JWT which we intend to verify.

    :param jwt_kid: key ID of the JSON Web Token which we attempt to verify
    :param issuer_public_keys: dict of public keys provided by the issuer

    :returns: dictionary containing issuers public_key which corresponds to the JWT.
              Raises an exception otherwise.

    """
    for jwk in issuer_public_keys.get('keys'):
        if jwk.get('kid') == jwt_kid:
            return jwk
    raise InvalidJWT('JSON web token kid not found among issuer kid(s).')


def verify_jwt(json_web_token):
    """
    Verifies signature and validity of a JSON Web Token. First extracts the issuer,
    signing algorithm and key ID from the unverified token headers. Later, verifies the validity
    and attempts to decode the token information providing the public_key is available from the issuer
    (will try to request public_keys from the issuer if the issuer, unless the issuer is not known already).

    :param json_web_token: the JWT string to verify

    :returns: The dict representation of the claims set,
              assuming the signature is valid and all
              requested data validation passes. Exception otherwise

    """
    issuer = get_jwt_issuer(json_web_token)
    issuer_public_keys = get_issuer_public_keys(issuer)
    jwt_kid = get_jwt_kid(json_web_token)
    jwt_key = get_jwk_matching_jwt_kid(jwt_kid, issuer_public_keys)

    # verify signature & validity
    try:
        return jwt.decode(json_web_token, jwt_key)
    except:
        raise InvalidJWT(traceback.format_exc())


def main():
    """
    Prototype of JWT verification; checks:
    - signature of the IDP (Identity Provider)
    - lifetime validity

    Needs a valid IDP token (otherwise runs only few tests):

    > python verify_jwt.py <valid_token>

    Terminal output:

    Test: catching invalid signature:
    ---------------------------------
    ... passed

    Test: catching expired token:
    -----------------------------
    ... passed

    Test: catching decoding token claims:
    -----------------------------
    ... passed

    Test: valid token decoding:
    -----------------------------
    {u'iss': u'https://iam.extreme-datacloud.eu/', u'iat': 1559828644, u'jti': u'64b1f432-5788-4230-914e-4cf37c046238', u'sub': u'b3127dc7-2be3-417b-9647-6bf61238ad01', u'exp': 1559832244}
    The JWT is valid!
    """

    try:
        print("\nTest: catching invalid signature:")
        print("---------------------------------")
        verify_jwt('eyJraWQiOiJyc2ExIiwiYWxnIjoiUlMyNTYifQ.eyJzdWIiOiJiMzEyN2RjNy0yYmUzLTQx'
                   + 'N2ItOTY0Ny02YmY2MTIzOGFkMDEiLCJpc3MiOiJodHRwczpcL1wvaWFtLmV4dHJlbWUtZGF'
                   + '0YWNsb3VkLmV1XC8iLCJleHAiOjE1NTkxMzg0MzEsImlhdCI6MTU1OTEzNDgzMSwianRpIj'
                   + 'oiYjE1MDExYWItZGFiYy00ODg2LTgxM2ItNjMxOTU0ZDdmMzIxIn0.kx8rGARIL-mVD0MDJ'
                   + 'otVUuhNisUe3il_pGMoVYTtmuFRwbdgJ6hyG7hqUVobwEdjEEi4kwKfVDr_VYafZBt-XmLM'
                   + 'dFTq71FQIbrfpvbRAk349vScZLWTq5DviEnxRI2wqbT3xl_ZoXrgTIwckciS9bBzqf77H57vQK6iGU5mSzq')

    except InvalidJWT:
        traceprint = traceback.format_exc()
        if 'JWTError: Signature verification failed.' in traceprint:
            print('... passed')
            pass
        else:
            traceback.print_exc()
            raise Exception

    try:
        print("\nTest: catching expired token:")
        print("-----------------------------")
        verify_jwt('eyJraWQiOiJyc2ExIiwiYWxnIjoiUlMyNTYifQ.eyJzdWIiOiJiMzEyN2RjNy0yYmUzLTQx'
                   + 'N2ItOTY0Ny02YmY2MTIzOGFkMDEiLCJpc3MiOiJodHRwczpcL1wvaWFtLmV4dHJlbWUtZGF'
                   + '0YWNsb3VkLmV1XC8iLCJleHAiOjE1NTkxMzg0MzEsImlhdCI6MTU1OTEzNDgzMSwianRpIj'
                   + 'oiYjE1MDExYWItZGFiYy00ODg2LTgxM2ItNjMxOTU0ZDdmMzIxIn0.kx8rGARIL-mVD0MDJ'
                   + 'otVUuhNisUe3il_pGMoVYTtmuFRwbdgJ6hyG7hqUVobwEdjEEi4kwKfVDr_VYafZBt-XmLM'
                   + 'dFTq71FQIbrfpvbRAk349vScZLWTq5DviEnxRI2wqBT3xl_ZoXrgTIwckciS9bBzqf77H57vQK6iGU5mSzQ')
    except InvalidJWT:
        traceprint = traceback.format_exc()
        if 'ExpiredSignatureError: Signature has expired.' in traceprint:
            print('... passed')
            pass
        else:
            traceback.print_exc()
            raise Exception

    try:
        print("\nTest: catching decoding token claims:")
        print("-----------------------------")
        verify_jwt('eyJrawQiOiJyc2ExIiwiYWxnIjoiUlMyNTYifQ.eyJzdWIiOiJiMzEyN2RjNy0yYmUzLTQx'
                   + 'N2ItOTY0Ny02YmY2MTIzOGFkMDEiLCJpc3MiOiJodHRwczpcL1wvaWFtLmV4dHJlbWUtZGF'
                   + '0YWNsb3VkLmV1XC8iLCJleHAiOjE1NTkxMzg0MzEsImlhdCI6MTU1OTEzNDgzMSwianRpIj'
                   + 'oiYjE1MDExYWItZGFiYy00ODg2LTgxM2ItNjMxOTU0ZDdmMzIxIn0.kx8rGARIL-mVD0MDJ'
                   + 'otVUuhNisUe3il_pGMoVYTtmuFRwbdgJ6hyG7hqUVobwEdjEEi4kwKfVDr_VYafZBt-XmLM'
                   + 'dFTq71FQIbrfpvbRAk349vScZLWTq5DviEnxRI2wqBT3xl_ZoXrgTIwckciS9bBzqf77H57vQK6iGU5mSzQ')
    except InvalidJWT:
        traceprint = traceback.format_exc()
        if 'JWTError: Error decoding token claims.' in traceprint:
            print('... passed')
            pass
        else:
            traceback.print_exc()
            raise Exception

    # real JWT validation
    if len(sys.argv) < 2:
        print('\n---------------------------------------------------------')
        print('No JWT provided ! Please provide a JWT as script argument')
        return

    jwt = sys.argv[1]

    try:
        print("\nTest: valid token decoding:")
        print("-----------------------------")
        res = verify_jwt(jwt)
        print(res)
    except InvalidJWT:
        traceback.print_exc()
        print('The JWT is not valid!')
    else:
        print('The JWT is valid!')


if __name__ == '__main__':
    main()




