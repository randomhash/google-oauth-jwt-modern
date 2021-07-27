import {createSign} from 'crypto';
import nodeFetch from 'node-fetch';

const GOOGLE_OAUTH2_URL = 'https://accounts.google.com/o/oauth2/token';

type Params = {
  email: string;
  scopes: string[];
  key: string;
  ttlMinutes?: number;
  delegationEmail?: string;
};

export type Token = {access_token: string; expires_in: number; token_type: string};
type Claims = {iss: string; scope: string; aud: string; exp: number; iat: number; sub?: string};

export function encodeJWT({email, scopes, key, ttlMinutes = 60, delegationEmail}: Params): string {
  const iat = Math.floor(new Date().getTime() / 1000);
  const exp = iat + Math.floor((ttlMinutes * 60 * 1000) / 1000);
  const claims: Claims = {
    iss: email,
    scope: scopes.join(' '),
    aud: GOOGLE_OAUTH2_URL,
    exp: exp,
    iat: iat,
  };

  if (delegationEmail) {
    claims.sub = delegationEmail;
  }

  const JWTHeader = Buffer.from(JSON.stringify({alg: 'RS256', typ: 'JWT'})).toString('base64');
  const JWTClaimSet = Buffer.from(JSON.stringify(claims)).toString('base64');
  const unsignedJWT = [JWTHeader, JWTClaimSet].join('.');

  const signedJWT = signJWT(key, unsignedJWT);

  return signedJWT;
}

function signJWT(key: string, unsignedJWT: string): string {
  try {
    const JWT_signature = createSign('RSA-SHA256').update(unsignedJWT).sign(key, 'base64');

    if (JWT_signature === '') {
      throw new Error('fail');
    }

    return [unsignedJWT, JWT_signature].join('.');
  } catch (e) {
    throw new Error('Failed to sign JWT, the key is probably invalid');
  }
}

export async function obtainToken(params: Params): Promise<Token> {
  const jwt = encodeJWT(params);

  return fetch<Token>(GOOGLE_OAUTH2_URL, {
    headers: {
      'Content-Type': 'application/json',
    },
    method: 'post',
    body: JSON.stringify({
      grant_type: 'urn:ietf:params:oauth:grant-type:jwt-bearer',
      assertion: jwt,
    }),
  });
}

async function fetch<T>(url: string, options: Parameters<typeof nodeFetch>[1]): Promise<T> {
  const res = await nodeFetch(url, options);

  return res.json();
}
