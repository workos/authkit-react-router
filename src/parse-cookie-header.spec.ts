import { parseCookieHeader } from './parse-cookie-header.js';

describe('parseCookieHeader', () => {
  it('returns {} for null/undefined/empty', () => {
    expect(parseCookieHeader(null)).toEqual({});
    expect(parseCookieHeader(undefined)).toEqual({});
    expect(parseCookieHeader('')).toEqual({});
  });

  it('parses a single cookie', () => {
    expect(parseCookieHeader('foo=bar')).toEqual({ foo: 'bar' });
  });

  it('parses multiple cookies', () => {
    expect(parseCookieHeader('foo=bar; baz=qux')).toEqual({ foo: 'bar', baz: 'qux' });
  });

  it('trims whitespace around name and value', () => {
    expect(parseCookieHeader('  foo  =  bar  ;  baz=qux  ')).toEqual({ foo: 'bar', baz: 'qux' });
  });

  it('handles duplicate names with last-write-wins', () => {
    expect(parseCookieHeader('foo=first; foo=second')).toEqual({ foo: 'second' });
    expect(parseCookieHeader('foo=a; foo=b; foo=c')).toEqual({ foo: 'c' });
  });

  it('skips empty pairs', () => {
    expect(parseCookieHeader(';;')).toEqual({});
    expect(parseCookieHeader('; ; foo=bar ;')).toEqual({ foo: 'bar' });
  });

  it('skips pairs with no equals sign', () => {
    expect(parseCookieHeader('justaname; foo=bar')).toEqual({ foo: 'bar' });
  });

  it('skips pairs with empty name', () => {
    expect(parseCookieHeader('=value; foo=bar')).toEqual({ foo: 'bar' });
    expect(parseCookieHeader('  =value')).toEqual({});
  });

  it('allows empty values', () => {
    expect(parseCookieHeader('foo=; bar=baz')).toEqual({ foo: '', bar: 'baz' });
  });

  it('preserves values containing equals signs', () => {
    expect(parseCookieHeader('token=a=b=c')).toEqual({ token: 'a=b=c' });
  });

  it('does not URL-decode values', () => {
    expect(parseCookieHeader('encoded=a%20b')).toEqual({ encoded: 'a%20b' });
  });

  it('handles sealed-cookie-like values', () => {
    const sealed = 'Fe26.2**abc123.def456';
    expect(parseCookieHeader(`__Host-wos-auth-verifier=${sealed}`)).toEqual({
      '__Host-wos-auth-verifier': sealed,
    });
  });

  it('prefers later value when both __Host- prefixed duplicates present', () => {
    expect(
      parseCookieHeader('__Host-wos-auth-verifier=A; __Host-wos-auth-verifier=B'),
    ).toEqual({ '__Host-wos-auth-verifier': 'B' });
  });
});
