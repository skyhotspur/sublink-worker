import { describe, it, expect } from 'vitest';
import yaml from 'js-yaml';
import { createApp, resolveSubscriptionTarget } from '../src/app/createApp.jsx';
import { MemoryKVAdapter } from '../src/adapters/kv/memoryKv.js';
import { ProxyParser } from '../src/parsers/ProxyParser.js';
import { convertYamlProxyToObject } from '../src/parsers/convertYamlProxyToObject.js';
import { convertSurgeProxyToObject } from '../src/parsers/convertSurgeProxyToObject.js';
import { SingboxConfigBuilder } from '../src/builders/SingboxConfigBuilder.js';
import { ClashConfigBuilder } from '../src/builders/ClashConfigBuilder.js';
import { SurgeConfigBuilder } from '../src/builders/SurgeConfigBuilder.js';
import { encodeBase64, decodeBase64 } from '../src/utils.js';

const createTestApp = () => createApp({
    kv: new MemoryKVAdapter(),
    assetFetcher: null,
    logger: console,
    config: { configTtlSeconds: 60, shortLinkTtlSeconds: null }
});

describe('share links without query string keep their name', () => {
    it('trojan://pw@host:port#name', async () => {
        const proxy = await ProxyParser.parse('trojan://secret@example.com:443#%E9%A6%99%E6%B8%AF%2001');
        expect(proxy.tag).toBe('香港 01');
        expect(proxy.server).toBe('example.com');
        expect(proxy.server_port).toBe(443);
        expect(proxy.password).toBe('secret');
    });

    it('vless with trailing slash before query', async () => {
        const proxy = await ProxyParser.parse('vless://11111111-2222-3333-4444-555555555555@example.com:443/?security=tls&sni=a.com#JP');
        expect(proxy.tag).toBe('JP');
        expect(proxy.server_port).toBe(443);
        expect(proxy.tls.server_name).toBe('a.com');
    });

    it('hysteria2 without query', async () => {
        const proxy = await ProxyParser.parse('hysteria2://pass@1.2.3.4:8443#HY');
        expect(proxy.tag).toBe('HY');
        expect(proxy.server_port).toBe(8443);
    });
});

describe('SOCKS5 share links', () => {
    it('parses plain socks5://user:pass@host:port#tag', async () => {
        const proxy = await ProxyParser.parse('socks5://alice:p%40ss@10.0.0.1:1080#Home');
        expect(proxy).toMatchObject({
            type: 'socks', tag: 'Home', server: '10.0.0.1', server_port: 1080,
            version: '5', username: 'alice', password: 'p@ss'
        });
    });

    it('parses v2rayN style socks://base64(user:pass)@host:port', async () => {
        const proxy = await ProxyParser.parse(`socks://${encodeBase64('bob:secret')}@[2001:db8::1]:7890#v6`);
        expect(proxy).toMatchObject({ server: '2001:db8::1', server_port: 7890, username: 'bob', password: 'secret', tag: 'v6' });
    });

    it('parses unauthenticated socks and defaults tag to host:port', async () => {
        const proxy = await ProxyParser.parse('socks5://127.0.0.1:1080');
        expect(proxy.tag).toBe('127.0.0.1:1080');
        expect(proxy.username).toBeUndefined();
    });
});

describe('socks5/http from Clash YAML and Surge subscriptions', () => {
    it('converts Clash socks5/http proxies', () => {
        expect(convertYamlProxyToObject({ name: 's', type: 'socks5', server: 'a', port: 1080, username: 'u', password: 'p', udp: true }))
            .toMatchObject({ type: 'socks', server_port: 1080, username: 'u', password: 'p', udp: true });
        expect(convertYamlProxyToObject({ name: 'h', type: 'http', server: 'b', port: 443, tls: true, sni: 'b.com' }))
            .toMatchObject({ type: 'http', server_port: 443, tls: { enabled: true, server_name: 'b.com' } });
    });

    it('converts Surge http/https/socks5 lines with positional auth', () => {
        expect(convertSurgeProxyToObject('H = http, 1.1.1.1, 8080, user, pass'))
            .toMatchObject({ type: 'http', server_port: 8080, username: 'user', password: 'pass' });
        expect(convertSurgeProxyToObject('HS = https, h.com, 443, username=u, password=p'))
            .toMatchObject({ type: 'http', username: 'u', password: 'p', tls: { enabled: true } });
        expect(convertSurgeProxyToObject('S = socks5, 2.2.2.2, 1080'))
            .toMatchObject({ type: 'socks', server_port: 1080 });
    });
});

describe('socks/http output for every client', () => {
    it('sing-box emits socks outbound and never a TLS socks', async () => {
        const builder = new SingboxConfigBuilder('socks5://u:p@10.0.0.1:1080#S5', [], [], undefined, 'en-US', 'test');
        await builder.build();
        const socks = builder.config.outbounds.find(o => o.tag === 'S5');
        expect(socks).toMatchObject({ type: 'socks', server: '10.0.0.1', server_port: 1080, version: '5', username: 'u', password: 'p' });
        expect(socks).not.toHaveProperty('tls');

        expect(builder.convertProxy({ type: 'socks', tag: 'x', server: 'a', server_port: 1, tls: { enabled: true } })).toBeNull();
    });

    it('sing-box 1.11 skips anytls (unsupported before 1.12) but keeps other nodes', async () => {
        const input = 'anytls://pw@a.example.com:443?sni=a.example.com#AT\nsocks5://u:p@10.0.0.1:1080#S5';
        const legacy = new SingboxConfigBuilder(input, [], [], undefined, 'en-US', 'test', false, false, undefined, undefined, '1.11');
        await legacy.build();
        expect(legacy.config.outbounds.some(o => o.type === 'anytls')).toBe(false);
        expect(legacy.config.outbounds.some(o => o.tag === 'S5')).toBe(true);
        const groupMembers = legacy.config.outbounds.flatMap(o => o.outbounds || []);
        expect(groupMembers).not.toContain('AT');

        const modern = new SingboxConfigBuilder(input, [], [], undefined, 'en-US', 'test', false, false, undefined, undefined, '1.12');
        await modern.build();
        expect(modern.config.outbounds.some(o => o.type === 'anytls' && o.tag === 'AT')).toBe(true);
    });

    it('Clash emits socks5 proxy', async () => {
        const builder = new ClashConfigBuilder('socks5://u:p@10.0.0.1:1080#S5', [], [], undefined, 'en-US', 'test');
        await builder.build();
        const config = yaml.load(builder.formatConfig());
        expect(config.proxies.find(p => p.name === 'S5')).toMatchObject({
            type: 'socks5', server: '10.0.0.1', port: 1080, username: 'u', password: 'p', udp: true
        });
    });

    it('Surge emits socks5 line', async () => {
        const builder = new SurgeConfigBuilder('socks5://u:p@10.0.0.1:1080#S5', [], [], undefined, 'en-US', 'test');
        await builder.build();
        expect(builder.formatConfig()).toContain('S5 = socks5, 10.0.0.1, 1080, u, p, udp-relay=true');
    });

    it('Surge round-trips http with TLS', () => {
        const builder = new SurgeConfigBuilder('', [], [], undefined, 'en-US', 'test');
        const line = builder.convertProxy({ type: 'http', tag: 'H', server: 'h.com', server_port: 443, username: 'u', password: 'p', tls: { enabled: true, server_name: 'h.com' } });
        expect(line).toBe('H = https, h.com, 443, u, p, sni=h.com');
        expect(convertSurgeProxyToObject(line)).toMatchObject({ type: 'http', username: 'u', password: 'p', tls: { enabled: true } });
    });
});

describe('resolveSubscriptionTarget', () => {
    it.each([
        ['sing-box/1.12.0', 'singbox'],
        ['SFA/1.11.4 (sing-box 1.11.4)', 'singbox'],
        ['SFI/1.12.0', 'singbox'],
        ['ClashMetaForAndroid/2.11.0.Meta', 'clash'],
        ['clash-verge/v2.2.3', 'clash'],
        ['mihomo/1.19.0', 'clash'],
        ['Stash/3.0.0 Clash/1.9.0', 'clash'],
        ['FlClash/v0.8.80', 'clash'],
        ['Surge iOS/3000', 'surge'],
        ['Surge Mac/2500', 'surge'],
        ['Shadowrocket/2070 CFNetwork/1494', 'xray'],
        ['v2rayN/7.0', 'xray'],
        ['Mozilla/5.0', 'xray'],
        [undefined, 'xray']
    ])('UA %s -> %s', (ua, expected) => {
        expect(resolveSubscriptionTarget(undefined, ua)).toBe(expected);
    });

    it('explicit target overrides UA', () => {
        expect(resolveSubscriptionTarget('clash', 'sing-box/1.12.0')).toBe('clash');
        expect(resolveSubscriptionTarget('SING-BOX', 'Surge iOS')).toBe('singbox');
        expect(resolveSubscriptionTarget('base64', 'clash-verge')).toBe('xray');
    });

    it('unknown target falls back to UA detection', () => {
        expect(resolveSubscriptionTarget('nope', 'mihomo/1.0')).toBe('clash');
    });
});

describe('/sub universal endpoint', () => {
    const link = 'ss://YWVzLTEyOC1nY206dGVzdA@example.com:8388#SS';
    const query = `config=${encodeURIComponent(link)}`;

    it('serves sing-box JSON to sing-box clients', async () => {
        const res = await createTestApp().request(`http://localhost/sub?${query}`, { headers: { 'User-Agent': 'sing-box/1.12.0' } });
        expect(res.status).toBe(200);
        expect(res.headers.get('content-type')).toContain('application/json');
        const body = await res.json();
        expect(body.outbounds.some(o => o.tag === 'SS')).toBe(true);
    });

    it('serves Clash YAML to Clash clients', async () => {
        const res = await createTestApp().request(`http://localhost/sub?${query}`, { headers: { 'User-Agent': 'clash.meta' } });
        expect(res.headers.get('content-type')).toContain('text/yaml');
        expect(yaml.load(await res.text()).proxies.some(p => p.name === 'SS')).toBe(true);
    });

    it('serves Surge config to Surge', async () => {
        const res = await createTestApp().request(`http://localhost/sub?${query}`, { headers: { 'User-Agent': 'Surge iOS/3000' } });
        expect(await res.text()).toContain('SS = ss, example.com, 8388');
    });

    it('serves base64 list to unknown clients and honours ?target=', async () => {
        const app = createTestApp();
        const res = await app.request(`http://localhost/sub?${query}`, { headers: { 'User-Agent': 'Shadowrocket/2070' } });
        expect(decodeBase64(await res.text())).toBe(link);

        const forced = await app.request(`http://localhost/sub?${query}&target=clash`, { headers: { 'User-Agent': 'Shadowrocket/2070' } });
        expect(forced.headers.get('content-type')).toContain('text/yaml');
    });

    it('/u/:code short link redirects to /sub and /resolve understands it', async () => {
        const app = createTestApp();
        const created = await app.request(`http://localhost/shorten-v2?url=${encodeURIComponent(`http://localhost/sub?${query}`)}&shortCode=all`);
        expect(await created.text()).toBe('all');

        const redirect = await app.request('http://localhost/u/all');
        expect(redirect.status).toBe(302);
        expect(redirect.headers.get('location')).toBe(`http://localhost/sub?${query}`);

        const resolved = await app.request(`http://localhost/resolve?url=${encodeURIComponent('http://localhost/u/all')}`);
        expect((await resolved.json()).originalUrl).toBe(`http://localhost/sub?${query}`);
    });
});
