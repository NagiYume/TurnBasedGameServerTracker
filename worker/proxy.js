export default {
    async fetch(request) {
        const origin = request.headers.get('Origin') || '*';

        if (request.method === 'OPTIONS') {
            return new Response(null, {
                headers: {
                    'Access-Control-Allow-Origin': origin,
                    'Access-Control-Allow-Methods': 'GET, OPTIONS',
                    'Access-Control-Allow-Headers': '*',
                    'Access-Control-Max-Age': '86400',
                },
            });
        }

        const target = new URL(request.url).searchParams.get('url');
        if (!target) {
            return new Response('Missing "url" parameter', { status: 400 });
        }

        try {
            const resp = await fetch(target, {
                headers: { 'User-Agent': 'HSR-Monitor/1.0' },
                redirect: 'follow',
            });

            const headers = new Headers(resp.headers);
            headers.set('Access-Control-Allow-Origin', origin);
            headers.delete('X-Frame-Options');

            return new Response(resp.body, {
                status: resp.status,
                statusText: resp.statusText,
                headers,
            });
        } catch (e) {
            return new Response('Proxy error: ' + e.message, {
                status: 502,
                headers: { 'Access-Control-Allow-Origin': origin },
            });
        }
    },
};
