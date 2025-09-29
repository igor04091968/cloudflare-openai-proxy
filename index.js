export default {
  async fetch(request) {
    const externalUrl = "https://api.openai.com";
    const url = new URL(request.url);
    const proxiedUrl = externalUrl + url.pathname + url.search;

    const proxiedRequest = new Request(proxiedUrl, {
      method: request.method,
      headers: request.headers,
      body: request.method !== "GET" && request.method !== "HEAD" ? request.body : null,
      redirect: 'follow'
    });

    try {
      const response = await fetch(proxiedRequest);
      return response;
    } catch (error) {
      return new Response(JSON.stringify({ error: error.message }), {
        status: 500,
        headers: { "Content-Type": "application/json" },
      });
    }
  },
};
