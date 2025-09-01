import { CONFIG, createConfig } from './config/index.js';
import { transformPath } from './config/platforms.js';

/**
 * Monitors performance metrics during request processing
 */
class PerformanceMonitor {
  /**
   * Initializes a new performance monitor
   */
  constructor() {
    this.startTime = Date.now();
    this.marks = new Map();
  }

  /**
   * Marks a timing point with the given name
   * @param {string} name - The name of the timing mark
   */
  mark(name) {
    if (this.marks.has(name)) {
      console.warn(`Mark with name ${name} already exists.`);
    }
    this.marks.set(name, Date.now() - this.startTime);
  }

  /**
   * Returns all collected metrics
   * @returns {Object.<string, number>} Object containing name-timestamp pairs
   */
  getMetrics() {
    return Object.fromEntries(this.marks.entries());
  }
}

/**
 * Detects if a request is a container registry operation
 * @param {Request} request - The incoming request object
 * @param {URL} url - Parsed URL object
 * @returns {boolean} True if this is a container registry operation
 */
function isDockerRequest(request, url) {
  // Check for container registry API endpoints
  if (url.pathname.startsWith('/v2/')) {
    return true;
  }

  // Check for Docker-specific User-Agent
  const userAgent = request.headers.get('User-Agent') || '';
  if (userAgent.toLowerCase().includes('docker/')) {
    return true;
  }

  // Check for Docker-specific Accept headers
  const accept = request.headers.get('Accept') || '';
  if (
    accept.includes('application/vnd.docker.distribution.manifest') ||
    accept.includes('application/vnd.oci.image.manifest') ||
    accept.includes('application/vnd.docker.image.rootfs.diff.tar.gzip')
  ) {
    return true;
  }

  return false;
}

/**
 * Detects if a request is a Git operation
 * @param {Request} request - The incoming request object
 * @param {URL} url - Parsed URL object
 * @returns {boolean} True if this is a Git operation
 */
function isGitRequest(request, url) {
  // Check for Git-specific endpoints
  if (url.pathname.endsWith('/info/refs')) {
    return true;
  }

  if (url.pathname.endsWith('/git-upload-pack') || url.pathname.endsWith('/git-receive-pack')) {
    return true;
  }

  // Check for Git user agents (more comprehensive check)
  const userAgent = request.headers.get('User-Agent') || '';
  if (userAgent.includes('git/') || userAgent.startsWith('git/')) {
    return true;
  }

  // Check for Git-specific query parameters
  if (url.searchParams.has('service')) {
    const service = url.searchParams.get('service');
    return service === 'git-upload-pack' || service === 'git-receive-pack';
  }

  // Check for Git-specific content types
  const contentType = request.headers.get('Content-Type') || '';
  if (contentType.includes('git-upload-pack') || contentType.includes('git-receive-pack')) {
    return true;
  }

  return false;
}

/**
 * Check if the request is for an AI inference provider
 * @param {Request} request - The incoming request object
 * @param {URL} url - Parsed URL object
 * @returns {boolean} True if this is an AI inference request
 */
function isAIInferenceRequest(request, url) {
  // Check for AI inference provider paths (ip/{provider}/...)
  if (url.pathname.startsWith('/ip/')) {
    return true;
  }

  // Check for common AI inference API endpoints
  const aiEndpoints = [
    '/v1/chat/completions',
    '/v1/completions',
    '/v1/messages',
    '/v1/predictions',
    '/v1/generate',
    '/v1/embeddings',
    '/openai/v1/chat/completions'
  ];

  if (aiEndpoints.some(endpoint => url.pathname.includes(endpoint))) {
    return true;
  }

  // Check for AI-specific content types
  const contentType = request.headers.get('Content-Type') || '';
  if (contentType.includes('application/json') && request.method === 'POST') {
    // Additional check for common AI inference patterns in URL
    if (
      url.pathname.includes('/chat/') ||
      url.pathname.includes('/completions') ||
      url.pathname.includes('/generate') ||
      url.pathname.includes('/predict')
    ) {
      return true;
    }
  }

  return false;
}

/**
 * Validates API token if security is enabled
 * @param {Request} request - The incoming request object
 * @param {import('./config/index.js').ApplicationConfig} config - Configuration object
 * @returns {{valid: boolean, error?: string, status?: number}} Token validation result
 */
function validateToken(request, config = CONFIG) {
  if (!config.SECURITY.SECRET_TOKEN) {
    // If no secret token is configured, allow access
    return { valid: true };
  }

  const authHeader = request.headers.get('Authorization');
  const customToken = request.headers.get('X-Xget-Api-Key');

  // Check Bearer token
  if (authHeader && authHeader.startsWith('Bearer ')) {
    const token = authHeader.slice(7);
    if (token === config.SECURITY.SECRET_TOKEN) {
      return { valid: true };
    }
  }

  // Check custom header
  if (customToken) {
    if (customToken === config.SECURITY.SECRET_TOKEN) {
      return { valid: true };
    }
  }

  // Check query parameter for GET requests
  if (request.method === 'GET' && new URL(request.url).searchParams.get('api_key') === config.SECURITY.SECRET_TOKEN) {
    return { valid: true };
  }

  return { valid: false, error: 'Invalid API key', status: 401 };
}

/**
 * Validates incoming requests against security rules
 * @param {Request} request - The incoming request object
 * @param {URL} url - Parsed URL object
 * @param {import('./config/index.js').ApplicationConfig} config - Configuration object
 * @returns {{valid: boolean, error?: string, status?: number}} Validation result
 */
function validateRequest(request, url, config = CONFIG) {
  // Validate API token first
  const tokenValidation = validateToken(request, config);
  if (!tokenValidation.valid) {
    return tokenValidation;
  }

  // Allow POST method for Git, Docker, and AI inference operations
  const isGit = isGitRequest(request, url);
  const isDocker = isDockerRequest(request, url);
  const isAI = isAIInferenceRequest(request, url);

  const allowedMethods =
    isGit || isDocker || isAI
      ? ['GET', 'HEAD', 'POST', 'PUT', 'PATCH']
      : config.SECURITY.ALLOWED_METHODS;

  if (!allowedMethods.includes(request.method)) {
    return { valid: false, error: 'Method not allowed', status: 405 };
  }

  if (url.pathname.length > config.SECURITY.MAX_PATH_LENGTH) {
    return { valid: false, error: 'Path too long', status: 414 };
  }

  return { valid: true };
}

/**
 * Creates a standardized error response
 * @param {string} message - Error message
 * @param {number} status - HTTP status code
 * @param {boolean} includeDetails - Whether to include detailed error information
 * @param {Request} request - The incoming request object
 * @param {import('./config/index.js').ApplicationConfig} config - Configuration object
 * @returns {Response} Error response
 */
function createErrorResponse(message, status, includeDetails = false, request, config = CONFIG) {
  const errorBody = includeDetails
    ? JSON.stringify({ error: message, status, timestamp: new Date().toISOString() })
    : message;

  return new Response(errorBody, {
    status,
    headers: addSecurityHeaders(
      new Headers({
        'Content-Type': includeDetails ? 'application/json' : 'text/plain'
      }),
      request,
      config
    )
  });
}

/**
 * Adds CORS headers based on configuration
 * @param {Headers} headers - Headers object to modify
 * @param {Request} request - The incoming request object
 * @param {import('./config/index.js').ApplicationConfig} config - Configuration object
 * @returns {Headers} Modified headers object with CORS headers
 */
function addCorsHeaders(headers, request, config = CONFIG) {
  const origin = request.headers.get('Origin');
  const allowedOrigins = config.SECURITY.ALLOWED_ORIGINS;

  if (allowedOrigins.includes('*')) {
    headers.set('Access-Control-Allow-Origin', '*');
  } else if (origin && allowedOrigins.includes(origin)) {
    headers.set('Access-Control-Allow-Origin', origin);
  } else if (origin) {
    headers.set('Access-Control-Allow-Origin', 'null'); // Not allowed origin
  }

  headers.set('Access-Control-Allow-Methods', config.SECURITY.ALLOWED_METHODS.join(', '));
  headers.set('Access-Control-Allow-Headers', 'Authorization, X-Xget-Api-Key, Content-Type');
  headers.set('Access-Control-Max-Age', '86400'); // 24 hours

  return headers;
}

/**
 * Handles CORS preflight requests
 * @param {Request} request - The incoming request object
 * @param {import('./config/index.js').ApplicationConfig} config - Configuration object
 * @returns {Response|null} Preflight response or null if not applicable
 */
function handleCorsPreflight(request, config = CONFIG) {
  if (request.method === 'OPTIONS') {
    const response = new Response(null, { status: 200, headers: new Headers() });
    addCorsHeaders(response.headers, request, config);
    return response;
  }
  return null;
}

/**
 * Adds security headers to the response
 * @param {Headers} headers - Headers object to modify
 * @param {Request} request - The incoming request object for CORS
 * @param {import('./config/index.js').ApplicationConfig} config - Configuration object
 * @returns {Headers} Modified headers object
 */
function addSecurityHeaders(headers, request, config = CONFIG) {
  headers.set('Strict-Transport-Security', 'max-age=31536000; includeSubDomains; preload');
  headers.set('X-Frame-Options', 'DENY');
  headers.set('X-XSS-Protection', '1; mode=block');
  headers.set('Referrer-Policy', 'strict-origin-when-cross-origin');
  // 仅当未显式设置 CSP 时，才应用默认 CSP，避免覆盖需要内联样式的 HTML 页
  if (!headers.has('Content-Security-Policy')) {
    headers.set('Content-Security-Policy', "default-src 'none'; img-src 'self'; script-src 'none'");
  }
  headers.set('Permissions-Policy', 'interest-cohort=()');
  addCorsHeaders(headers, request, config);
  return headers;
}

/**
 * Parses Docker WWW-Authenticate header
 * @param {string} authenticateStr - The WWW-Authenticate header value
 * @returns {{realm: string, service: string}} Parsed authentication info
 */
function parseAuthenticate(authenticateStr) {
  // sample: Bearer realm="https://auth.ipv6.docker.com/token",service="registry.docker.io"
  const re = /(?<=\=")(?:\\.|[^"\\])*(?=")/g;
  const matches = authenticateStr.match(re);
  if (matches == null || matches.length < 2) {
    throw new Error(`invalid Www-Authenticate Header: ${authenticateStr}`);
  }
  return {
    realm: matches[0],
    service: matches[1]
  };
}

/**
 * Fetches authentication token from container registry
 * @param {{realm: string, service: string}} wwwAuthenticate - Authentication info
 * @param {string} scope - The scope for the token
 * @param {string} authorization - Authorization header value
 * @returns {Promise<Response>} Token response
 */
async function fetchToken(wwwAuthenticate, scope, authorization) {
  const url = new URL(wwwAuthenticate.realm);
  if (wwwAuthenticate.service.length) {
    url.searchParams.set('service', wwwAuthenticate.service);
  }
  if (scope) {
    url.searchParams.set('scope', scope);
  }
  const headers = new Headers();
  if (authorization) {
    headers.set('Authorization', authorization);
  }
  return await fetch(url, { method: 'GET', headers: headers });
}

/**
 * Creates unauthorized response for container registry
 * @param {URL} url - Request URL
 * @returns {Response} Unauthorized response
 */
function responseUnauthorized(url) {
  const headers = new Headers();
  headers.set('WWW-Authenticate', `Bearer realm="https://${url.hostname}/v2/auth",service="Xget"`);
  return new Response(JSON.stringify({ message: 'UNAUTHORIZED' }), {
    status: 401,
    headers: headers
  });
}

/**
 * Handles incoming requests with caching, retries, and security measures
 * @param {Request} request - The incoming request
 * @param {Object} env - Environment variables
 * @param {ExecutionContext} ctx - Cloudflare Workers execution context
 * @returns {Promise<Response>} The response object
 */
async function handleRequest(request, env, ctx) {
  try {
    // Create config with environment variable overrides
    const config = env ? createConfig(env) : CONFIG;
    const url = new URL(request.url);
    const isDocker = isDockerRequest(request, url);

    // Handle CORS preflight requests
    const corsResponse = handleCorsPreflight(request, config);
    if (corsResponse) {
      return corsResponse;
    }

    const monitor = new PerformanceMonitor();

    // Handle Docker API version check
    if (isDocker && (url.pathname === '/v2/' || url.pathname === '/v2')) {
      const headers = new Headers({
        'Docker-Distribution-Api-Version': 'registry/2.0',
        'Content-Type': 'application/json'
      });
      addSecurityHeaders(headers, request, config);
      return new Response('{}', { status: 200, headers });
    }

    // Workers 内置根路径介绍页与健康检查
    // 1) 健康检查端点（Workers 原生版本）
    if (url.pathname === '/health' || url.pathname === '/api/health') {
      const info = {
        service: 'Xget',
        version: '1.0.0',
        platform: 'Cloudflare Workers',
        status: 'OK',
        timestamp: new Date().toISOString(),
        region: (request.cf && request.cf.colo) || 'N/A',
        endpoints: {
          health: '/health',
          root: '/',
          proxy: '/{platform}/{path}'
        }
      };
      return new Response(JSON.stringify(info, null, 2), {
        status: 200,
        headers: addSecurityHeaders(
          new Headers({
            'Content-Type': 'application/json',
            'Cache-Control': 'public, max-age=60',
            'X-Service': 'Xget-Workers'
          }),
          request,
          config
        )
      });
    }

    // 2) 内置 URL 转换器功能页：/convert
    if (url.pathname === '/convert') {
      const originalUrl = url.searchParams.get('url')?.trim();

      // 将原始 URL 转换为 Xget 路径
      function tryConvert(u) {
        try {
          const parsed = new URL(u);

          // 1) 特例：raw.githubusercontent.com 映射为 gh/raw 路径
          if (parsed.hostname === 'raw.githubusercontent.com') {
            // 格式：/owner/repo/branch/path -> /gh/owner/repo/raw/branch/path
            const parts = parsed.pathname.split('/').filter(Boolean);
            if (parts.length >= 3) {
              const [owner, repo, branch, ...rest] = parts;
              const restPath = rest.length ? `/${rest.join('/')}` : '';
              const xgetPath = `/gh/${owner}/${repo}/raw/${branch}${restPath}${parsed.search}`;
              return { platformKey: 'gh', xgetPath };
            }
          }

          // 2) 基于 PLATFORMS 的最长前缀匹配（含子路径）
          const platformEntries = Object.entries(CONFIG.PLATFORMS)
            .map(([key, base]) => ({ key, base }))
            // 优先匹配更“长”的 base（含路径的更具体）
            .sort((a, b) => b.base.length - a.base.length);

          for (const { key, base } of platformEntries) {
            try {
              const baseUrl = new URL(base);
              if (parsed.hostname !== baseUrl.hostname) continue;

              // 处理 baseUrl.path 前缀（如 https://github.com/Homebrew）
              const basePath = baseUrl.pathname.endsWith('/')
                ? baseUrl.pathname.slice(0, -1)
                : baseUrl.pathname;
              const inputPath = parsed.pathname;

              if (!inputPath.startsWith(basePath)) continue;

              // 去掉基路径，保留余下路径
              let restPath = inputPath.slice(basePath.length);
              if (!restPath.startsWith('/')) restPath = '/' + restPath;

              // 平台前缀：将 - 替换为 /
              const prefix = `/${key.replace(/-/g, '/')}`;

              // 容器注册表平台使用 /cr/ 前缀
              const xgetPath = key.startsWith('cr-')
                ? `/cr/${key.split('-')[1]}${restPath}${parsed.search}`
                : `${prefix}${restPath}${parsed.search}`;

              return { platformKey: key, xgetPath };
            } catch (_) {
              // base 不是合法 URL 的情况忽略
            }
          }

          // 3) 常见主机别名兜底（如 github.com -> gh）
          if (parsed.hostname === 'github.com') {
            return { platformKey: 'gh', xgetPath: `/gh${parsed.pathname}${parsed.search}` };
          }
          if (parsed.hostname === 'pypi.org') {
            return { platformKey: 'pypi', xgetPath: `/pypi${parsed.pathname}${parsed.search}` };
          }
          if (parsed.hostname === 'files.pythonhosted.org') {
            return { platformKey: 'pypi-files', xgetPath: `/pypi/files${parsed.pathname}${parsed.search}` };
          }
          if (parsed.hostname === 'registry.npmjs.org') {
            return { platformKey: 'npm', xgetPath: `/npm${parsed.pathname}${parsed.search}` };
          }
          if (parsed.hostname === 'ghcr.io') {
            return { platformKey: 'cr-ghcr', xgetPath: `/cr/ghcr${parsed.pathname}${parsed.search}` };
          }
          if (parsed.hostname === 'quay.io') {
            return { platformKey: 'cr-quay', xgetPath: `/cr/quay${parsed.pathname}${parsed.search}` };
          }

          return { error: '未识别的源站，当前转换器暂不支持该 URL' };
        } catch (e) {
          return { error: 'URL 格式不正确，请输入完整的 http(s) URL' };
        }
      }

      const branding = `<p class="note"><strong>预部署实例（不保证可靠性）：</strong><a href="https://xget.xi-xu.me" target="_blank" rel="noopener">xget.xi-xu.me</a> - 开箱即用，无需部署！</p>`;

      if (!originalUrl) {
        const html = `<!DOCTYPE html><html lang="zh-CN"><head><meta charset="UTF-8" /><meta name="viewport" content="width=device-width, initial-scale=1" /><meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; img-src 'self' data:; form-action 'self'; base-uri 'self'"><title>Xget - URL 转换器</title><style>
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, 'Microsoft Yahei', sans-serif; margin: 2rem; line-height: 1.6; color: #111; }
    code { background: #f6f8fa; padding: 0.15rem 0.35rem; border-radius: 4px; }
    input,button { font-size: 16px; }
    a { color: #0969da; text-decoration: none; }
    a:hover { text-decoration: underline; }
    .note { background: #fff8c5; border: 1px solid #ffd33d; padding: 0.75rem 1rem; border-radius: 6px; }
    form { display:flex; gap:.5rem; max-width:720px; }
    input[type=url] { flex:1; padding:.5rem .75rem; border:1px solid #ccc; border-radius:6px; }
    button { padding:.5rem .9rem; border:0; border-radius:6px; background:#0969da; color:#fff; cursor:pointer; }
  </style></head><body>
  <h1>🔗 Xget URL 转换器</h1>
  ${branding}
  <p style="font-weight:600;color:#0f5132;background:#d1e7dd;border:1px solid #badbcc;padding:.75rem 1rem;border-radius:6px;">⚡ 立即体验极速下载：无需注册，无需配置，直接使用即可感受飞一般的下载速度！</p>
  <form action="/convert" method="GET" style="margin:1rem 0;display:flex;gap:.5rem;max-width:720px;">
    <input type="url" name="url" placeholder="在此粘贴原始 URL（例如 https://github.com/... 或 https://registry.npmjs.org/...）" style="flex:1;padding:.5rem .75rem;border:1px solid #ccc;border-radius:6px;" required />
    <button type="submit" style="padding:.5rem .9rem;border:0;border-radius:6px;background:#0969da;color:#fff;cursor:pointer;">转换</button>
  </form>
  <p>支持来源：GitHub、GitLab、Hugging Face、npm、PyPI、conda、Maven、Homebrew、容器注册表（ghcr、quay、gcr、mcr 等）及更多。只需粘贴原始 URL，自动生成 Xget 加速链接。</p>
</body>
</html>`;
        return new Response(html, {
          status: 200,
          headers: addSecurityHeaders(
            new Headers({ 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store' }),
            request,
            config
          )
        });
      }

      const result = tryConvert(originalUrl);
      const instanceOrigin = url.origin;

      // 构建结果区块，避免在模板字符串内嵌套模板字符串导致语法歧义
      let resultSection = '';
      if (result.error) {
        const safeErr = String(result.error).replace(/&/g, '&amp;').replace(/</g, '&lt;');
        resultSection = '<p style="color:#842029;background:#f8d7da;border:1px solid #f5c2c7;padding:.75rem 1rem;border-radius:6px;">' + safeErr + '</p>';
      } else {
        const safePath = String(result.xgetPath || '');
        resultSection = (
          '<h2>转换成功</h2>' +
          '<p>当前实例链接：</p>' +
          '<pre><code>' + instanceOrigin + safePath + '</code></pre>' +
          '<p>预部署实例链接：</p>' +
          '<pre><code>https://xget.xi-xu.me' + safePath + '</code></pre>' +
          '<p>' +
          '<a href="' + safePath + '" style="margin-right:1rem;">在当前实例中打开</a>' +
          '<a href="https://xget.xi-xu.me' + safePath + '" target="_blank" rel="noopener">在预部署实例中打开</a>' +
          '</p>'
        );
      }

      const html = `<!DOCTYPE html><html lang="zh-CN"><head><meta charset="UTF-8" /><meta name="viewport" content="width=device-width, initial-scale=1.0" /><title>Xget - URL 转换结果</title><style>
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, 'Microsoft Yahei', sans-serif; margin: 2rem; line-height: 1.6; color: #111; }
    code { background: #f6f8fa; padding: 0.15rem 0.35rem; border-radius: 4px; }
    input,button { font-size: 16px; }
    a { color: #0969da; text-decoration: none; }
    a:hover { text-decoration: underline; }
    pre { background: #f6f8fa; padding: 1rem; border-radius: 6px; overflow: auto; }
    .note { background: #fff8c5; border: 1px solid #ffd33d; padding: 0.75rem 1rem; border-radius: 6px; }
  </style></head><body>
  <h1>🔗 Xget URL 转换结果</h1>
  ${branding}
  <form action="/convert" method="GET" style="margin:1rem 0;display:flex;gap:.5rem;max-width:720px;">
    <input type="url" name="url" value="${originalUrl.replace(/"/g, '&quot;')}" style="flex:1;padding:.5rem .75rem;border:1px solid #ccc;border-radius:6px;" required />
    <button type="submit" style="padding:.5rem .9rem;border:0;border-radius:6px;background:#0969da;color:#fff;cursor:pointer;">重新转换</button>
  </form>
  ${resultSection}
</body>
</html>`;

      return new Response(html, {
        status: 200,
        headers: addSecurityHeaders(
          new Headers({ 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store' })
        )
      });
    }

    // 3) 根路径直接跳转到 /convert 功能页（透传查询参数）
    if (url.pathname === '/' || url.pathname === '') {
      const dest = new URL(url.toString());
      dest.pathname = '/convert';
      // 保留原始查询参数，便于直接传入 url=xxx
      const headers = addSecurityHeaders(new Headers({ Location: dest.toString() }), request, config);
      return new Response(null, { status: 302, headers });
    }

    // 4) 根路径说明页（如需改回说明页，可恢复此段）
    // 注：当前我们选择方案 A，直接跳转到 /convert，因此说明页逻辑被替换为 302 重定向。


    const validation = validateRequest(request, url, config);
    if (!validation.valid) {
      return createErrorResponse(validation.error || 'Validation failed', validation.status || 400, false, request, config);
    }

    // Parse platform and path
    let platform;
    let effectivePath = url.pathname;

    // Handle container registry paths specially
    if (isDocker) {
      // For Docker requests (excluding version check which is handled above),
      // check if they have /cr/ prefix
      if (!url.pathname.startsWith('/cr/') && !url.pathname.startsWith('/v2/cr/')) {
        return createErrorResponse('container registry requests must use /cr/ prefix', 400);
      }
      // Remove /v2 from the path for container registry API consistency if present
      effectivePath = url.pathname.replace(/^\/v2/, '');
    } else if (isDocker && !url.pathname.startsWith('/cr/') && !url.pathname.startsWith('/v2/cr/')) {
      return createErrorResponse('container registry requests must use /cr/ prefix', 400, false, request, config);
    }

    // Platform detection using transform patterns
    // Sort platforms by path length (descending) to prioritize more specific paths
    // e.g., conda/community should match before conda, pypi/files before pypi
    const sortedPlatforms = Object.keys(config.PLATFORMS).sort((a, b) => {
      const pathA = `/${a.replace('-', '/')}/`;
      const pathB = `/${b.replace('-', '/')}/`;
      return pathB.length - pathA.length;
    });

    platform =
      sortedPlatforms.find(key => {
        const expectedPrefix = `/${key.replace('-', '/')}/`;
        return effectivePath.startsWith(expectedPrefix);
      }) || effectivePath.split('/')[1];

    if (!platform || !config.PLATFORMS[platform]) {
      const HOME_PAGE_URL = 'https://github.com/xixu-me/Xget';
      return Response.redirect(HOME_PAGE_URL, 302);
    }

    // Transform URL based on platform using unified logic
    const targetPath = transformPath(effectivePath, platform);

    // For container registries, ensure we add the /v2 prefix for the Docker API
    let finalTargetPath;
    if (platform.startsWith('cr-')) {
      finalTargetPath = `/v2${targetPath}`;
    } else {
      finalTargetPath = targetPath;
    }

    const targetUrl = `${config.PLATFORMS[platform]}${finalTargetPath}${url.search}`;
    const authorization = request.headers.get('Authorization');

    // Handle Docker authentication
    if (isDocker && url.pathname === '/v2/auth') {
      const newUrl = new URL(config.PLATFORMS[platform] + '/v2/');
      const resp = await fetch(newUrl.toString(), {
        method: 'GET',
        redirect: 'follow'
      });
      if (resp.status !== 401) {
        return resp;
      }
      const authenticateStr = resp.headers.get('WWW-Authenticate');
      if (authenticateStr === null) {
        return resp;
      }
      const wwwAuthenticate = parseAuthenticate(authenticateStr);
      let scope = url.searchParams.get('scope');
      return await fetchToken(wwwAuthenticate, scope || '', authorization || '');
    }

    // Check if this is a Git operation
    const isGit = isGitRequest(request, url);

    // Check if this is an AI inference request
    const isAI = isAIInferenceRequest(request, url);

    // Check cache first (skip cache for Git, Docker, and AI inference operations)
    /** @type {Cache} */
    // @ts-ignore - Cloudflare Workers cache API
    const cache = caches.default;
    const cacheKey = new Request(targetUrl, request);
    let response;

    if (!isGit && !isDocker && !isAI) {
      response = await cache.match(cacheKey);
      if (response) {
        monitor.mark('cache_hit');
        return response;
      }
    }

    /** @type {RequestInit} */
    const fetchOptions = {
      method: request.method,
      headers: new Headers(),
      redirect: 'follow'
    };

    // Add body for POST/PUT/PATCH requests (Git/Docker/AI inference operations)
    if (['POST', 'PUT', 'PATCH'].includes(request.method) && (isGit || isDocker || isAI)) {
      fetchOptions.body = request.body;
    }

    // Cast headers to Headers for proper typing
    const requestHeaders = /** @type {Headers} */ (fetchOptions.headers);

    // Set appropriate headers for Git/Docker/AI vs regular requests
    if (isGit || isDocker || isAI) {
      // For Git/Docker/AI operations, copy all headers from the original request
      // This ensures protocol compliance
      for (const [key, value] of request.headers.entries()) {
        // Skip headers that might cause issues with proxying
        if (!['host', 'connection', 'upgrade', 'proxy-connection'].includes(key.toLowerCase())) {
          requestHeaders.set(key, value);
        }
      }

      // Set Git-specific headers if not present
      if (isGit && !requestHeaders.has('User-Agent')) {
        requestHeaders.set('User-Agent', 'git/2.34.1');
      }

      // For Git upload-pack requests, ensure proper content type
      if (isGit && request.method === 'POST' && url.pathname.endsWith('/git-upload-pack')) {
        if (!requestHeaders.has('Content-Type')) {
          requestHeaders.set('Content-Type', 'application/x-git-upload-pack-request');
        }
      }

      // For Git receive-pack requests, ensure proper content type
      if (isGit && request.method === 'POST' && url.pathname.endsWith('/git-receive-pack')) {
        if (!requestHeaders.has('Content-Type')) {
          requestHeaders.set('Content-Type', 'application/x-git-receive-pack-request');
        }
      }

      // For AI inference requests, ensure proper content type and headers
      if (isAI) {
        // Ensure JSON content type for AI API requests if not already set
        if (request.method === 'POST' && !requestHeaders.has('Content-Type')) {
          requestHeaders.set('Content-Type', 'application/json');
        }

        // Set appropriate User-Agent for AI requests if not present
        if (!requestHeaders.has('User-Agent')) {
          requestHeaders.set('User-Agent', 'Xget-AI-Proxy/1.0');
        }
      }
    } else {
      // Regular file download headers
      Object.assign(fetchOptions, {
        cf: {
          http3: true,
          cacheTtl: config.CACHE_DURATION,
          cacheEverything: true,
          minify: {
            javascript: true,
            css: true,
            html: true
          },
          preconnect: true
        }
      });

      requestHeaders.set('Accept-Encoding', 'gzip, deflate, br');
      requestHeaders.set('Connection', 'keep-alive');
      requestHeaders.set('User-Agent', 'Wget/1.21.3');
      requestHeaders.set('Origin', request.headers.get('Origin') || '*');

      // Handle range requests
      const rangeHeader = request.headers.get('Range');
      if (rangeHeader) {
        requestHeaders.set('Range', rangeHeader);
      }
    }

    // Implement retry mechanism
    let attempts = 0;
    while (attempts < config.MAX_RETRIES) {
      try {
        monitor.mark('attempt_' + attempts);

        // Fetch with timeout
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), config.TIMEOUT_SECONDS * 1000);

        // For Git/Docker operations, don't use Cloudflare-specific options
        const finalFetchOptions =
          isGit || isDocker
            ? { ...fetchOptions, signal: controller.signal }
            : { ...fetchOptions, signal: controller.signal };

        // Special handling for HEAD requests to ensure Content-Length header
        if (request.method === 'HEAD') {
          // First, try the HEAD request
          response = await fetch(targetUrl, finalFetchOptions);

          // If HEAD request succeeds but lacks Content-Length, do a GET request to get it
          if (response.ok && !response.headers.get('Content-Length')) {
            const getResponse = await fetch(targetUrl, {
              ...finalFetchOptions,
              method: 'GET'
            });

            if (getResponse.ok) {
              // Create a new response with HEAD method but include Content-Length from GET
              const headHeaders = new Headers(response.headers);
              const contentLength = getResponse.headers.get('Content-Length');

              if (contentLength) {
                headHeaders.set('Content-Length', contentLength);
              } else {
                // If still no Content-Length, calculate it from the response body
                const arrayBuffer = await getResponse.arrayBuffer();
                headHeaders.set('Content-Length', arrayBuffer.byteLength.toString());
              }

              response = new Response(null, {
                status: getResponse.status,
                statusText: getResponse.statusText,
                headers: headHeaders
              });
            }
          }
        } else {
          response = await fetch(targetUrl, finalFetchOptions);
        }

        clearTimeout(timeoutId);

        if (response.ok || response.status === 206) {
          monitor.mark('success');
          break;
        }

        // For container registry, handle authentication challenges more intelligently
        if (isDocker && response.status === 401) {
          monitor.mark('docker_auth_challenge');

          // For container registries, first check if we can get a token without credentials
          // This allows access to public repositories
          const authenticateStr = response.headers.get('WWW-Authenticate');
          if (authenticateStr) {
            try {
              const wwwAuthenticate = parseAuthenticate(authenticateStr);

              // Infer scope from the request path for container registry requests
              let scope = '';
              const pathParts = url.pathname.split('/');
              if (pathParts.length >= 4 && pathParts[1] === 'v2') {
                // Extract repository name from path like /v2/cr/ghcr/nginxinc/nginx-unprivileged/manifests/latest
                // Remove /v2 and platform prefix to get the repo path
                const repoPath = pathParts.slice(4).join('/'); // Skip /v2/cr/[registry]
                const repoParts = repoPath.split('/');
                if (repoParts.length >= 1) {
                  const repoName = repoParts.slice(0, -2).join('/'); // Remove /manifests/tag or /blobs/sha
                  if (repoName) {
                    scope = `repository:${repoName}:pull`;
                  }
                }
              }

              // Try to get a token for public access (without authorization)
              const tokenResponse = await fetchToken(wwwAuthenticate, scope || '', '');
              if (tokenResponse.ok) {
                const tokenData = await tokenResponse.json();
                if (tokenData.token) {
                  // Retry the original request with the obtained token
                  const retryHeaders = new Headers(requestHeaders);
                  retryHeaders.set('Authorization', `Bearer ${tokenData.token}`);

                  const retryResponse = await fetch(targetUrl, {
                    ...finalFetchOptions,
                    headers: retryHeaders
                  });

                  if (retryResponse.ok) {
                    response = retryResponse;
                    monitor.mark('success');
                    break;
                  }
                }
              }
            } catch (error) {
              console.log('Token fetch failed:', error);
            }
          }

          // If token fetch failed or didn't work, return the unauthorized response
          // Only return this if we truly can't access the resource
          return responseUnauthorized(url);
        }

        // Don't retry on client errors (4xx) - these won't improve with retries
        if (response.status >= 400 && response.status < 500) {
          monitor.mark('client_error');
          break;
        }

        attempts++;
        if (attempts < config.MAX_RETRIES) {
          await new Promise(resolve => setTimeout(resolve, config.RETRY_DELAY_MS * attempts));
        }
      } catch (error) {
        attempts++;
        if (error instanceof Error && error.name === 'AbortError') {
          return createErrorResponse('Request timeout', 408, false, request, config);
        }
        if (attempts >= config.MAX_RETRIES) {
          const message = error instanceof Error ? error.message : String(error);
          return createErrorResponse(
            `Failed after ${config.MAX_RETRIES} attempts: ${message}`,
            500,
            true,
            request,
            config
          );
        }
        // Wait before retrying
        await new Promise(resolve => setTimeout(resolve, config.RETRY_DELAY_MS * attempts));
      }
    }

    // Check if we have a valid response after all attempts
    if (!response) {
      return createErrorResponse('No response received after all retry attempts', 500, true, request, config);
    }

    // If response is still not ok after all retries, return the error
    if (!response.ok && response.status !== 206) {
      // 对 Docker 的 401 做专门处理；其余情况尽量透传上游响应，避免把 HTML/纯文本错误页改造成 JSON
      if (isDocker && response.status === 401) {
        const errorText = await response.text().catch(() => '');
        return createErrorResponse(
          `Authentication required for this container registry resource. This may be a private repository. Original error: ${errorText}`,
          401,
          true,
          request,
          config
        );
      }

      // Git/GitHub 等网页类响应或 4xx/5xx，优先透传上游内容与 Content-Type
      const ct = response.headers.get('content-type') || '';
      if (isGit || ct.includes('text/html') || ct.includes('text/plain')) {
        return response;
      }

      // 其他类型的错误（如 JSON API），保留原信息，但不强制改为 JSON 包装
      return response;
    }

    // Handle URL rewriting for different platforms
    let responseBody = response.body;

    // Handle PyPI simple index URL rewriting
    if (platform === 'pypi' && response.headers.get('content-type')?.includes('text/html')) {
      const originalText = await response.text();
      // Rewrite URLs in the response body to go through the Cloudflare Worker
      // files.pythonhosted.org URLs should be rewritten to go through our pypi/files endpoint
      const rewrittenText = originalText.replace(
        /https:\/\/files\.pythonhosted\.org/g,
        `${url.origin}/pypi/files`
      );
      responseBody = new ReadableStream({
        start(controller) {
          controller.enqueue(new TextEncoder().encode(rewrittenText));
          controller.close();
        }
      });
    }

    // Handle npm registry URL rewriting
    if (platform === 'npm' && response.headers.get('content-type')?.includes('application/json')) {
      const originalText = await response.text();
      // Rewrite tarball URLs in npm registry responses to go through our npm endpoint
      // https://registry.npmjs.org/package/-/package-version.tgz -> https://xget.xi-xu.me/npm/package/-/package-version.tgz
      const rewrittenText = originalText.replace(
        /https:\/\/registry\.npmjs\.org\/([^\/]+)/g,
        `${url.origin}/npm/$1`
      );
      responseBody = new ReadableStream({
        start(controller) {
          controller.enqueue(new TextEncoder().encode(rewrittenText));
          controller.close();
        }
      });
    }

    // Prepare response headers
    const headers = new Headers(response.headers);

    if (isGit || isDocker) {
      // For Git/Docker operations, preserve all headers from the upstream response
      // These protocols are very sensitive to header changes
      // Don't add any additional headers that might interfere with protocol operation
      // The response headers from upstream should be passed through as-is
    } else {
      // Regular file download headers
      headers.set('Cache-Control', `public, max-age=${config.CACHE_DURATION}`);
      headers.set('X-Content-Type-Options', 'nosniff');
      headers.set('Accept-Ranges', 'bytes');
      addSecurityHeaders(headers);
    }

    // Create final response
    const finalResponse = new Response(responseBody, {
      status: response.status,
      headers: headers
    });

    // Cache successful responses (skip caching for Git, Docker, and AI inference operations)
    // Only cache GET and HEAD requests to avoid "Cannot cache response to non-GET request" errors
    if (
      !isGit &&
      !isDocker &&
      !isAI &&
      ['GET', 'HEAD'].includes(request.method) &&
      (response.ok || response.status === 206)
    ) {
      ctx.waitUntil(cache.put(cacheKey, finalResponse.clone()));
    }

    monitor.mark('complete');
    return isGit || isDocker || isAI
      ? finalResponse
      : addPerformanceHeaders(finalResponse, monitor);
  } catch (error) {
    console.error('Error handling request:', error);
    const message = error instanceof Error ? error.message : String(error);
    return createErrorResponse(`Internal Server Error: ${message}`, 500, true, request, CONFIG);
  }
}

/**
 * Adds performance metrics to response headers
 * @param {Response} response - The response object
 * @param {PerformanceMonitor} monitor - Performance monitor instance
 * @returns {Response} New response with performance headers
 */
function addPerformanceHeaders(response, monitor) {
  const headers = new Headers(response.headers);
  headers.set('X-Performance-Metrics', JSON.stringify(monitor.getMetrics()));
  addSecurityHeaders(headers);
  return new Response(response.body, {
    status: response.status,
    headers: headers
  });
}

export default {
  /**
   * Main entry point for the Cloudflare Worker
   * @param {Request} request - The incoming request
   * @param {Object} env - Environment variables
   * @param {ExecutionContext} ctx - Cloudflare Workers execution context
   * @returns {Promise<Response>} The response object
   */
  fetch(request, env, ctx) {
    return handleRequest(request, env, ctx);
  }
};
