// Estrategia: network-first para HTML, cache-first para assets estáticos.
// Si el SW falla en instalar, nunca bloquea la carga de la app.
const CACHE = 'mango-v4';
const ASSETS = ['/logo.png', '/manifest.json', '/icon-192.png', '/icon-512.png'];

self.addEventListener('install', e => {
  self.skipWaiting(); // toma control inmediatamente, sin esperar cachear
  e.waitUntil(
    caches.open(CACHE).then(c =>
      // addAll individual para que un fallo no rompa todo
      Promise.allSettled(ASSETS.map(a => c.add(a)))
    )
  );
});

self.addEventListener('activate', e => {
  e.waitUntil(
    caches.keys().then(keys =>
      Promise.all(keys.filter(k => k !== CACHE).map(k => caches.delete(k)))
    )
  );
  self.clients.claim();
});

self.addEventListener('fetch', e => {
  const url = new URL(e.request.url);

  // API: siempre red, nunca cachear
  if (url.pathname.startsWith('/api/')) return;

  // HTML (index.html / raíz): network-first — siempre la versión más reciente
  if (e.request.headers.get('accept')?.includes('text/html') || url.pathname === '/' || url.pathname === '/index.html') {
    e.respondWith(
      fetch(e.request).catch(() => caches.match('/index.html'))
    );
    return;
  }

  // Assets estáticos: cache-first
  e.respondWith(
    caches.match(e.request).then(cached => cached || fetch(e.request))
  );
});
