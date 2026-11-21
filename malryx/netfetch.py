"""Téléchargements robustes : quand le DNS du réseau ne résout pas un nom (cas fréquent avec certains
fournisseurs d'accès : database.clamav.net, github.com…), Malryx interroge des résolveurs DNS-over-HTTPS
publics joints PAR ADRESSE IP (Cloudflare 1.1.1.1, Google 8.8.8.8, Quad9 9.9.9.9), puis se connecte à
l'adresse obtenue en conservant le nom d'hôte pour TLS (SNI + vérification du certificat).
La sécurité TLS est donc intacte : seul le DNS local est contourné."""
import http.client
import json
import socket
import ssl
import urllib.error
import urllib.parse
import urllib.request

UA = "Malryx-Updater"
OFFLINE = False   # positionné par l'application : en mode hors ligne, AUCUNE connexion n'est ouverte


class OfflineError(OSError):
    pass


def _guard():
    if OFFLINE:
        raise OfflineError("mode hors ligne activé : aucune connexion réseau")
DOH = [
    "https://1.1.1.1/dns-query?name={h}&type=A",
    "https://8.8.8.8/resolve?name={h}&type=A",
    "https://9.9.9.9:5053/dns-query?name={h}&type=A",
]
_doh_cache = {}


def doh_resolve(host):
    _guard()
    if host in _doh_cache:
        return _doh_cache[host]
    for url in DOH:
        try:
            req = urllib.request.Request(url.format(h=host), headers={"accept": "application/dns-json", "User-Agent": UA})
            with urllib.request.urlopen(req, timeout=10) as r:
                ans = [a["data"] for a in json.load(r).get("Answer", []) if a.get("type") == 1]
            if ans:
                _doh_cache[host] = ans[0]
                return ans[0]
        except (OSError, ValueError, KeyError):
            continue
    return None


def dns_ok(host):
    try:
        socket.getaddrinfo(host, 443)
        return True
    except socket.gaierror:
        return False


class _PinnedHTTPS(http.client.HTTPSConnection):
    """Connexion vers une IP donnée, mais TLS négocié et vérifié pour le vrai nom d'hôte."""
    def __init__(self, host, ip, **kw):
        super().__init__(host, context=ssl.create_default_context(), **kw)
        self._ip = ip

    def connect(self):
        sock = socket.create_connection((self._ip, self.port), self.timeout)
        self.sock = self._context.wrap_socket(sock, server_hostname=self.host)


def _get_direct(url, headers, timeout):
    """GET via DoH + IP épinglée, redirections suivies (GitHub → objects.githubusercontent.com)."""
    for _ in range(6):
        u = urllib.parse.urlsplit(url)
        ip = doh_resolve(u.hostname)
        if not ip:
            raise OSError(f"{u.hostname} introuvable (DNS local et DNS-over-HTTPS en échec)")
        c = _PinnedHTTPS(u.hostname, ip, port=u.port or 443, timeout=timeout)
        c.request("GET", (u.path or "/") + (f"?{u.query}" if u.query else ""), headers={"Host": u.hostname, **headers})
        r = c.getresponse()
        if r.status in (301, 302, 303, 307, 308):
            url = urllib.parse.urljoin(url, r.getheader("Location")); r.read(); c.close()
            continue
        return r
    raise OSError("trop de redirections")


def open_url(url, headers=None, timeout=60):
    """Renvoie un objet réponse lisible (.read(), .status, .getheader). Proxy système respecté en mode normal."""
    _guard()
    headers = {"User-Agent": UA, **(headers or {})}
    host = urllib.parse.urlsplit(url).hostname
    if dns_ok(host):
        try:
            return urllib.request.urlopen(urllib.request.Request(url, headers=headers), timeout=timeout)
        except urllib.error.HTTPError:
            raise
        except urllib.error.URLError as e:
            if not isinstance(e.reason, socket.gaierror):
                raise
    r = _get_direct(url, headers, timeout)
    if r.status >= 400:
        raise urllib.error.HTTPError(url, r.status, r.reason, r.headers, None)
    return r


def fetch_json(url, **kw):
    with open_url(url, **kw) as r:
        return json.load(r)


def download(url, dest, progress=None, headers=None, timeout=120):
    """Télécharge vers dest (fichier temporaire puis renommage atomique). Renvoie la taille."""
    import os
    tmp = str(dest) + ".part"
    r = open_url(url, headers=headers, timeout=timeout)
    total = int(r.getheader("Content-Length") or 0)
    done = 0
    with open(tmp, "wb") as f:
        while True:
            chunk = r.read(1 << 20)
            if not chunk:
                break
            f.write(chunk); done += len(chunk)
            if progress and total:
                progress(f"{done / 1e6:.0f} / {total / 1e6:.0f} Mo")
    r.close()
    if total and done != total:
        os.remove(tmp)
        raise OSError("téléchargement incomplet")
    os.replace(tmp, dest)
    return done
