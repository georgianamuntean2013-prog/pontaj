"""Import de calendare din link ICS (Google, Outlook, iCloud).
Descarcare sigura, citire si extindere a evenimentelor recurente. Nu depinde de restul aplicatiei."""
import ipaddress, re, socket
from datetime import date, datetime, time, timedelta, timezone
from urllib.error import HTTPError
from urllib.parse import urlparse
from urllib.request import HTTPRedirectHandler, Request, build_opener
from zoneinfo import ZoneInfo

from dateutil.rrule import rrulestr

LOCAL = ZoneInfo("Europe/Bucharest")
MAX_BYTES = 8_000_000
WIN = {  # nume de fusuri orare folosite de Outlook -> IANA
    "GTB Standard Time": "Europe/Bucharest", "E. Europe Standard Time": "Europe/Chisinau",
    "W. Europe Standard Time": "Europe/Berlin", "Central Europe Standard Time": "Europe/Budapest",
    "Central European Standard Time": "Europe/Warsaw", "Romance Standard Time": "Europe/Paris",
    "GMT Standard Time": "Europe/London", "FLE Standard Time": "Europe/Kiev", "Turkey Standard Time": "Europe/Istanbul",
    "Russian Standard Time": "Europe/Moscow", "UTC": "UTC", "Eastern Standard Time": "America/New_York",
    "Central Standard Time": "America/Chicago", "Mountain Standard Time": "America/Denver",
    "Pacific Standard Time": "America/Los_Angeles"}


class EroareCalendar(Exception):
    """Mesaj pentru om, sigur de afisat."""


# ---------------- descarcare sigura ----------------
def url_sigur(url):
    """Accepta doar https (sau webcal) catre adrese publice. Opreste accesul la reteaua interna (SSRF)."""
    url = url.strip()
    if url.lower().startswith("webcal://"):
        url = "https://" + url[9:]
    p = urlparse(url)
    if p.scheme != "https" or not p.hostname:
        raise EroareCalendar("Linkul trebuie sa inceapa cu https:// sau webcal://.")
    try:
        adrese = socket.getaddrinfo(p.hostname, p.port or 443, proto=socket.IPPROTO_TCP)
    except socket.gaierror:
        raise EroareCalendar("Nu pot gasi serverul din link.")
    for a in adrese:
        if not ipaddress.ip_address(a[4][0].split("%")[0]).is_global:
            raise EroareCalendar("Linkul nu este permis.")
    return url


class _Redirect(HTTPRedirectHandler):
    max_redirections = 3

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        url_sigur(newurl)  # fiecare redirectionare e verificata din nou
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def descarca(url):
    url = url_sigur("".join(url.split()))  # fara spatii sau rupturi de rand strecurate la copiere
    # Outlook raspunde cu eroarea 400 clientilor care nu se prezinta ca un browser
    req = Request(url, headers={
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36",
        "Accept": "text/calendar, text/plain;q=0.9, */*;q=0.8"})
    try:
        with build_opener(_Redirect).open(req, timeout=15) as r:
            brut = r.read(MAX_BYTES + 1)
    except EroareCalendar:
        raise
    except HTTPError as e:
        raise EroareCalendar(f"Serverul calendarului a raspuns cu eroarea {e.code}. Verifica linkul: trebuie sa fie linkul ICS "
                             "(se termina cu .ics), copiat intreg, fara spatii.")
    except Exception:
        raise EroareCalendar("Nu am putut descarca calendarul. Verifica linkul.")
    if len(brut) > MAX_BYTES:
        raise EroareCalendar("Calendarul este prea mare.")
    text = brut.decode("utf-8", errors="replace")
    if "BEGIN:VCALENDAR" not in text:
        raise EroareCalendar("Linkul nu duce la un calendar (format ICS).")
    return text


# ---------------- citire ICS ----------------
def _prop(linie):
    """NUME;PARAM=val:VALOARE -> (NUME, {PARAM: val}, VALOARE)"""
    inq, taie = False, -1
    for i, ch in enumerate(linie):
        if ch == '"':
            inq = not inq
        elif ch == ":" and not inq:
            taie = i
            break
    if taie < 1:
        return None
    cap, val = linie[:taie], linie[taie + 1:]
    parti, buf, inq = [], "", False
    for ch in cap:
        if ch == '"':
            inq = not inq
        if ch == ";" and not inq:
            parti.append(buf)
            buf = ""
        else:
            buf += ch
    parti.append(buf)
    params = {}
    for p in parti[1:]:
        k, _, v = p.partition("=")
        params[k.upper()] = v.strip('"')
    return parti[0].upper(), params, val


def _brute(text):
    linii = re.sub(r"\n[ \t]", "", text.replace("\r\n", "\n").replace("\r", "\n")).split("\n")
    ev, cur, alarma = [], None, False
    for l in linii:
        if l == "BEGIN:VEVENT":
            cur = {}
        elif l == "END:VEVENT":
            if cur is not None:
                ev.append(cur)
            cur = None
        elif l == "BEGIN:VALARM":
            alarma = True
        elif l == "END:VALARM":
            alarma = False
        elif cur is not None and not alarma:
            p = _prop(l)
            if p:
                cur.setdefault(p[0], []).append((p[1], p[2]))
    return ev


def _val(e, n):
    return e[n][0][1] if n in e else None


def _tz(nume):
    if not nume:
        return LOCAL
    try:
        return ZoneInfo(WIN.get(nume, nume))
    except Exception:
        return LOCAL


def _dt(val, params):
    """-> (data sau datetime cu fus orar, toata_ziua)"""
    val = val.strip()
    if params.get("VALUE") == "DATE" or (len(val) == 8 and val.isdigit()):
        return datetime.strptime(val[:8], "%Y%m%d").date(), True
    if val.endswith("Z"):
        return datetime.strptime(val, "%Y%m%dT%H%M%SZ").replace(tzinfo=timezone.utc), False
    return datetime.strptime(val, "%Y%m%dT%H%M%S").replace(tzinfo=_tz(params.get("TZID"))), False


def _start(val, params):
    d, toata = _dt(val, params)
    return datetime.combine(d, time(0), tzinfo=LOCAL) if toata else d


def _cheie(dt):
    return dt.astimezone(timezone.utc).strftime("%Y%m%dT%H%M%S")


def _durata(v):
    m = re.match(r"^([+-])?P(?:(\d+)W)?(?:(\d+)D)?(?:T(?:(\d+)H)?(?:(\d+)M)?(?:(\d+)S)?)?$", (v or "").strip())
    if not m:
        return timedelta(0)
    w, d, h, mi, s = (int(x or 0) for x in m.groups()[1:])
    return (-1 if m.group(1) == "-" else 1) * timedelta(weeks=w, days=d, hours=h, minutes=mi, seconds=s)


def _text(v):
    return re.sub(r"\\([nN,;\\])", lambda m: "\n" if m.group(1) in "nN" else m.group(1), v)


def _regula(val, start):
    m = re.search(r"UNTIL=([0-9TZ]+)", val)
    if m and not m.group(1).endswith("Z"):
        u = m.group(1)
        if "T" in u:
            loc = datetime.strptime(u, "%Y%m%dT%H%M%S").replace(tzinfo=start.tzinfo)
        else:
            loc = datetime.strptime(u[:8], "%Y%m%d").replace(hour=23, minute=59, second=59, tzinfo=start.tzinfo)
        val = val.replace(m.group(0), "UNTIL=" + loc.astimezone(timezone.utc).strftime("%Y%m%dT%H%M%SZ"))
    return rrulestr("RRULE:" + val, dtstart=start)


def _expandeaza(e, de, pana, suprascrise):
    uid = _val(e, "UID")
    p, v = e["DTSTART"][0]
    d0, toata = _dt(v, p)
    start = datetime.combine(d0, time(0), tzinfo=LOCAL) if toata else d0
    if "DTEND" in e:
        p2, v2 = e["DTEND"][0]
        dur = _start(v2, p2) - start
    elif "DURATION" in e:
        dur = _durata(_val(e, "DURATION"))
    else:
        dur = timedelta(days=1) if toata else timedelta(0)
    if dur <= timedelta(0):
        return []
    titlu = _text(_val(e, "SUMMARY") or "")[:200]
    privat = (_val(e, "CLASS") or "").upper() in ("PRIVATE", "CONFIDENTIAL")

    def ev(s):
        return {"inceput": s.astimezone(timezone.utc), "sfarsit": (s + dur).astimezone(timezone.utc),
                "titlu": titlu, "privat": privat}

    if "RRULE" not in e:
        return [ev(start)] if start + dur > de and start < pana else []
    exd = set()
    for pp, vv in e.get("EXDATE", []):
        for x in vv.split(","):
            try:
                exd.add(_cheie(_start(x, pp)))
            except ValueError:
                pass
    rez = []
    for s in _regula(_val(e, "RRULE"), start).between(de - dur, pana, inc=True)[:1000]:
        k = _cheie(s)
        if k not in exd and (uid, k) not in suprascrise:
            rez.append(ev(s))
    return rez


def evenimente(text, de, pana):
    """Evenimentele care ocupa timpul intre 'de' si 'pana' (datetime cu fus orar). Sare peste cele marcate 'liber',
    anulate, fara durata. Evenimentele pe toata ziua conteaza ocupate doar daca nu sunt marcate 'liber'."""
    brute = _brute(text)
    suprascrise = {}
    for e in brute:
        if "RECURRENCE-ID" in e:
            try:
                suprascrise[(_val(e, "UID"), _cheie(_start(e["RECURRENCE-ID"][0][1], e["RECURRENCE-ID"][0][0])))] = e
            except ValueError:
                pass
    rez = []
    for e in brute:
        if "DTSTART" not in e or (_val(e, "STATUS") or "").upper() == "CANCELLED":
            continue
        if (_val(e, "TRANSP") or "").upper() == "TRANSPARENT" or (_val(e, "X-MICROSOFT-CDO-BUSYSTATUS") or "").upper() == "FREE":
            continue
        try:
            rez += _expandeaza(e, de, pana, suprascrise)
        except Exception:
            continue  # un eveniment cu format ciudat nu strica restul calendarului
    rez.sort(key=lambda x: x["inceput"])
    return rez
