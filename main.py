import base64, csv, hashlib, io, json, os, re, secrets, sqlite3, threading, time
from datetime import date, datetime, timedelta, timezone
from functools import lru_cache
from zoneinfo import ZoneInfo
from fastapi import Depends, FastAPI, Header, HTTPException, Request
from fastapi.responses import Response
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

try:
    from cryptography.hazmat.primitives import serialization
    from py_vapid import Vapid
    from pywebpush import WebPushException, webpush
except ImportError:  # aplicatia merge si fara notificari
    webpush = None

import calimport
from urllib.parse import urlparse

TZ = ZoneInfo("Europe/Bucharest")
DB = os.environ.get("PONTAJ_DB", "pontaj.db")
app = FastAPI(title="Pontaj")
fails = {}  # username -> (count, locked_until)


def q(sql, args=(), one=False, write=False):
    con = sqlite3.connect(DB)
    con.row_factory = sqlite3.Row
    try:
        cur = con.execute(sql, args)
        if write:
            con.commit()
            return cur.lastrowid
        rows = cur.fetchall()
        return (rows[0] if rows else None) if one else rows
    finally:
        con.close()


def hp(parola, salt):
    return hashlib.pbkdf2_hmac("sha256", parola.encode(), salt.encode(), 200_000).hex()


def add_user(username, nume, prenume, parola, admin=0, functie="", ore_zi=8.0, firma_id=1, schimba=0, locatie=0):
    salt = secrets.token_hex(8)
    return q("INSERT INTO utilizatori(username,nume,prenume,salt,hash,admin,functie,ore_zi,firma_id,schimba_parola,locatie) VALUES(?,?,?,?,?,?,?,?,?,?,?)",
             (username, nume, prenume, salt, hp(parola, salt), admin, functie, ore_zi, firma_id, schimba, locatie), write=True)


def init():
    q("""CREATE TABLE IF NOT EXISTS utilizatori(id INTEGER PRIMARY KEY, username TEXT UNIQUE, nume TEXT,
         prenume TEXT, salt TEXT, hash TEXT, admin INTEGER DEFAULT 0)""", write=True)
    q("CREATE TABLE IF NOT EXISTS sesiuni(token TEXT PRIMARY KEY, user_id INTEGER, creat REAL)", write=True)
    q("""CREATE TABLE IF NOT EXISTS pontaje(id INTEGER PRIMARY KEY, user_id INTEGER, data TEXT, ora_venire TEXT,
         ora_plecare TEXT, pauza_min INTEGER DEFAULT 0, UNIQUE(user_id,data))""", write=True)
    q("""CREATE TABLE IF NOT EXISTS concedii(id INTEGER PRIMARY KEY, user_id INTEGER, de_la TEXT, pana_la TEXT,
         tip TEXT, status TEXT DEFAULT 'in asteptare')""", write=True)
    q("CREATE TABLE IF NOT EXISTS zile_co(user_id INTEGER, an INTEGER, zile REAL DEFAULT 0, PRIMARY KEY(user_id,an))", write=True)
    q("CREATE TABLE IF NOT EXISTS push_abonari(endpoint TEXT PRIMARY KEY, user_id INTEGER, p256dh TEXT, auth TEXT)", write=True)
    q("CREATE TABLE IF NOT EXISTS remindere(zi TEXT, slot TEXT, PRIMARY KEY(zi,slot))", write=True)
    q("CREATE TABLE IF NOT EXISTS setari(cheie TEXT PRIMARY KEY, valoare TEXT)", write=True)
    try:
        q("ALTER TABLE utilizatori ADD COLUMN activ INTEGER DEFAULT 1", write=True)
    except sqlite3.OperationalError:
        pass  # coloana exista deja
    for col in ("ora_de_la", "ora_pana_la"):
        try:
            q(f"ALTER TABLE concedii ADD COLUMN {col} TEXT", write=True)
        except sqlite3.OperationalError:
            pass
    for col, tip in (("functie", "TEXT DEFAULT ''"), ("ore_zi", "REAL DEFAULT 8")):
        try:
            q(f"ALTER TABLE utilizatori ADD COLUMN {col} {tip}", write=True)
        except sqlite3.OperationalError:
            pass
    q("""CREATE TABLE IF NOT EXISTS firme(id INTEGER PRIMARY KEY, denumire TEXT, cui TEXT DEFAULT '',
         adresa TEXT DEFAULT '', contact TEXT DEFAULT '', activ INTEGER DEFAULT 1)""", write=True)
    for col, tip in (("firma_id", "INTEGER"), ("schimba_parola", "INTEGER DEFAULT 0"), ("superadmin", "INTEGER DEFAULT 0")):
        try:
            q(f"ALTER TABLE utilizatori ADD COLUMN {col} {tip}", write=True)
        except sqlite3.OperationalError:
            pass
    if not q("SELECT 1 FROM firme LIMIT 1", one=True):
        q("INSERT INTO firme(id,denumire) VALUES(1,'Firma mea')", write=True)  # firma existenta, o redenumesti din Admin
    q("CREATE TABLE IF NOT EXISTS acorduri(user_id INTEGER, versiune TEXT, raspuns INTEGER, data TEXT, PRIMARY KEY(user_id,versiune))", write=True)
    try:
        q("ALTER TABLE firme ADD COLUMN gdpr_text TEXT DEFAULT ''", write=True)
    except sqlite3.OperationalError:
        pass
    q("""CREATE TABLE IF NOT EXISTS corectii(id INTEGER PRIMARY KEY, user_id INTEGER, data TEXT, ora_venire TEXT,
         ora_plecare TEXT, motiv TEXT, status TEXT, creat TEXT, decis_de INTEGER, decis_la TEXT,
         vechi_venire TEXT, vechi_plecare TEXT)""", write=True)
    try:
        q("ALTER TABLE pontaje ADD COLUMN corectat INTEGER DEFAULT 0", write=True)
    except sqlite3.OperationalError:
        pass
    for tabel, col in [("utilizatori", "locatie INTEGER DEFAULT 0")] + [
            ("pontaje", f"{p}_{c} REAL") for p in ("venire", "plecare") for c in ("lat", "lon", "prec")]:
        try:
            q(f"ALTER TABLE {tabel} ADD COLUMN {col}", write=True)
        except sqlite3.OperationalError:
            pass
    q("""CREATE TABLE IF NOT EXISTS calendare(id INTEGER PRIMARY KEY, user_id INTEGER, nume TEXT, url TEXT,
         vizibil TEXT DEFAULT 'ocupat', ultima TEXT, eroare TEXT, nr INTEGER DEFAULT 0)""", write=True)
    q("CREATE TABLE IF NOT EXISTS evenimente(cal_id INTEGER, user_id INTEGER, inceput TEXT, sfarsit TEXT, titlu TEXT, privat INTEGER)", write=True)
    q("CREATE INDEX IF NOT EXISTS ev_user ON evenimente(user_id, inceput)", write=True)
    q("CREATE TABLE IF NOT EXISTS grupuri(id INTEGER PRIMARY KEY, firma_id INTEGER, nume TEXT)", write=True)
    q("CREATE TABLE IF NOT EXISTS membri_grup(grup_id INTEGER, user_id INTEGER, PRIMARY KEY(grup_id,user_id))", write=True)
    q("""CREATE TABLE IF NOT EXISTS fisiere(id INTEGER PRIMARY KEY, grup_id INTEGER, user_id INTEGER, nume TEXT,
         descriere TEXT, marime INTEGER, creat TEXT, continut BLOB)""", write=True)
    for col in ("nota TEXT DEFAULT ''", "nota_ver INTEGER DEFAULT 0", "nota_de TEXT", "nota_la TEXT"):
        try:
            q(f"ALTER TABLE grupuri ADD COLUMN {col}", write=True)
        except sqlite3.OperationalError:
            pass
    if not q("SELECT 1 FROM utilizatori LIMIT 1", one=True):
        add_user(os.environ.get("ADMIN_USER", "admin"), "Admin", "", os.environ.get("ADMIN_PASS", "schimba-ma"), 1)
        print("Cont admin creat. Schimba parola din ADMIN_PASS!")
    q("UPDATE utilizatori SET firma_id=1 WHERE firma_id IS NULL", write=True)
    if not q("SELECT 1 FROM utilizatori WHERE superadmin=1", one=True):  # proprietarul aplicatiei = primul admin
        q("UPDATE utilizatori SET superadmin=1 WHERE id=(SELECT MIN(id) FROM utilizatori WHERE admin=1)", write=True)


init()


def me(request: Request, authorization: str = Header(default="")):
    tok = authorization.removeprefix("Bearer ").strip()
    u = q("""SELECT u.* FROM sesiuni s JOIN utilizatori u ON u.id=s.user_id
             WHERE s.token=? AND s.creat>? AND COALESCE(u.activ,1)=1
               AND EXISTS (SELECT 1 FROM firme f WHERE f.id=u.firma_id AND COALESCE(f.activ,1)=1)""",
          (tok, time.time() - 60 * 86400), one=True)
    if not u:
        raise HTTPException(401, "Sesiune expirata. Autentifica-te din nou.")
    if u["schimba_parola"] and request.url.path not in ("/api/parola", "/api/eu"):
        raise HTTPException(403, "Trebuie sa-ti schimbi parola inainte de a continua.")
    if request.url.path not in ("/api/parola", "/api/eu", "/api/gdpr") and not acord_ok(u):
        raise HTTPException(403, "Trebuie sa confirmi informarea privind datele personale.")
    return u


def admin(u=Depends(me)):
    if not u["admin"]:
        raise HTTPException(403, "Doar administratorul poate face asta.")
    return u


def owner(u=Depends(me)):  # proprietarul aplicatiei, deasupra firmelor
    if not u["superadmin"]:
        raise HTTPException(403, "Doar proprietarul aplicatiei poate face asta.")
    return u


def acelasi(uid, firma):
    return q("SELECT 1 FROM utilizatori WHERE id=? AND firma_id=?", (uid, firma), one=True) is not None


def profil(u):
    f = q("SELECT id,denumire,cui,adresa,contact FROM firme WHERE id=?", (u["firma_id"],), one=True)
    return {"nume": u["nume"], "prenume": u["prenume"], "admin": u["admin"], "id": u["id"],
            "superadmin": u["superadmin"], "schimba": u["schimba_parola"], "firma": dict(f),
            "gdpr": 0 if acord_ok(u) else 1, "locatie": u["locatie"]}


class Login(BaseModel):
    username: str
    parola: str


class Loc(BaseModel):
    lat: float | None = None
    lon: float | None = None
    prec: float | None = None


def loc_valida(b, u):
    """Pastreaza locatia doar pentru colegii marcati ca lucrand in teren si doar daca sunt coordonate reale."""
    if not (b and u["locatie"] and b.lat is not None and b.lon is not None):
        return None, None, None
    if not (-90 <= b.lat <= 90 and -180 <= b.lon <= 180):
        return None, None, None
    return round(b.lat, 6), round(b.lon, 6), None if b.prec is None else round(min(max(b.prec, 0), 99999))


class NewUser(BaseModel):
    username: str
    nume: str
    prenume: str
    parola: str
    admin: int = 0
    functie: str = ""
    ore_zi: float = 8
    locatie: int = 0


class Pauza(BaseModel):
    minute: int


class Concediu(BaseModel):
    de_la: str
    pana_la: str
    tip: str = "concediu"
    ora_de_la: str | None = None
    ora_pana_la: str | None = None


@app.post("/api/login")
def login(b: Login):
    n, until = fails.get(b.username, (0, 0))
    if until > time.time():
        raise HTTPException(429, "Prea multe incercari. Reincearca in 5 minute.")
    u = q("""SELECT * FROM utilizatori WHERE username=? AND COALESCE(activ,1)=1
             AND firma_id IN (SELECT id FROM firme WHERE COALESCE(activ,1)=1)""", (b.username,), one=True)
    if not u or not secrets.compare_digest(u["hash"], hp(b.parola, u["salt"])):
        fails[b.username] = (n + 1, time.time() + 300 if n + 1 >= 5 else 0)
        raise HTTPException(401, "Utilizator sau parola gresita.")
    fails.pop(b.username, None)
    tok = secrets.token_urlsafe(32)
    q("INSERT INTO sesiuni VALUES(?,?,?)", (tok, u["id"], time.time()), write=True)
    return {"token": tok, **profil(u)}


@app.get("/api/eu")
def eu(u=Depends(me)):
    return profil(u)


def total(r):
    if not (r["ora_venire"] and r["ora_plecare"]):
        return None
    a = datetime.strptime(r["ora_venire"], "%H:%M")
    b = datetime.strptime(r["ora_plecare"], "%H:%M")
    if b < a:
        b += timedelta(days=1)
    return round((b - a).total_seconds() / 3600 - (r["pauza_min"] or 0) / 60, 2)


def out(r):
    d = dict(r)
    d["total_ore"] = total(r)
    return d


@app.post("/api/venire")
def venire(b: Loc | None = None, u=Depends(me)):
    now = datetime.now(TZ)
    zi = now.strftime("%Y-%m-%d")
    r = q("SELECT * FROM pontaje WHERE user_id=? AND data=?", (u["id"], zi), one=True)
    if not r:  # ora de venire nu se suprascrie niciodata
        q("INSERT INTO pontaje(user_id,data,ora_venire,pauza_min,venire_lat,venire_lon,venire_prec) VALUES(?,?,?,?,?,?,?)", (u["id"], zi, now.strftime("%H:%M"), 30 if (u["ore_zi"] or 8) > 6 else 0, *loc_valida(b, u)), write=True)
    return out(q("SELECT * FROM pontaje WHERE user_id=? AND data=?", (u["id"], zi), one=True))


@app.post("/api/plecare")
def plecare(b: Loc | None = None, u=Depends(me)):
    now = datetime.now(TZ)
    ieri = (now - timedelta(days=1)).strftime("%Y-%m-%d")
    r = q("""SELECT * FROM pontaje WHERE user_id=? AND data>=? AND ora_venire IS NOT NULL
             ORDER BY data DESC LIMIT 1""", (u["id"], ieri), one=True)
    if not r:
        raise HTTPException(409, "Nu ai pontat venirea azi.")
    q("UPDATE pontaje SET ora_plecare=?, plecare_lat=?, plecare_lon=?, plecare_prec=? WHERE id=?", (now.strftime("%H:%M"), *loc_valida(b, u), r["id"]), write=True)
    return out(q("SELECT * FROM pontaje WHERE id=?", (r["id"],), one=True))


@app.put("/api/pauza")
def pauza(b: Pauza, u=Depends(me)):
    zi = datetime.now(TZ).strftime("%Y-%m-%d")
    q("UPDATE pontaje SET pauza_min=? WHERE user_id=? AND data=?", (max(0, min(b.minute, 240)), u["id"], zi), write=True)
    r = q("SELECT * FROM pontaje WHERE user_id=? AND data=?", (u["id"], zi), one=True)
    if not r:
        raise HTTPException(409, "Pontează întâi venirea.")
    return out(r)


def luna_rows(luna, user_id=None, firma=None):
    sql = """SELECT p.*, u.nume, u.prenume, COALESCE(u.ore_zi,8) AS ore_zi, COALESCE(u.locatie,0) AS cere_loc FROM pontaje p JOIN utilizatori u ON u.id=p.user_id
             WHERE p.data LIKE ?"""
    args = [luna + "-%"]
    if user_id:
        sql += " AND p.user_id=?"
        args.append(user_id)
    if firma:
        sql += " AND u.firma_id=?"
        args.append(firma)
    return q(sql + " ORDER BY p.data, u.nume", args)


@app.get("/api/pontaje")
def pontaje(luna: str, toti: int = 0, u=Depends(me)):
    if toti and not u["admin"]:
        raise HTTPException(403, "Doar administratorul poate vedea toti colegii.")
    return randuri(luna, None if toti else u["id"], u["firma_id"])


@app.get("/api/export")
def export(luna: str, a=Depends(admin)):
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["Data", "Ora Venire", "Ora Plecare", "Pauza Masa", "Total Ore", "Nume", "Prenume", "Norma", "Diferenta"])
    for r in randuri(luna, None, a["firma_id"]):
        w.writerow([r["data"], r["ora_venire"], r["ora_plecare"], r["pauza_min"], r["total_ore"], r["nume"],
                    r["prenume"], r["norma"], r["diferenta"]])
    return Response(buf.getvalue(), media_type="text/csv",
                    headers={"Content-Disposition": f"attachment; filename=pontaj-{luna}.csv"})


@app.get("/api/utilizatori")
def utilizatori(a=Depends(admin)):
    return [dict(r) for r in q("SELECT id,username,nume,prenume,admin,COALESCE(activ,1) AS activ,COALESCE(functie,'') AS functie,COALESCE(ore_zi,8) AS ore_zi, COALESCE(locatie,0) AS locatie, COALESCE((SELECT raspuns FROM acorduri WHERE user_id=utilizatori.id AND versiune=?),0) AS gdpr FROM utilizatori WHERE firma_id=? ORDER BY nume", (gdpr_info(a["firma_id"])["versiune"], a["firma_id"]))]


@app.post("/api/utilizatori")
def creeaza(b: NewUser, a=Depends(admin)):
    if len(b.parola) < 6:
        raise HTTPException(422, "Parola trebuie sa aiba minim 6 caractere.")
    if not 0.5 <= b.ore_zi <= 12:
        raise HTTPException(422, "Orele pe zi trebuie sa fie intre 0,5 si 12.")
    try:
        return {"id": add_user(b.username.strip(), b.nume.strip(), b.prenume.strip(), b.parola, b.admin, b.functie.strip(), b.ore_zi, a["firma_id"], 1, 1 if b.locatie else 0)}
    except sqlite3.IntegrityError:
        raise HTTPException(409, "Numele de utilizator exista deja in aplicatie. Alege altul, de exemplu cu numele firmei la final.")


@app.post("/api/utilizatori/{uid}/activ/{val}")
def activ(uid: int, val: int, a=Depends(admin)):
    if uid == a["id"]:
        raise HTTPException(422, "Nu te poti dezactiva pe tine.")
    if not acelasi(uid, a["firma_id"]):
        raise HTTPException(404, "Colegul nu exista.")
    q("UPDATE utilizatori SET activ=? WHERE id=?", (1 if val else 0, uid), write=True)
    if not val:
        q("DELETE FROM sesiuni WHERE user_id=?", (uid,), write=True)  # il deconecteaza imediat
    return {"ok": True}


@app.post("/api/concedii")
def cere_concediu(b: Concediu, u=Depends(me)):
    if b.pana_la < b.de_la:
        raise HTTPException(422, "Data de final e inainte de data de inceput.")
    if (date.fromisoformat(b.pana_la) - date.fromisoformat(b.de_la)).days > 366:
        raise HTTPException(422, "Perioada e prea lunga.")
    if b.tip not in ("concediu", "medical", "invoire", "zi_libera", "altele"):
        raise HTTPException(422, "Tip invalid.")
    if b.ora_de_la or b.ora_pana_la:
        ok = (b.tip in ("medical", "invoire") and b.ora_de_la and b.ora_pana_la and b.de_la == b.pana_la
              and "08:00" <= b.ora_de_la < b.ora_pana_la <= "16:30")
        if not ok:
            raise HTTPException(422, "Cererea pe ore: medical sau invoire, o singura zi, intre 08:00 si 16:30.")
    return {"id": q("INSERT INTO concedii(user_id,de_la,pana_la,tip,ora_de_la,ora_pana_la) VALUES(?,?,?,?,?,?)",
                    (u["id"], b.de_la, b.pana_la, b.tip, b.ora_de_la, b.ora_pana_la), write=True)}


@app.get("/api/concedii")
def concedii(toti: int = 0, u=Depends(me)):
    if toti and not u["admin"]:
        raise HTTPException(403, "Doar administratorul poate vedea toate cererile.")
    sql = "SELECT c.*, u.nume, u.prenume FROM concedii c JOIN utilizatori u ON u.id=c.user_id"
    rows = q(sql + (" WHERE u.firma_id=?" if toti else " WHERE c.user_id=?") + " ORDER BY c.de_la DESC",
             (u["firma_id"],) if toti else (u["id"],))
    return [dict(r) for r in rows]


@app.delete("/api/concedii/{cid}")
def anuleaza(cid: int, u=Depends(me)):
    c = q("SELECT * FROM concedii WHERE id=?", (cid,), one=True)
    if not c or (c["user_id"] != u["id"] and not (u["admin"] and acelasi(c["user_id"], u["firma_id"]))):
        raise HTTPException(404, "Cererea nu exista.")
    if not u["admin"] and c["status"] != "in asteptare":
        raise HTTPException(403, "Cererea e deja procesata. Cere administratorului sa o anuleze.")
    q("DELETE FROM concedii WHERE id=?", (cid,), write=True)
    return {"ok": True}


@app.post("/api/concedii/{cid}/{status}")
def decide(cid: int, status: str, a=Depends(admin)):
    if status not in ("aprobat", "respins"):
        raise HTTPException(422, "Status invalid.")
    q("UPDATE concedii SET status=? WHERE id=? AND user_id IN (SELECT id FROM utilizatori WHERE firma_id=?)",
      (status, cid, a["firma_id"]), write=True)
    return {"ok": True}


class Zile(BaseModel):
    user_id: int
    an: int
    zile: float


@lru_cache(maxsize=None)
def sarbatori(an):
    """Sarbatorile legale din Romania: fixe + cele legate de Pastele ortodox."""
    a, b, c = an % 4, an % 7, an % 19
    d = (19 * c + 15) % 30
    e = (2 * a + 4 * b - d + 34) % 7
    luna, zi = divmod(d + e + 114, 31)
    pasti = date(an, luna, zi + 1) + timedelta(days=13)
    fixe = [(1, 1), (1, 2), (1, 6), (1, 7), (1, 24), (5, 1), (6, 1), (8, 15), (11, 30), (12, 1), (12, 25), (12, 26)]
    mobile = [pasti + timedelta(days=x) for x in (-2, 0, 1, 49, 50)]  # Vinerea Mare, Paste, Rusalii
    return frozenset([date(an, m, z) for m, z in fixe] + mobile)


def zile_lucratoare(a, b, an=None):
    d, sfarsit, n = date.fromisoformat(a), date.fromisoformat(b), 0
    while d <= sfarsit:
        if d.weekday() < 5 and d not in sarbatori(d.year) and (an is None or d.year == an):
            n += 1
        d += timedelta(days=1)
    return n


def sold(uid):
    al = {r["an"]: r["zile"] for r in q("SELECT an,zile FROM zile_co WHERE user_id=?", (uid,))}

    def folosit(status, an):
        rows = q("SELECT de_la,pana_la FROM concedii WHERE user_id=? AND tip='concediu' AND status=?", (uid, status))
        return sum(zile_lucratoare(c["de_la"], c["pana_la"], an) for c in rows)

    u25, u26 = folosit("aprobat", 2025), folosit("aprobat", 2026)
    r25 = al.get(2025, 0) - u25
    din_25 = min(max(r25, 0), u26)  # zilele din 2026 se scad intai din soldul lui 2025
    return {"2025": {"alocat": al.get(2025, 0), "ramase": r25 - din_25},
            "2026": {"alocat": al.get(2026, 0), "ramase": al.get(2026, 0) - (u26 - din_25)},
            "in_asteptare": folosit("in asteptare", None)}


@app.get("/api/zile-co")
def zile_co(user_id: int = 0, u=Depends(me)):
    if user_id and user_id != u["id"] and not u["admin"]:
        raise HTTPException(403, "Doar administratorul poate vedea soldul altui coleg.")
    if user_id and user_id != u["id"] and not acelasi(user_id, u["firma_id"]):
        raise HTTPException(404, "Colegul nu exista.")
    return sold(user_id or u["id"])


@app.put("/api/zile-co")
def seteaza_zile(b: Zile, a=Depends(admin)):
    if not acelasi(b.user_id, a["firma_id"]):
        raise HTTPException(404, "Colegul nu exista.")
    q("""INSERT INTO zile_co(user_id,an,zile) VALUES(?,?,?)
         ON CONFLICT(user_id,an) DO UPDATE SET zile=excluded.zile""", (b.user_id, b.an, b.zile), write=True)
    return {"ok": True}


class Abonare(BaseModel):
    endpoint: str
    keys: dict


def vapid():
    r = q("SELECT valoare FROM setari WHERE cheie='vapid_pem'", one=True)
    if r:
        pem = r["valoare"].encode()
    else:
        nou = Vapid()
        nou.generate_keys()
        pem = nou.private_pem()
        q("INSERT INTO setari VALUES('vapid_pem',?)", (pem.decode(),), write=True)
    v = Vapid.from_pem(pem)
    pub = v.public_key.public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
    return v, base64.urlsafe_b64encode(pub).rstrip(b"=").decode()


def trimite(user_id, titlu, text):
    if not webpush:
        return 0
    v, n = vapid()[0], 0
    for s in q("SELECT * FROM push_abonari WHERE user_id=?", (user_id,)):
        try:
            webpush({"endpoint": s["endpoint"], "keys": {"p256dh": s["p256dh"], "auth": s["auth"]}},
                    json.dumps({"titlu": titlu, "text": text}), vapid_private_key=v,
                    vapid_claims={"sub": "mailto:" + os.environ.get("VAPID_EMAIL", "admin@example.com")})
            n += 1
        except WebPushException as e:
            if e.response is not None and e.response.status_code in (404, 410):  # abonare expirata
                q("DELETE FROM push_abonari WHERE endpoint=?", (s["endpoint"],), write=True)
        except Exception as e:
            print("Eroare notificare:", e)
    return n


def de_reamintit(zi, firma=None):
    """Cei care nu au pontat venirea si nu sunt liberi (CO, medical, invoire etc. aprobate)."""
    d = date.fromisoformat(zi)
    if d.weekday() >= 5 or d in sarbatori(d.year):
        return []
    rows = q("""SELECT DISTINCT a.user_id FROM push_abonari a JOIN utilizatori u ON u.id=a.user_id
        WHERE COALESCE(u.activ,1)=1
          AND NOT EXISTS (SELECT 1 FROM pontaje p WHERE p.user_id=a.user_id AND p.data=? AND p.ora_venire IS NOT NULL)
          AND NOT EXISTS (SELECT 1 FROM concedii c WHERE c.user_id=a.user_id AND c.status='aprobat'
                          AND (c.ora_de_la IS NULL OR c.ora_de_la<='08:10') AND ? BETWEEN c.de_la AND c.pana_la)
          AND (? IS NULL OR u.firma_id=?)""", (zi, zi, firma, firma))
    return [r["user_id"] for r in rows]


SLOTURI = {"07:50": ("Pontaj", "Nu uita să apeși Venire."),
           "08:10": ("Nu ai pontat încă", "Apasă Venire dacă ai început lucrul.")}


def remindere(slot, zi, firma=None):
    titlu, text = SLOTURI[slot]
    return sum(trimite(uid, titlu, text) for uid in de_reamintit(zi, firma))


def claim(zi, slot):  # un singur proces trimite fiecare reminder, o singura data pe zi
    con = sqlite3.connect(DB)
    try:
        cur = con.execute("INSERT OR IGNORE INTO remindere VALUES(?,?)", (zi, slot))
        con.commit()
        return cur.rowcount == 1
    finally:
        con.close()


def bucla():
    while True:
        try:
            acum = datetime.now(TZ)
            zi = acum.strftime("%Y-%m-%d")
            for slot in SLOTURI:
                h, m = map(int, slot.split(":"))
                t = acum.replace(hour=h, minute=m, second=0, microsecond=0)
                if t <= acum < t + timedelta(minutes=5) and claim(zi, slot):
                    remindere(slot, zi)
        except Exception as e:
            print("Eroare remindere:", e)
        time.sleep(30)


threading.Thread(target=bucla, daemon=True).start()


@app.get("/api/push/cheie")
def push_cheie(_=Depends(me)):
    if not webpush:
        raise HTTPException(503, "Lipseste pachetul pywebpush. Ruleaza: python -m pip install -r requirements.txt")
    return {"cheie": vapid()[1]}


@app.post("/api/push/abonare")
def push_abonare(b: Abonare, u=Depends(me)):
    q("""INSERT INTO push_abonari VALUES(?,?,?,?) ON CONFLICT(endpoint)
         DO UPDATE SET user_id=excluded.user_id, p256dh=excluded.p256dh, auth=excluded.auth""",
      (b.endpoint, u["id"], b.keys.get("p256dh"), b.keys.get("auth")), write=True)
    return {"ok": True}


@app.post("/api/push/test")
def push_test(u=Depends(me)):
    if not trimite(u["id"], "Pontaj", "Notificările funcționează."):
        raise HTTPException(409, "Nu am putut trimite. Activeaza notificarile pe acest dispozitiv.")
    return {"ok": True}


@app.post("/api/push/remindere-acum")
def remindere_acum(a=Depends(admin)):
    return {"trimise": remindere("08:10", datetime.now(TZ).strftime("%Y-%m-%d"), a["firma_id"])}


NORMA = 8.0  # 8:00-16:30 minus pauza 11:30-12:00


def ore_partiale(c):
    """Ore din program (8:00-16:30, fara pauza 11:30-12:00) acoperite de o cerere pe ore."""
    def m(t):
        h, mi = map(int, t.split(":"))
        return h * 60 + mi
    a, b = max(m(c["ora_de_la"]), 480), min(m(c["ora_pana_la"]), 990)
    if b <= a:
        return 0.0
    return round((b - a - max(0, min(b, 720) - max(a, 690))) / 60, 2)


def norma_zi(zi, cereri, ore_zi=NORMA):
    d = date.fromisoformat(zi)
    if d.weekday() >= 5 or d in sarbatori(d.year):
        return 0.0
    n = ore_zi
    for c in cereri:  # cereri aprobate ale colegului
        if c["de_la"] <= zi <= c["pana_la"]:
            if c["ora_de_la"] and c["ora_pana_la"]:
                n -= ore_partiale(c)
            else:
                return 0.0
    return max(n, 0.0)


def randuri(luna, uid=None, firma=None):
    cereri = {}
    for c in q("SELECT * FROM concedii WHERE status='aprobat' AND pana_la>=? AND de_la<=?", (luna + "-01", luna + "-31")):
        cereri.setdefault(c["user_id"], []).append(c)
    res = []
    for r in luna_rows(luna, uid, firma):
        d = out(r)
        d["norma"] = norma_zi(r["data"], cereri.get(r["user_id"], []), r["ore_zi"])
        d["diferenta"] = None if d["total_ore"] is None else round(d["total_ore"] - d["norma"], 2)
        res.append(d)
    return res


def rezumat(uid, luna):
    """Ore lucrate vs norma, pana ieri (azi doar daca ziua e incheiata)."""
    azi = datetime.now(TZ).strftime("%Y-%m-%d")
    an, ln = map(int, luna.split("-"))
    d, sf = date(an, ln, 1), date(an + (ln == 12), ln % 12 + 1, 1) - timedelta(days=1)
    cereri = q("SELECT * FROM concedii WHERE status='aprobat' AND user_id=? AND pana_la>=? AND de_la<=?",
               (uid, d.isoformat(), sf.isoformat()))
    pontaj = {r["data"]: r for r in luna_rows(luna, uid)}
    ore = q("SELECT COALESCE(ore_zi,8) AS o FROM utilizatori WHERE id=?", (uid,), one=True)["o"]
    lucrate = norma = 0.0
    while d <= sf:
        zi, r = d.isoformat(), pontaj.get(d.isoformat())
        if zi < azi or (zi == azi and r and r["ora_plecare"]):
            norma += norma_zi(zi, cereri, ore)
        if r and total(r) is not None:
            lucrate += total(r)
        d += timedelta(days=1)
    return {"lucrate": round(lucrate, 2), "norma": round(norma, 2), "diferenta": round(lucrate - norma, 2)}


@app.get("/api/rezumat")
def rezumat_luna(luna: str, toti: int = 0, u=Depends(me)):
    if not toti:
        return rezumat(u["id"], luna)
    if not u["admin"]:
        raise HTTPException(403, "Doar administratorul poate vedea toti colegii.")
    return [{**dict(x), **rezumat(x["id"], luna)}
            for x in q("SELECT id,nume,prenume FROM utilizatori WHERE COALESCE(activ,1)=1 AND firma_id=? ORDER BY nume", (u["firma_id"],))]


class Detalii(BaseModel):
    nume: str
    prenume: str
    functie: str = ""
    ore_zi: float = 8
    locatie: int = 0


class Parola(BaseModel):
    veche: str
    noua: str


@app.put("/api/utilizatori/{uid}")
def modifica(uid: int, b: Detalii, a=Depends(admin)):
    if not 0.5 <= b.ore_zi <= 12:
        raise HTTPException(422, "Orele pe zi trebuie sa fie intre 0,5 si 12.")
    if not acelasi(uid, a["firma_id"]):
        raise HTTPException(404, "Colegul nu exista.")
    q("UPDATE utilizatori SET nume=?, prenume=?, functie=?, ore_zi=?, locatie=? WHERE id=?",
      (b.nume.strip(), b.prenume.strip(), b.functie.strip(), b.ore_zi, 1 if b.locatie else 0, uid), write=True)
    return {"ok": True}


@app.post("/api/parola")
def schimba_parola(b: Parola, u=Depends(me), authorization: str = Header(default="")):
    if not secrets.compare_digest(u["hash"], hp(b.veche, u["salt"])):
        raise HTTPException(403, "Parola actuala e gresita.")
    if len(b.noua) < 6:
        raise HTTPException(422, "Parola noua trebuie sa aiba minim 6 caractere.")
    if b.noua == b.veche:
        raise HTTPException(422, "Alege o parola diferita de cea actuala.")
    salt = secrets.token_hex(8)
    q("UPDATE utilizatori SET salt=?, hash=?, schimba_parola=0 WHERE id=?", (salt, hp(b.noua, salt), u["id"]), write=True)
    tok = authorization.removeprefix("Bearer ").strip()
    q("DELETE FROM sesiuni WHERE user_id=? AND token<>?", (u["id"], tok), write=True)  # deconecteaza celelalte dispozitive
    return {"ok": True}


class DateFirma(BaseModel):
    denumire: str
    cui: str = ""
    adresa: str = ""
    contact: str = ""


class FirmaNoua(DateFirma):
    admin_username: str
    admin_nume: str
    admin_prenume: str = ""
    admin_parola: str


@app.put("/api/firma")
def modifica_firma(b: DateFirma, a=Depends(admin)):
    if not b.denumire.strip():
        raise HTTPException(422, "Scrie denumirea firmei.")
    q("UPDATE firme SET denumire=?, cui=?, adresa=?, contact=? WHERE id=?",
      (b.denumire.strip(), b.cui.strip(), b.adresa.strip(), b.contact.strip(), a["firma_id"]), write=True)
    return profil(a)["firma"]


@app.get("/api/firme")
def firme(_=Depends(owner)):
    return [dict(r) for r in q("""SELECT f.*, (SELECT COUNT(*) FROM utilizatori u
        WHERE u.firma_id=f.id AND COALESCE(u.activ,1)=1) AS colegi FROM firme f ORDER BY f.denumire""")]


@app.post("/api/firme")
def firma_noua(b: FirmaNoua, _=Depends(owner)):
    user = b.admin_username.strip()
    if not b.denumire.strip() or not user or not b.admin_nume.strip():
        raise HTTPException(422, "Completeaza denumirea firmei si utilizatorul + numele administratorului.")
    if len(b.admin_parola) < 6:
        raise HTTPException(422, "Parola initiala trebuie sa aiba minim 6 caractere.")
    if q("SELECT 1 FROM utilizatori WHERE username=?", (user,), one=True):
        raise HTTPException(409, "Numele de utilizator exista deja in aplicatie. Alege altul.")
    fid = q("INSERT INTO firme(denumire,cui,adresa,contact) VALUES(?,?,?,?)",
            (b.denumire.strip(), b.cui.strip(), b.adresa.strip(), b.contact.strip()), write=True)
    add_user(user, b.admin_nume.strip(), b.admin_prenume.strip(), b.admin_parola, 1, "Administrator", 8.0, fid, 1)
    return {"id": fid}


@app.post("/api/firme/{fid}/activ/{val}")
def firma_activ(fid: int, val: int, o=Depends(owner)):
    if fid == o["firma_id"]:
        raise HTTPException(422, "Nu iti poti dezactiva propria firma.")
    q("UPDATE firme SET activ=? WHERE id=?", (1 if val else 0, fid), write=True)
    if not val:  # deconecteaza imediat toata firma
        q("DELETE FROM sesiuni WHERE user_id IN (SELECT id FROM utilizatori WHERE firma_id=?)", (fid,), write=True)
    return {"ok": True}


def implicit(f):
    cui = f" (CUI {f['cui']})" if f["cui"] else ""
    loc = ""
    if q("SELECT 1 FROM utilizatori WHERE firma_id=? AND locatie=1 AND COALESCE(activ,1)=1", (f["id"],), one=True):
        loc = ("\n\nLocația: pentru colegii marcați de administrator că lucrează în teren, se salvează locația dispozitivului "
               "doar în momentul în care apeși Venire sau Plecare. Locația nu este urmărită continuu.")
    if q("SELECT 1 FROM calendare c JOIN utilizatori u ON u.id=c.user_id WHERE u.firma_id=?", (f["id"],), one=True):
        loc += ("\n\nCalendar: dacă îți conectezi calendarul, aplicația citește evenimentele lui (ora și, dacă alegi, titlul) "
                "și le arată colegilor din grupurile tale doar așa cum decizi tu: ocupat, cu titlu sau deloc. "
                "Poți șterge calendarul oricând, iar datele importate se șterg odată cu el.")
    if q("""SELECT 1 FROM grupuri g WHERE g.firma_id=? AND (COALESCE(g.nota,'')<>''
            OR EXISTS (SELECT 1 FROM fisiere x WHERE x.grup_id=g.id))""", (f["id"],), one=True):
        loc += "\n\nDocumente: fișierele și notele din grupurile de calendar sunt vizibile doar membrilor grupului respectiv."
    return f"""Informare privind prelucrarea datelor personale

Operator: {f['denumire']}{cui}. Contact: {f['contact'] or 'administratorul firmei'}.

Ce date prelucrăm: nume, prenume, funcție, orele de venire și plecare, cererile de concediu și de învoire și, dacă le activezi, notificările de pe dispozitiv.

De ce: pentru evidența timpului de lucru și a concediilor și pentru calculul orelor lucrate.{loc}

Cine le vede: tu și administratorul firmei {f['denumire']}. Furnizorul aplicației le prelucrează doar pentru ca aplicația să funcționeze.

Cât timp: cât durează raportul de muncă și pe perioadele impuse de lege.

Drepturile tale: acces, rectificare, ștergere, restricționare, opoziție și plângere la Autoritatea Națională de Supraveghere a Prelucrării Datelor cu Caracter Personal (ANSPDCP). Pentru orice cerere, scrie la datele de contact de mai sus."""


def gdpr_info(firma_id):
    f = q("SELECT * FROM firme WHERE id=?", (firma_id,), one=True)
    text = (f["gdpr_text"] or "").strip() or implicit(f)
    return {"text": text, "versiune": hashlib.sha256(text.encode()).hexdigest()[:10]}


def acord_ok(u):
    r = q("SELECT raspuns FROM acorduri WHERE user_id=? AND versiune=?", (u["id"], gdpr_info(u["firma_id"])["versiune"]), one=True)
    return bool(r and r["raspuns"])


def inregistreaza_acord(uid, versiune, raspuns):
    q("INSERT OR REPLACE INTO acorduri VALUES(?,?,?,?)",
      (uid, versiune, 1 if raspuns else 0, datetime.now(TZ).isoformat(timespec="seconds")), write=True)


class Acord(BaseModel):
    versiune: str
    raspuns: bool


class TextGdpr(BaseModel):
    text: str


@app.get("/api/gdpr")
def gdpr(u=Depends(me)):
    return gdpr_info(u["firma_id"])


@app.post("/api/gdpr")
def gdpr_raspuns(b: Acord, u=Depends(me)):
    if b.versiune != gdpr_info(u["firma_id"])["versiune"]:
        raise HTTPException(409, "Informarea s-a schimbat. Reincarca pagina.")
    inregistreaza_acord(u["id"], b.versiune, b.raspuns)
    if not b.raspuns:  # fara confirmare nu poate folosi aplicatia
        q("DELETE FROM sesiuni WHERE user_id=?", (u["id"],), write=True)
    return {"ok": True}


@app.put("/api/gdpr-text")
def gdpr_text(b: TextGdpr, a=Depends(admin)):
    f = q("SELECT * FROM firme WHERE id=?", (a["firma_id"],), one=True)
    t = b.text.strip()
    q("UPDATE firme SET gdpr_text=? WHERE id=?", ("" if t == implicit(f).strip() else t, a["firma_id"]), write=True)
    g = gdpr_info(a["firma_id"])
    inregistreaza_acord(a["id"], g["versiune"], True)  # cine scrie textul nu e intrebat si el
    return g


class Corectie(BaseModel):
    data: str
    ora_venire: str | None = None
    ora_plecare: str | None = None
    motiv: str = ""


class CorectieAdmin(Corectie):
    user_id: int


def valideaza_corectie(b, zile_inapoi):
    azi = datetime.now(TZ).date()
    try:
        d = date.fromisoformat(b.data)
    except ValueError:
        raise HTTPException(422, "Data nu este valida.")
    if d > azi:
        raise HTTPException(422, "Nu poti corecta o zi din viitor.")
    if (azi - d).days > zile_inapoi:
        raise HTTPException(422, f"Se pot corecta doar zilele din ultimele {zile_inapoi} de zile.")
    if not (b.ora_venire or b.ora_plecare):
        raise HTTPException(422, "Completeaza cel putin o ora.")
    for t in (b.ora_venire, b.ora_plecare):
        if t:
            try:
                datetime.strptime(t, "%H:%M")
            except ValueError:
                raise HTTPException(422, "Ora trebuie sa fie in formatul HH:MM.")


def aplica_corectie(c):
    """Scrie orele in pontaj (suprascrie doar ce s-a completat). Intoarce randul vechi, pentru istoric."""
    r = q("SELECT * FROM pontaje WHERE user_id=? AND data=?", (c["user_id"], c["data"]), one=True)
    if r:
        q("UPDATE pontaje SET ora_venire=COALESCE(?,ora_venire), ora_plecare=COALESCE(?,ora_plecare), corectat=1 WHERE id=?",
          (c["ora_venire"], c["ora_plecare"], r["id"]), write=True)
    else:
        ore = q("SELECT COALESCE(ore_zi,8) AS o FROM utilizatori WHERE id=?", (c["user_id"],), one=True)["o"]
        q("INSERT INTO pontaje(user_id,data,ora_venire,ora_plecare,pauza_min,corectat) VALUES(?,?,?,?,?,1)",
          (c["user_id"], c["data"], c["ora_venire"], c["ora_plecare"], 30 if ore > 6 else 0), write=True)
    return r


def inchide_corectie(cid, c, status, decis_de):
    vechi = aplica_corectie(c) if status == "aprobat" else None
    q("UPDATE corectii SET status=?, decis_de=?, decis_la=?, vechi_venire=?, vechi_plecare=? WHERE id=?",
      (status, decis_de, datetime.now(TZ).isoformat(timespec="seconds"),
       vechi["ora_venire"] if vechi else None, vechi["ora_plecare"] if vechi else None, cid), write=True)


@app.post("/api/corectii")
def cere_corectie(b: Corectie, u=Depends(me)):
    valideaza_corectie(b, 62)
    if q("SELECT 1 FROM corectii WHERE user_id=? AND data=? AND status='in asteptare'", (u["id"], b.data), one=True):
        raise HTTPException(409, "Ai deja o cerere in asteptare pentru ziua asta.")
    return {"id": q("INSERT INTO corectii(user_id,data,ora_venire,ora_plecare,motiv,status,creat) VALUES(?,?,?,?,?,'in asteptare',?)",
                    (u["id"], b.data, b.ora_venire or None, b.ora_plecare or None, b.motiv.strip(),
                     datetime.now(TZ).isoformat(timespec="seconds")), write=True)}


@app.get("/api/corectii")
def corectii(toti: int = 0, u=Depends(me)):
    if toti and not u["admin"]:
        raise HTTPException(403, "Doar administratorul poate vedea cererile colegilor.")
    sql = """SELECT c.*, x.nume, x.prenume, p.ora_venire AS actual_venire, p.ora_plecare AS actual_plecare
             FROM corectii c JOIN utilizatori x ON x.id=c.user_id
             LEFT JOIN pontaje p ON p.user_id=c.user_id AND p.data=c.data"""
    rows = q(sql + (" WHERE x.firma_id=?" if toti else " WHERE c.user_id=?") + " ORDER BY c.data DESC, c.id DESC LIMIT 100",
             (u["firma_id"],) if toti else (u["id"],))
    return [dict(r) for r in rows]


@app.delete("/api/corectii/{cid}")
def anuleaza_corectie(cid: int, u=Depends(me)):
    r = q("DELETE FROM corectii WHERE id=? AND user_id=? AND status='in asteptare'", (cid, u["id"]), write=True)
    return {"ok": True}


@app.post("/api/corectii/{cid}/{status}")
def decide_corectie(cid: int, status: str, a=Depends(admin)):
    if status not in ("aprobat", "respins"):
        raise HTTPException(422, "Status invalid.")
    c = q("SELECT * FROM corectii WHERE id=? AND status='in asteptare'", (cid,), one=True)
    if not c or not acelasi(c["user_id"], a["firma_id"]):
        raise HTTPException(404, "Cererea nu exista sau a fost deja tratata.")
    inchide_corectie(cid, c, status, a["id"])
    return {"ok": True}


@app.post("/api/corectii-admin")
def corecteaza(b: CorectieAdmin, a=Depends(admin)):
    if not acelasi(b.user_id, a["firma_id"]):
        raise HTTPException(404, "Colegul nu exista.")
    valideaza_corectie(b, 366)
    acum = datetime.now(TZ).isoformat(timespec="seconds")
    cid = q("INSERT INTO corectii(user_id,data,ora_venire,ora_plecare,motiv,status,creat) VALUES(?,?,?,?,?,'in asteptare',?)",
            (b.user_id, b.data, b.ora_venire or None, b.ora_plecare or None, b.motiv.strip() or "Corectat de administrator", acum), write=True)
    inchide_corectie(cid, q("SELECT * FROM corectii WHERE id=?", (cid,), one=True), "aprobat", a["id"])
    return {"ok": True}


VIZIBIL = ("ocupat", "detalii", "ascuns")


class CalNou(BaseModel):
    nume: str
    url: str
    vizibil: str = "ocupat"


class CalMod(BaseModel):
    nume: str
    vizibil: str


class Grup(BaseModel):
    nume: str
    membri: list[int] = []


def iso(dt):
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S")


def sincronizeaza(cid):
    """Descarca calendarul si ii inlocuieste evenimentele. Intoarce None sau un mesaj de eroare pentru om."""
    c = q("SELECT * FROM calendare WHERE id=?", (cid,), one=True)
    if not c:
        return None
    acum = datetime.now(timezone.utc)
    ev, eroare = None, None
    try:
        ev = calimport.evenimente(calimport.descarca(c["url"]), acum - timedelta(days=2), acum + timedelta(days=120))
    except calimport.EroareCalendar as e:
        eroare = str(e)
    except Exception as e:
        print("Eroare calendar:", type(e).__name__)  # fara adresa, ea e secreta
        eroare = "Calendarul nu a putut fi citit."
    con = sqlite3.connect(DB)
    try:
        if ev is not None:
            con.execute("DELETE FROM evenimente WHERE cal_id=?", (cid,))
            con.executemany("INSERT INTO evenimente VALUES(?,?,?,?,?,?)",
                            [(cid, c["user_id"], iso(e["inceput"]), iso(e["sfarsit"]), e["titlu"], 1 if e["privat"] else 0) for e in ev])
        con.execute("UPDATE calendare SET ultima=?, eroare=?, nr=? WHERE id=?",
                    (iso(acum) if ev is not None else c["ultima"], eroare, len(ev) if ev is not None else c["nr"], cid))
        con.commit()
    finally:
        con.close()
    return eroare


def bucla_calendare():
    time.sleep(60)
    while True:
        try:
            for r in q("""SELECT c.id FROM calendare c JOIN utilizatori u ON u.id=c.user_id
                          WHERE COALESCE(u.activ,1)=1 AND u.firma_id IN (SELECT id FROM firme WHERE COALESCE(activ,1)=1)"""):
                sincronizeaza(r["id"])
        except Exception as e:
            print("Eroare sincronizare calendare:", e)
        time.sleep(900)


threading.Thread(target=bucla_calendare, daemon=True).start()


def cal_al_meu(cid, u):
    c = q("SELECT * FROM calendare WHERE id=? AND user_id=?", (cid, u["id"]), one=True)
    if not c:
        raise HTTPException(404, "Calendarul nu exista.")
    return c


@app.get("/api/calendare")
def calendare(u=Depends(me)):  # adresa ICS e secreta: se arata doar serverul
    return [{**{k: r[k] for k in ("id", "nume", "vizibil", "ultima", "eroare", "nr")}, "sursa": urlparse(r["url"]).hostname}
            for r in q("SELECT * FROM calendare WHERE user_id=? ORDER BY id", (u["id"],))]


@app.post("/api/calendare")
def calendar_nou(b: CalNou, u=Depends(me)):
    if b.vizibil not in VIZIBIL:
        raise HTTPException(422, "Alege ce vad colegii.")
    if not b.nume.strip():
        raise HTTPException(422, "Da-i un nume calendarului.")
    if q("SELECT COUNT(*) c FROM calendare WHERE user_id=?", (u["id"],), one=True)["c"] >= 5:
        raise HTTPException(422, "Poti conecta cel mult 5 calendare.")
    try:
        calimport.url_sigur(b.url)
    except calimport.EroareCalendar as e:
        raise HTTPException(422, str(e))
    cid = q("INSERT INTO calendare(user_id,nume,url,vizibil) VALUES(?,?,?,?)", (u["id"], b.nume.strip()[:60], b.url.strip(), b.vizibil), write=True)
    eroare = sincronizeaza(cid)
    if eroare:  # nu pastram un calendar care nu merge de la prima incercare
        q("DELETE FROM calendare WHERE id=?", (cid,), write=True)
        raise HTTPException(422, eroare)
    return {"id": cid}


@app.put("/api/calendare/{cid}")
def calendar_mod(cid: int, b: CalMod, u=Depends(me)):
    cal_al_meu(cid, u)
    if b.vizibil not in VIZIBIL:
        raise HTTPException(422, "Alege ce vad colegii.")
    q("UPDATE calendare SET nume=?, vizibil=? WHERE id=?", (b.nume.strip()[:60] or "Calendar", b.vizibil, cid), write=True)
    return {"ok": True}


@app.delete("/api/calendare/{cid}")
def calendar_sterge(cid: int, u=Depends(me)):
    cal_al_meu(cid, u)
    q("DELETE FROM evenimente WHERE cal_id=?", (cid,), write=True)
    q("DELETE FROM calendare WHERE id=?", (cid,), write=True)
    return {"ok": True}


@app.post("/api/calendare/{cid}/sync")
def calendar_sync(cid: int, u=Depends(me)):
    cal_al_meu(cid, u)
    return {"eroare": sincronizeaza(cid)}


def membri_grup(gid):
    return [dict(r) for r in q("""SELECT x.id, x.nume, x.prenume FROM membri_grup m JOIN utilizatori x ON x.id=m.user_id
                                  WHERE m.grup_id=? AND COALESCE(x.activ,1)=1 ORDER BY x.nume""", (gid,))]


def grup_accesibil(gid, u):
    g = q("SELECT * FROM grupuri WHERE id=? AND firma_id=?", (gid, u["firma_id"]), one=True)
    if not g or not (u["admin"] or q("SELECT 1 FROM membri_grup WHERE grup_id=? AND user_id=?", (gid, u["id"]), one=True)):
        raise HTTPException(404, "Grupul nu exista.")
    return g


def seteaza_membri(gid, ids, firma):
    q("DELETE FROM membri_grup WHERE grup_id=?", (gid,), write=True)
    for i in set(ids):
        q("INSERT INTO membri_grup VALUES(?,?)", (gid, i), write=True)


def valideaza_grup(b, firma):
    if not b.nume.strip():
        raise HTTPException(422, "Scrie numele grupului.")
    if any(not acelasi(i, firma) for i in b.membri):
        raise HTTPException(404, "Un coleg din lista nu exista.")


@app.get("/api/grupuri")
def grupuri(u=Depends(me)):
    if u["admin"]:
        rows = q("SELECT * FROM grupuri WHERE firma_id=? ORDER BY nume", (u["firma_id"],))
    else:
        rows = q("""SELECT g.* FROM grupuri g JOIN membri_grup m ON m.grup_id=g.id
                    WHERE g.firma_id=? AND m.user_id=? ORDER BY g.nume""", (u["firma_id"], u["id"]))
    return [{"id": g["id"], "nume": g["nume"], "membri": membri_grup(g["id"])} for g in rows]


@app.post("/api/grupuri")
def grup_nou(b: Grup, a=Depends(admin)):
    valideaza_grup(b, a["firma_id"])
    gid = q("INSERT INTO grupuri(firma_id,nume) VALUES(?,?)", (a["firma_id"], b.nume.strip()[:60]), write=True)
    seteaza_membri(gid, b.membri, a["firma_id"])
    return {"id": gid}


@app.put("/api/grupuri/{gid}")
def grup_mod(gid: int, b: Grup, a=Depends(admin)):
    grup_accesibil(gid, a)
    valideaza_grup(b, a["firma_id"])
    q("UPDATE grupuri SET nume=? WHERE id=?", (b.nume.strip()[:60], gid), write=True)
    seteaza_membri(gid, b.membri, a["firma_id"])
    return {"ok": True}


@app.delete("/api/grupuri/{gid}")
def grup_sterge(gid: int, a=Depends(admin)):
    grup_accesibil(gid, a)
    q("DELETE FROM fisiere WHERE grup_id=?", (gid,), write=True)
    q("DELETE FROM membri_grup WHERE grup_id=?", (gid,), write=True)
    q("DELETE FROM grupuri WHERE id=?", (gid,), write=True)
    return {"ok": True}


def blocuri_zi(uid, zi, viewer):
    """Ce vede 'viewer' din ziua 'zi' a lui 'uid', dupa alegerile lui uid. Intoarce (blocuri in minute, stare)."""
    d = date.fromisoformat(zi)
    inc = datetime(d.year, d.month, d.day, tzinfo=TZ)
    sf = inc + timedelta(days=1)
    mn = lambda dt: max(0, min(1440, int((dt.astimezone(TZ) - inc).total_seconds() // 60)))
    propriu = uid == viewer
    cals = {c["id"]: c["vizibil"] for c in q("SELECT id,vizibil FROM calendare WHERE user_id=?", (uid,))}
    bl = []
    for r in q("SELECT * FROM evenimente WHERE user_id=? AND inceput<? AND sfarsit>?", (uid, iso(sf), iso(inc))):
        viz = "detalii" if propriu else cals.get(r["cal_id"], "ascuns")
        if viz == "ascuns":
            continue
        de = mn(datetime.fromisoformat(r["inceput"]).replace(tzinfo=timezone.utc))
        pana = mn(datetime.fromisoformat(r["sfarsit"]).replace(tzinfo=timezone.utc))
        if pana > de:
            bl.append({"de": de, "pana": pana, "tip": "ocupat",
                       "titlu": r["titlu"] if viz == "detalii" and (propriu or not r["privat"]) else None})
    hm = lambda t: int(t[:2]) * 60 + int(t[3:5])
    for c in q("SELECT * FROM concedii WHERE user_id=? AND status='aprobat' AND ? BETWEEN de_la AND pana_la", (uid, zi)):
        # doar "Absent": tipul concediului (de exemplu medical) nu se arata colegilor
        de, pana = (hm(c["ora_de_la"]), hm(c["ora_pana_la"])) if c["ora_de_la"] and c["ora_pana_la"] else (0, 1440)
        bl.append({"de": de, "pana": pana, "tip": "absent", "titlu": "Absent"})
    stare = "fara_calendar" if not cals else ("nepartajat" if not propriu and all(v == "ascuns" for v in cals.values()) else "ok")
    return sorted(bl, key=lambda b: b["de"]), stare


@app.get("/api/program")
def program(grup: int, data: str, u=Depends(me)):
    grup_accesibil(grup, u)
    try:
        date.fromisoformat(data)
    except ValueError:
        raise HTTPException(422, "Data nu este valida.")
    rez = []
    for p in membri_grup(grup):
        bl, stare = blocuri_zi(p["id"], data, u["id"])
        rez.append({**p, "blocuri": bl, "stare": stare})
    return {"data": data, "membri": rez}


@app.get("/api/ore-libere")
def ore_libere(grup: int, data: str, zile: int = 5, minute: int = 60, u=Depends(me)):
    grup_accesibil(grup, u)
    if not (10 <= minute <= 480 and 1 <= zile <= 14):
        raise HTTPException(422, "Durata sau numarul de zile nu e valid.")
    try:
        d = date.fromisoformat(data)
    except ValueError:
        raise HTTPException(422, "Data nu este valida.")
    membri, sloturi, necunoscut, contor, k = membri_grup(grup), [], {}, 0, 0
    while contor < zile and k < 40:
        zi = d + timedelta(days=k)
        k += 1
        if zi.weekday() >= 5 or zi in sarbatori(zi.year):
            continue
        contor += 1
        ocupat = [(690, 720)]  # pauza de masa 11:30-12:00
        for p in membri:
            bl, stare = blocuri_zi(p["id"], zi.isoformat(), u["id"])
            if stare != "ok":
                necunoscut[p["id"]] = f"{p['nume']} {p['prenume']}"
            ocupat += [(b["de"], b["pana"]) for b in bl]
        cur = 480  # program 8:00-16:30
        for de, pana in sorted(ocupat) + [(990, 990)]:
            if min(de, 990) - cur >= minute:
                sloturi.append({"data": zi.isoformat(), "de": cur, "pana": min(de, 990)})
            cur = max(cur, pana)
    return {"sloturi": sloturi[:15], "necunoscut": list(necunoscut.values())}


MAX_FISIER = 10 * 1024 * 1024
MAX_GRUP = 300 * 1024 * 1024
INTERZISE = {"exe", "bat", "cmd", "com", "scr", "js", "vbs", "ps1", "msi", "jar", "dll", "lnk", "hta", "reg", "sh"}


class NotaMod(BaseModel):
    text: str
    ver: int


def membru_grup(gid, u):
    """Documentele si notele sunt ale membrilor grupului, nu ale intregii firme (nici ale administratorului, daca nu e membru)."""
    g = q("SELECT * FROM grupuri WHERE id=? AND firma_id=?", (gid, u["firma_id"]), one=True)
    if not g or not q("SELECT 1 FROM membri_grup WHERE grup_id=? AND user_id=?", (gid, u["id"]), one=True):
        raise HTTPException(404, "Grupul nu exista sau nu faci parte din el.")
    return g


def curata_nume(n):
    n = re.sub(r'[\\/:*?"<>|\x00-\x1f]', "_", n.replace("\\", "/").split("/")[-1]).strip(" .")[:120]
    return n or "fisier"


@app.get("/api/grupuri/{gid}/nota")
def nota(gid: int, u=Depends(me)):
    g = membru_grup(gid, u)
    return {"text": g["nota"] or "", "ver": g["nota_ver"] or 0, "de": g["nota_de"], "la": g["nota_la"]}


@app.put("/api/grupuri/{gid}/nota")
def nota_mod(gid: int, b: NotaMod, u=Depends(me)):
    membru_grup(gid, u)
    if len(b.text) > 20000:
        raise HTTPException(422, "Nota e prea lunga (maxim 20.000 de caractere).")
    con = sqlite3.connect(DB)
    try:  # se salveaza doar daca nimeni n-a schimbat nota intre timp
        cur = con.execute("""UPDATE grupuri SET nota=?, nota_ver=COALESCE(nota_ver,0)+1, nota_de=?, nota_la=?
                             WHERE id=? AND COALESCE(nota_ver,0)=?""",
                          (b.text, f"{u['prenume']} {u['nume']}".strip(), iso(datetime.now(timezone.utc)), gid, b.ver))
        con.commit()
        salvat = cur.rowcount == 1
    finally:
        con.close()
    if not salvat:
        raise HTTPException(409, "Altcineva a modificat nota intre timp. Apasa Reincarca ca sa vezi versiunea noua.")
    return {"ver": b.ver + 1}


@app.get("/api/grupuri/{gid}/fisiere")
def fisiere(gid: int, u=Depends(me)):
    membru_grup(gid, u)
    return [{**{k: r[k] for k in ("id", "nume", "descriere", "marime", "creat")},
             "autor": f"{r['prenume']} {r['nume_u']}".strip(), "al_meu": r["user_id"] == u["id"]}
            for r in q("""SELECT f.id,f.nume,f.descriere,f.marime,f.creat,f.user_id, x.prenume, x.nume AS nume_u
                          FROM fisiere f JOIN utilizatori x ON x.id=f.user_id WHERE f.grup_id=? ORDER BY f.id DESC""", (gid,))]


@app.post("/api/grupuri/{gid}/fisiere")
async def incarca_fisier(gid: int, request: Request, nume: str, descriere: str = "", u=Depends(me)):
    membru_grup(gid, u)
    if int(request.headers.get("content-length") or 0) > MAX_FISIER:
        raise HTTPException(413, "Fisierul are peste 10 MB.")
    continut = await request.body()
    if not continut:
        raise HTTPException(422, "Fisierul e gol.")
    if len(continut) > MAX_FISIER:
        raise HTTPException(413, "Fisierul are peste 10 MB.")
    nume = curata_nume(nume)
    if "." in nume and nume.rsplit(".", 1)[-1].lower() in INTERZISE:
        raise HTTPException(422, "Acest tip de fisier nu se poate incarca (programe si scripturi).")
    if q("SELECT COALESCE(SUM(marime),0) s FROM fisiere WHERE grup_id=?", (gid,), one=True)["s"] + len(continut) > MAX_GRUP:
        raise HTTPException(413, "Grupul a atins limita de spatiu pentru documente. Sterge fisiere vechi.")
    fid = q("INSERT INTO fisiere(grup_id,user_id,nume,descriere,marime,creat,continut) VALUES(?,?,?,?,?,?,?)",
            (gid, u["id"], nume, descriere.strip()[:200], len(continut), iso(datetime.now(timezone.utc)), sqlite3.Binary(continut)), write=True)
    return {"id": fid}


@app.get("/api/fisiere/{fid}")
def descarca_fisier(fid: int, u=Depends(me)):
    f = q("SELECT * FROM fisiere WHERE id=?", (fid,), one=True)
    if not f:
        raise HTTPException(404, "Fisierul nu exista.")
    membru_grup(f["grup_id"], u)
    # mereu ca descarcare, niciodata afisat in pagina
    return Response(bytes(f["continut"]), media_type="application/octet-stream",
                    headers={"Content-Disposition": "attachment", "X-Content-Type-Options": "nosniff"})


@app.delete("/api/fisiere/{fid}")
def sterge_fisier(fid: int, u=Depends(me)):
    f = q("SELECT grup_id,user_id FROM fisiere WHERE id=?", (fid,), one=True)
    if not f:
        raise HTTPException(404, "Fisierul nu exista.")
    membru_grup(f["grup_id"], u)
    if f["user_id"] != u["id"] and not u["admin"]:
        raise HTTPException(403, "Doar cine l-a incarcat sau administratorul poate sterge fisierul.")
    q("DELETE FROM fisiere WHERE id=?", (fid,), write=True)
    return {"ok": True}


_aici = os.path.dirname(os.path.abspath(__file__))
# pe Linux (online) numele folderului conteaza: accepta si "Static", asa cum apare pe unele calculatoare Windows
_static = next((os.path.join(_aici, d) for d in ("static", "Static") if os.path.isdir(os.path.join(_aici, d))),
               os.path.join(_aici, "static"))
app.mount("/", StaticFiles(directory=_static, html=True), name="static")
