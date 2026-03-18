from flask import Flask, render_template, request, redirect, session, flash
import sqlite3
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash
from sqlite3 import IntegrityError

app = Flask(__name__)
app.secret_key = 'tajny_klic_pro_session'

# -------------------------------------------------------
# Tento řádek určuje, kdo je admin (podle emailu)
ADMIN_EMAIL = "admin@admin.cz"
# -------------------------------------------------------

def pripoj_db():
    return sqlite3.connect('system.db')

def priprav_databazi():
    conn = pripoj_db()
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS uzivatele 
                 (id INTEGER PRIMARY KEY AUTOINCREMENT, jmeno TEXT, email TEXT UNIQUE, heslo TEXT, vek INTEGER)''')
    c.execute('''CREATE TABLE IF NOT EXISTS dochazka 
                 (id INTEGER PRIMARY KEY AUTOINCREMENT, email TEXT, akce TEXT, cas TEXT)''')
    conn.commit()
    conn.close()

# -------------------------------------------------------
# Hlavní stránka
# -------------------------------------------------------
@app.route('/')
def index():
    prijmeni = session.get('uzivatel_jmeno')
    je_admin = session.get('uzivatel_email') == ADMIN_EMAIL
    datum = datetime.now().strftime("%d.%m.%Y")
    return render_template('index.html', jmeno=prijmeni, je_admin=je_admin)

# -------------------------------------------------------
# Registrace
# -------------------------------------------------------
@app.route('/registrace', methods=['POST'])
def registrace():
    jmeno = request.form['jmeno']
    email = request.form['email']
    heslo = request.form['heslo']
    vek = request.form['vek']
    cas = datetime.now().strftime("%d.%m.%Y %H:%M:%S")

    try:
        vek = int(vek)
        if vek < 0 or vek > 150:
            flash("Neplatný věk!")
            return redirect('/')
    except ValueError:
        flash("Věk musí být číslo!")
        return redirect('/')

    if len(heslo) < 8:
        flash("Heslo musí mít alespoň 8 znaků!")
        return redirect('/')

    heslo_hash = generate_password_hash(heslo)

    try:
        conn = pripoj_db()
        c = conn.cursor()
        c.execute("INSERT INTO uzivatele (jmeno, email, heslo, vek) VALUES (?, ?, ?, ?)", (jmeno, email, heslo_hash, vek))
        c.execute("INSERT INTO dochazka (email, akce, cas) VALUES (?, ?, ?)", (email, "Registrace a první přihlášení", cas))
        conn.commit()
        conn.close()
        session['uzivatel_email'] = email
        session['uzivatel_jmeno'] = jmeno
        return redirect('/')
    except IntegrityError:
        flash("Tento e-mail již existuje!")
        return redirect('/')

# -------------------------------------------------------
# Přihlášení
# -------------------------------------------------------
@app.route('/login', methods=['POST'])
def login():
    email = request.form['email']
    heslo = request.form['heslo']

    conn = pripoj_db()
    c = conn.cursor()
    c.execute("SELECT jmeno, heslo FROM uzivatele WHERE email=?", (email,))
    uzivatel = c.fetchone()

    if uzivatel and check_password_hash(uzivatel[1], heslo):
        session['uzivatel_email'] = email
        session['uzivatel_jmeno'] = uzivatel[0]
        cas = datetime.now().strftime("%d.%m.%Y %H:%M:%S")
        c.execute("INSERT INTO dochazka (email, akce, cas) VALUES (?, ?, ?)", (email, "Přihlášení", cas))
        conn.commit()
        conn.close()
        return redirect('/')
    else:
        conn.close()
        flash("Chybné jméno nebo heslo!")
        return redirect('/')

# -------------------------------------------------------
# Odhlášení
# -------------------------------------------------------
@app.route('/logout')
def logout():
    email = session.get('uzivatel_email')
    if email:
        cas = datetime.now().strftime("%d.%m.%Y %H:%M:%S")
        conn = pripoj_db()
        c = conn.cursor()
        c.execute("INSERT INTO dochazka (email, akce, cas) VALUES (?, ?, ?)", (email, "Odhlášení", cas))
        conn.commit()
        conn.close()

    session.clear()
    return redirect('/')

# -------------------------------------------------------
# Profil uživatele – každý vidí jen svoje záznamy
# -------------------------------------------------------
@app.route('/profil')
def profil():
    # Pokud není přihlášen, pošleme ho zpět
    if not session.get('uzivatel_email'):
        flash("Nejdříve se přihlas!")
        return redirect('/')

    email = session.get('uzivatel_email')
    conn = pripoj_db()
    c = conn.cursor()

    # Načteme údaje uživatele
    c.execute("SELECT jmeno, email, vek FROM uzivatele WHERE email=?", (email,))
    udaje = c.fetchone()

    # Načteme jeho historii docházky, nejnovější záznamy první
    c.execute("SELECT akce, cas FROM dochazka WHERE email=? ORDER BY id DESC", (email,))
    historie = c.fetchall()

    conn.close()
    return render_template('profil.html', udaje=udaje, historie=historie)

# -------------------------------------------------------
# Admin stránka – vidí jen admin
# -------------------------------------------------------
@app.route('/admin')
def admin():
    # Pokud není přihlášen jako admin, zastavíme ho
    if session.get('uzivatel_email') != ADMIN_EMAIL:
        flash("Nemáš přístup na tuto stránku!")
        return redirect('/')

    conn = pripoj_db()
    c = conn.cursor()

    # Načteme všechny uživatele
    c.execute("SELECT id, jmeno, email, vek FROM uzivatele ORDER BY id DESC")
    uzivatele = c.fetchall()

    # Načteme celou docházku všech uživatelů, nejnovější první
    c.execute("SELECT email, akce, cas FROM dochazka ORDER BY id DESC")
    dochazka = c.fetchall()

    conn.close()
    return render_template('admin.html', uzivatele=uzivatele, dochazka=dochazka)

# -------------------------------------------------------
# Smazání uživatele – pouze admin
# -------------------------------------------------------
@app.route('/smazat/<int:uzivatel_id>')
def smazat(uzivatel_id):
    # Ochrana – jen admin může mazat
    if session.get('uzivatel_email') != ADMIN_EMAIL:
        flash("Nemáš přístup!")
        return redirect('/')

    conn = pripoj_db()
    c = conn.cursor()

    # Nejdřív zjistíme email mazaného uživatele
    c.execute("SELECT email FROM uzivatele WHERE id=?", (uzivatel_id,))
    radek = c.fetchone()

    if radek:
        email_mazaneho = radek[0]
        # Smažeme uživatele i jeho docházku
        c.execute("DELETE FROM uzivatele WHERE id=?", (uzivatel_id,))
        c.execute("DELETE FROM dochazka WHERE email=?", (email_mazaneho,))
        conn.commit()

    conn.close()
    return redirect('/admin')

if __name__ == '__main__':
    priprav_databazi()
    app.run(debug=True)