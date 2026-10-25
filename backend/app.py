import base64
import hashlib
import json
import os
import secrets
import sqlite3
from datetime import date, datetime, timedelta, timezone
from functools import wraps
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from flask import Flask, g, jsonify, request
from werkzeug.security import check_password_hash, generate_password_hash

BASE_DIR = Path(__file__).resolve().parent
DATABASE_PATH = Path(os.getenv("DATABASE_PATH", BASE_DIR / "data" / "clinical_compass.db"))
KEY_PATH = Path(os.getenv("DATA_ENCRYPTION_KEY_PATH", BASE_DIR / "data" / ".data_encryption_key"))
KEY_FILE = os.getenv("DATA_ENCRYPTION_KEY_FILE")
SLOTS = ("09:30", "11:00", "12:30", "15:30", "17:00")
MOSCOW_TZ = timezone(timedelta(hours=3))
_KEY_CACHE = None


def get_db():
    DATABASE_PATH.parent.mkdir(parents=True, exist_ok=True)
    db = sqlite3.connect(DATABASE_PATH, timeout=20)
    db.row_factory = sqlite3.Row
    db.execute("PRAGMA foreign_keys=ON")
    db.execute("PRAGMA journal_mode=WAL")
    return db


def _decode_key(value):
    key = base64.urlsafe_b64decode(value.strip().encode("ascii"))
    if len(key) != 32:
        raise RuntimeError("AES-256 key must contain exactly 32 bytes")
    return key


def encryption_key():
    global _KEY_CACHE
    if _KEY_CACHE is not None:
        return _KEY_CACHE
    env_value = os.getenv("DATA_ENCRYPTION_KEY")
    source = Path(KEY_FILE) if KEY_FILE else KEY_PATH
    if env_value:
        _KEY_CACHE = _decode_key(env_value)
        return _KEY_CACHE
    if source.exists():
        _KEY_CACHE = _decode_key(source.read_text(encoding="utf-8"))
        return _KEY_CACHE
    source.parent.mkdir(parents=True, exist_ok=True)
    generated = base64.urlsafe_b64encode(AESGCM.generate_key(bit_length=256)).decode("ascii")
    try:
        descriptor = os.open(source, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            stream.write(generated)
    except FileExistsError:
        pass
    _KEY_CACHE = _decode_key(source.read_text(encoding="utf-8"))
    return _KEY_CACHE


def _aad(patient_id, record_type):
    return f"clinical-compass:v2:{patient_id}:{record_type}".encode()


def insert_secure(db, patient_id, record_type, document, *, created_at=None, status=None, severity=None):
    nonce = os.urandom(12)
    raw = json.dumps(document, ensure_ascii=False, separators=(",", ":")).encode()
    encrypted = AESGCM(encryption_key()).encrypt(nonce, raw, _aad(patient_id, record_type))
    cursor = db.execute(
        "INSERT INTO secure_records(patient_id,record_type,created_at,status,severity,nonce,ciphertext) VALUES(?,?,?,?,?,?,?)",
        (patient_id, record_type, created_at or datetime.now().isoformat(timespec="seconds"), status, severity, nonce, encrypted),
    )
    return cursor.lastrowid


def decrypt_record(row):
    raw = AESGCM(encryption_key()).decrypt(row["nonce"], row["ciphertext"], _aad(row["patient_id"], row["record_type"]))
    item = json.loads(raw.decode())
    item.update({"id": row["id"], "created_at": row["created_at"]})
    if row["status"] is not None:
        item["status"] = row["status"]
    if row["severity"] is not None:
        item["severity"] = row["severity"]
    return item


def records(db, patient_id, record_type, newest=False):
    order = "DESC" if newest else "ASC"
    rows = db.execute(f"SELECT * FROM secure_records WHERE patient_id=? AND record_type=? ORDER BY created_at {order}", (patient_id, record_type)).fetchall()
    return [decrypt_record(row) for row in rows]


def latest(db, patient_id, record_type):
    row = db.execute("SELECT * FROM secure_records WHERE patient_id=? AND record_type=? ORDER BY id DESC LIMIT 1", (patient_id, record_type)).fetchone()
    return decrypt_record(row) if row else None


RISK_RULESET_VERSION = "safety-v1"
LEGAL_DOCUMENT_VERSION = "legal-v1-2026-10-25"
LEGAL_OPERATOR = {
    "name": "[ПОЛНОЕ НАИМЕНОВАНИЕ ООО / ФИО ИП]",
    "registration": "ИНН [__________], ОГРН/ОГРНИП [__________]",
    "address": "[ЮРИДИЧЕСКИЙ АДРЕС ОПЕРАТОРА]",
    "email": "privacy@[ДОМЕН].ru",
}


def legal_documents():
    operator = f"{LEGAL_OPERATOR['name']}, {LEGAL_OPERATOR['registration']}, адрес: {LEGAL_OPERATOR['address']}"
    return {
        "version": LEGAL_DOCUMENT_VERSION,
        "operator": LEGAL_OPERATOR,
        "prototype_notice": "Шаблон для pet-проекта. До работы с реальными пациентами реквизиты, основания и формулировки должен проверить юрист и ответственное лицо медицинской организации.",
        "documents": {
            "personal_data": {
                "title": "Согласие на обработку персональных данных",
                "text": f"Я свободно, своей волей и в своём интересе даю согласие оператору {operator} на обработку моих ФИО, даты рождения, адреса электронной почты, сведений учётной записи, записей на приём, сообщений и технических данных подключения. Цели: регистрация и работа личного кабинета, организация связи с выбранными врачами, запись на приём, обеспечение безопасности и поддержка пользователей. Действия: сбор, запись, систематизация, накопление, хранение, уточнение, извлечение, использование, предоставление выбранным врачам и уполномоченным обработчикам, блокирование и удаление с использованием средств автоматизации. Согласие действует до достижения целей обработки или его отзыва, если обязательный срок хранения не установлен законом. Отзыв направляется на {LEGAL_OPERATOR['email']}. Отзыв не прекращает обработку, для которой у оператора остаётся иное законное основание.",
            },
            "health_data": {
                "title": "Согласие на обработку специальных категорий данных о здоровье",
                "text": f"Я отдельно даю согласие оператору {operator} на обработку сведений о состоянии здоровья: жалоб, результатов опросников, ежедневных отметок, диагнозов, назначений, переносимости препаратов, побочных эффектов и сигналов безопасности. Эти данные обрабатываются для ведения защищённой карточки, отображения динамики, сопровождения лечения выбранными врачами и формирования вспомогательных сигналов. Автоматический сигнал не является диагнозом и сам по себе не изменяет лечение. Решения о лечении принимает врач. Согласие действует до достижения целей или отзыва с учётом обязательных сроков хранения.",
            },
            "medical_confidentiality": {
                "title": "Согласие на предоставление сведений, составляющих врачебную тайну",
                "text": "Я разрешаю предоставлять сведения о факте обращения, состоянии здоровья, диагнозах, обследованиях, назначениях и лечении только врачам, с которыми я самостоятельно установил(а) связь через запись или подтверждение приёма в сервисе. Передача иным лицам допускается только с отдельного согласия либо в случаях, прямо предусмотренных законодательством Российской Федерации. Я понимаю, что могу прекратить доступ конкретного врача в порядке, установленном оператором.",
            },
            "terms": {
                "title": "Пользовательское соглашение и уведомление о границах сервиса",
                "text": "Я понимаю, что сервис является информационным инструментом и не заменяет очную медицинскую помощь или экстренную службу. Опросники и автоматические сигналы не являются диагнозом. При непосредственной угрозе жизни или здоровью необходимо самостоятельно обратиться по номеру 112 или 103. Я подтверждаю достоверность указанных мной данных и принимаю условия использования прототипа.",
            },
        },
    }


def consent_document_hash():
    raw = json.dumps(legal_documents(), ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(raw).hexdigest()


def validate_consent(payload, birth_date):
    consents = payload.get("consents") if isinstance(payload.get("consents"), dict) else {}
    required = ("personal_data", "health_data", "medical_confidentiality", "terms")
    if consents.get("version") != LEGAL_DOCUMENT_VERSION or any(consents.get(key) is not True for key in required):
        return None, "Необходимо отдельно принять все обязательные документы"
    today = date.today()
    age = today.year - birth_date.year - ((today.month, today.day) < (birth_date.month, birth_date.day))
    representative = consents.get("representative") if isinstance(consents.get("representative"), dict) else None
    if age < 18:
        if not representative:
            return None, "Для несовершеннолетнего требуется согласие законного представителя"
        fields = ("full_name", "relationship", "document_details", "email")
        if any(len(str(representative.get(key, "")).strip()) < 3 for key in fields):
            return None, "Заполните сведения о законном представителе"
        representative = {key:str(representative[key]).strip() for key in fields}
    return {
        "version": LEGAL_DOCUMENT_VERSION,
        "document_hash": consent_document_hash(),
        "accepted": {key: True for key in required},
        "subject_is_minor": age < 18,
        "representative": representative if age < 18 else None,
        "operator_snapshot": LEGAL_OPERATOR,
        "accepted_at": datetime.now(MOSCOW_TZ).isoformat(timespec="seconds"),
        "ip_address": request.headers.get("X-Forwarded-For", request.remote_addr or "").split(",")[0].strip(),
        "user_agent": request.headers.get("User-Agent", "")[:500],
        "method": "authenticated_checkbox_prototype",
    }, None


def evaluate_safety_risk(payload, previous_checkin=None):
    """Transparent prototype rules. A clinician must approve them before clinical use."""
    flags = {
        "immediate_danger": payload.get("immediate_danger") is True,
        "recent_self_harm": payload.get("recent_self_harm") is True,
        "self_harm_thoughts": payload.get("self_harm_thoughts") is True,
        "suicide_plan": payload.get("suicide_plan") is True,
        "means_access": payload.get("means_access") is True,
        "sudden_worsening": payload.get("sudden_worsening") is True,
        "severe_physical_symptoms": payload.get("severe_physical_symptoms") is True,
    }
    mood = int(payload["mood"])
    anxiety = int(payload["anxiety"])
    sleep = float(payload["sleep"])
    triggers = []
    level = "none"

    if flags["immediate_danger"]:
        triggers.append(("IMMEDIATE_DANGER", "Пациент сообщил о непосредственной опасности сейчас"))
    if flags["self_harm_thoughts"] and flags["suicide_plan"] and flags["means_access"]:
        triggers.append(("PLAN_MEANS_INTENT", "Есть мысли, конкретный план и доступ к средствам"))
    if flags["severe_physical_symptoms"]:
        triggers.append(("SEVERE_PHYSICAL_SYMPTOMS", "Пациент отметил опасные физические симптомы"))
    if triggers:
        level = "critical"
    else:
        if flags["self_harm_thoughts"]:
            triggers.append(("SELF_HARM_THOUGHTS", "Пациент сообщил о мыслях о самоповреждении"))
        if flags["recent_self_harm"]:
            triggers.append(("SELF_HARM_PAST_YEAR", "Пациент сообщил о самоповреждении или попытке за последний год"))
        if flags["suicide_plan"] or flags["means_access"]:
            triggers.append(("PLAN_OR_MEANS", "Отмечен отдельный признак возможного высокого риска"))
        if flags["sudden_worsening"]:
            triggers.append(("SUDDEN_WORSENING", "Пациент отметил резкое ухудшение состояния"))
        if previous_checkin:
            mood_drop = int(previous_checkin.get("mood", mood)) - mood
            anxiety_drop = int(previous_checkin.get("anxiety", anxiety)) - anxiety
            if mood_drop >= 3 or anxiety_drop >= 3:
                triggers.append(("RAPID_SCALE_DECLINE", "Показатели ухудшились на 3 или более пункта"))
        if triggers:
            level = "urgent"
        elif mood <= 3 or anxiety <= 3 or sleep < 5:
            level = "observation"
            if mood <= 3:
                triggers.append(("LOW_MOOD", f"Настроение {mood}/10"))
            if anxiety <= 3:
                triggers.append(("LOW_ANXIETY_WELLBEING", f"Самооценка тревоги {anxiety}/10"))
            if sleep < 5:
                triggers.append(("SHORT_SLEEP", f"Сон {sleep:g} ч"))

    recommendations = {
        "critical": "Немедленно оценить безопасность пациента и организовать экстренную помощь при подтверждении опасности.",
        "urgent": "Связаться с пациентом и провести клиническую оценку в срок, установленный клиникой.",
        "observation": "Оценить динамику и необходимость дополнительного контакта с пациентом.",
        "none": "",
    }
    return {
        "level": level,
        "ruleset_version": RISK_RULESET_VERSION,
        "rule_codes": [code for code, _ in triggers],
        "reasons": [reason for _, reason in triggers],
        "recommendation": recommendations[level],
        "answers": flags,
    }


def create_schema():
    with get_db() as db:
        old_relations = []
        patient_columns = db.execute("PRAGMA table_info(patients)").fetchall()
        if patient_columns and any(row[1] == "doctor_id" for row in patient_columns):
            old_relations = [(row[0], row[1]) for row in db.execute("SELECT id, doctor_id FROM patients WHERE doctor_id IS NOT NULL").fetchall()]
            db.commit()
            db.execute("PRAGMA foreign_keys=OFF")
            db.executescript(
                """
                CREATE TABLE patients_new(id INTEGER PRIMARY KEY AUTOINCREMENT, created_at TEXT NOT NULL);
                INSERT INTO patients_new(id,created_at) SELECT id,created_at FROM patients;
                DROP TABLE patients;
                ALTER TABLE patients_new RENAME TO patients;
                """
            )
            db.execute("PRAGMA foreign_keys=ON")
        db.executescript(
            """
            CREATE TABLE IF NOT EXISTS users(
              id INTEGER PRIMARY KEY AUTOINCREMENT, role TEXT NOT NULL CHECK(role IN ('doctor','patient')),
              email TEXT NOT NULL UNIQUE COLLATE NOCASE, password_hash TEXT NOT NULL,
              entity_id INTEGER NOT NULL, created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS sessions(
              token_hash TEXT PRIMARY KEY, user_id INTEGER NOT NULL, expires_at TEXT NOT NULL,
              FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
            );
            CREATE TABLE IF NOT EXISTS doctors(
              id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, specialty TEXT NOT NULL,
              experience INTEGER NOT NULL DEFAULT 0, clinic TEXT NOT NULL DEFAULT '', rating REAL NOT NULL DEFAULT 5,
              price INTEGER NOT NULL DEFAULT 2500, about TEXT NOT NULL DEFAULT ''
            );
            CREATE TABLE IF NOT EXISTS patients(
              id INTEGER PRIMARY KEY AUTOINCREMENT, created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS patient_doctors(
              patient_id INTEGER NOT NULL, doctor_id INTEGER NOT NULL, created_at TEXT NOT NULL,
              PRIMARY KEY(patient_id,doctor_id), FOREIGN KEY(patient_id) REFERENCES patients(id) ON DELETE CASCADE,
              FOREIGN KEY(doctor_id) REFERENCES doctors(id) ON DELETE CASCADE
            );
            CREATE TABLE IF NOT EXISTS patient_stats(
              patient_id INTEGER PRIMARY KEY, points INTEGER NOT NULL DEFAULT 0, streak INTEGER NOT NULL DEFAULT 0,
              last_checkin_date TEXT, FOREIGN KEY(patient_id) REFERENCES patients(id) ON DELETE CASCADE
            );
            CREATE TABLE IF NOT EXISTS secure_records(
              id INTEGER PRIMARY KEY AUTOINCREMENT, patient_id INTEGER NOT NULL, record_type TEXT NOT NULL,
              created_at TEXT NOT NULL, status TEXT, severity TEXT, nonce BLOB NOT NULL, ciphertext BLOB NOT NULL,
              FOREIGN KEY(patient_id) REFERENCES patients(id) ON DELETE CASCADE
            );
            CREATE INDEX IF NOT EXISTS idx_secure_records ON secure_records(patient_id,record_type,created_at);
            CREATE TABLE IF NOT EXISTS appointment_slots(
              id INTEGER PRIMARY KEY AUTOINCREMENT, doctor_id INTEGER NOT NULL, patient_id INTEGER NOT NULL,
              appointment_record_id INTEGER NOT NULL, appointment_date TEXT NOT NULL, appointment_time TEXT NOT NULL,
              UNIQUE(doctor_id,appointment_date,appointment_time),
              FOREIGN KEY(doctor_id) REFERENCES doctors(id), FOREIGN KEY(patient_id) REFERENCES patients(id),
              FOREIGN KEY(appointment_record_id) REFERENCES secure_records(id) ON DELETE CASCADE
            );
            CREATE TABLE IF NOT EXISTS notification_reads(
              user_id INTEGER NOT NULL, event_key TEXT NOT NULL, read_at TEXT NOT NULL,
              PRIMARY KEY(user_id,event_key), FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
            );
            CREATE TABLE IF NOT EXISTS medicines(
              id INTEGER PRIMARY KEY, name TEXT NOT NULL, ingredient TEXT NOT NULL, drug_class TEXT NOT NULL,
              dose_range TEXT NOT NULL, effect_window TEXT NOT NULL, common_effects TEXT NOT NULL,
              urgent_effects TEXT NOT NULL, monitoring TEXT NOT NULL,
              minimum_age TEXT NOT NULL DEFAULT '18 лет', contraindications TEXT NOT NULL DEFAULT ''
            );
            """
        )
        medicine_columns = {row[1] for row in db.execute("PRAGMA table_info(medicines)").fetchall()}
        if "minimum_age" not in medicine_columns:
            db.execute("ALTER TABLE medicines ADD COLUMN minimum_age TEXT NOT NULL DEFAULT '18 лет'")
        if "contraindications" not in medicine_columns:
            db.execute("ALTER TABLE medicines ADD COLUMN contraindications TEXT NOT NULL DEFAULT ''")
        if old_relations:
            db.executemany("INSERT OR IGNORE INTO patient_doctors(patient_id,doctor_id,created_at) VALUES(?,?,?)", [(patient_id,doctor_id,datetime.now().isoformat(timespec="seconds")) for patient_id,doctor_id in old_relations])
        db.execute("INSERT OR IGNORE INTO patient_stats(patient_id) SELECT id FROM patients")
        db.execute("UPDATE doctors SET price=2500 WHERE price IS NULL OR price<=0")
        medicines = [
            (1,"Авиандр","Фабомотизол","Анксиолитик","1 таблетка 2 раза в сутки","4–6 недель","Головная боль|Головокружение|Сонливость|Слабость","Аллергическая реакция|Резкое ухудшение","Контроль переносимости через 2 недели"),
            (2,"Эсциталопрам","Эсциталопрам","СИОЗС","10–20 мг/сут","4–6 недель","Тошнота|Головная боль|Изменения сна|Потливость","Серотониновый синдром|Суицидальные мысли","Контроль тревоги, настроения и переносимости"),
            (3,"Сертралин","Сертралин","СИОЗС","50–200 мг/сут","4–6 недель","Тошнота|Головная боль|Бессонница|Тремор","Серотониновый синдром|Резкое усиление тревоги","Повторные шкалы через 4–6 недель"),
            (4,"Венлафаксин","Венлафаксин","СИОЗСН","75–225 мг/сут","4–6 недель","Тошнота|Головная боль|Повышение давления|Потливость","Существенное повышение давления|Синдром отмены","Контроль артериального давления"),
            (5,"Прегабалин","Прегабалин","Противоэпилептический","150–600 мг/сут","1–2 недели","Головокружение|Сонливость|Отёки|Увеличение веса","Выраженные отёки|Аллергическая реакция","Контроль веса, отёков и сонливости"),
            (6,"Агомелатин","Агомелатин","Антидепрессант","25–50 мг на ночь","2–4 недели","Головная боль|Тошнота|Головокружение","Нарушение функции печени","Контроль печёночных ферментов"),
            (7,"Гидроксизин","Гидроксизин","Анксиолитик","50–100 мг/сут","В первые дни","Сонливость|Сухость во рту|Слабость","Аллергия|Задержка мочеиспускания","Оценка дневной сонливости"),
        ]
        db.executemany("""INSERT OR IGNORE INTO medicines(
            id,name,ingredient,drug_class,dose_range,effect_window,common_effects,urgent_effects,monitoring
        ) VALUES(?,?,?,?,?,?,?,?,?)""", medicines)
        medicine_details = [
            ("18 лет", "Гиперчувствительность к компонентам|Беременность и грудное вскармливание|Непереносимость галактозы", 1),
            ("18 лет", "Одновременный приём ингибиторов МАО|Удлинение интервала QT|Гиперчувствительность к эсциталопраму", 2),
            ("18 лет", "Одновременный приём ингибиторов МАО|Гиперчувствительность к сертралину|Совместный приём с пимозидом", 3),
            ("18 лет", "Одновременный приём ингибиторов МАО|Неконтролируемая артериальная гипертензия требует особой оценки|Гиперчувствительность к венлафаксину", 4),
            ("18 лет", "Гиперчувствительность к прегабалину|Беременность и грудное вскармливание требуют индивидуальной оценки|Непереносимость галактозы", 5),
            ("18 лет", "Нарушение функции печени|Повышение трансаминаз более чем в 3 раза|Одновременный приём сильных ингибиторов CYP1A2", 6),
            ("От 3 лет — зависит от формы и показания", "Удлинение интервала QT|Тяжёлая сердечно-сосудистая патология|Беременность и грудное вскармливание|Гиперчувствительность к гидроксизину", 7),
        ]
        db.executemany("UPDATE medicines SET minimum_age=?, contraindications=? WHERE id=?", medicine_details)


app = Flask(__name__)


@app.after_request
def headers(response):
    origin = request.headers.get("Origin")
    allowed = os.getenv("ALLOWED_ORIGINS", "http://localhost:5173,http://localhost:5174").split(",")
    if origin in allowed:
        response.headers["Access-Control-Allow-Origin"] = origin
        response.headers["Vary"] = "Origin"
        response.headers["Access-Control-Allow-Headers"] = "Content-Type,Authorization"
        response.headers["Access-Control-Allow-Methods"] = "GET,POST,PATCH,DELETE,OPTIONS"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    return response


@app.route("/api/<path:_>", methods=["OPTIONS"])
def options(_):
    return "", 204


def token_hash(token):
    return hashlib.sha256(token.encode()).hexdigest()


def issue_session(db, user_id):
    token = secrets.token_urlsafe(32)
    expires = (datetime.now() + timedelta(days=7)).isoformat(timespec="seconds")
    db.execute("DELETE FROM sessions WHERE user_id=?", (user_id,))
    db.execute("INSERT INTO sessions VALUES(?,?,?)", (token_hash(token), user_id, expires))
    return token


def user_payload(db, user):
    base = {"id": user["id"], "role": user["role"], "email": user["email"], "entity_id": user["entity_id"]}
    if user["role"] == "doctor":
        doctor = db.execute("SELECT * FROM doctors WHERE id=?", (user["entity_id"],)).fetchone()
        base["profile"] = dict(doctor)
    else:
        profile = latest(db, user["entity_id"], "profile")
        base["profile"] = profile
    return base


def require_auth(role=None):
    def decorator(function):
        @wraps(function)
        def wrapper(*args, **kwargs):
            value = request.headers.get("Authorization", "")
            if not value.startswith("Bearer "):
                return jsonify({"error": "Требуется вход"}), 401
            with get_db() as db:
                user = db.execute("""SELECT u.* FROM users u JOIN sessions s ON s.user_id=u.id
                    WHERE s.token_hash=? AND s.expires_at>?""", (token_hash(value[7:]), datetime.now().isoformat())).fetchone()
                if not user or (role and user["role"] != role):
                    return jsonify({"error": "Сессия недействительна"}), 401
                g.user = dict(user)
            return function(*args, **kwargs)
        return wrapper
    return decorator


@app.get("/api/health")
def health():
    return jsonify({"status":"ok","service":"clinical-compass-api","encryption":"AES-256-GCM"})


@app.get("/api/legal/documents")
def get_legal_documents():
    return jsonify(legal_documents())


@app.post("/api/auth/register")
def register():
    payload = request.get_json(silent=True) or {}
    role = payload.get("role")
    email = str(payload.get("email", "")).strip().lower()
    password = str(payload.get("password", ""))
    name = str(payload.get("name", "")).strip()
    if role not in {"doctor", "patient"} or "@" not in email or len(password) < 6 or len(name) < 2:
        return jsonify({"error":"Заполните имя, корректный email и пароль от 6 символов"}), 400
    consent_document = None
    if role == "patient":
        try:
            birth_date = date.fromisoformat(str(payload.get("birth_date", "")))
            if birth_date > date.today():
                return jsonify({"error":"Дата рождения не может быть позже сегодняшнего дня"}),400
        except ValueError:
            return jsonify({"error":"Укажите корректную дату рождения"}),400
        consent_document, consent_error = validate_consent(payload, birth_date)
        if consent_error:
            return jsonify({"error":consent_error}),400
    now = datetime.now().isoformat(timespec="seconds")
    try:
        with get_db() as db:
            if role == "doctor":
                cursor = db.execute("INSERT INTO doctors(name,specialty,experience,clinic,price,about) VALUES(?,?,?,?,?,?)", (
                    name, str(payload.get("specialty", "Психиатр")), int(payload.get("experience", 0)),
                    str(payload.get("clinic", "Частная практика")), 2500, str(payload.get("about", ""))))
                entity_id = cursor.lastrowid
            else:
                cursor = db.execute("INSERT INTO patients(created_at) VALUES(?)", (now,))
                entity_id = cursor.lastrowid
                db.execute("INSERT INTO patient_stats(patient_id) VALUES(?)", (entity_id,))
                insert_secure(db, entity_id, "profile", {
                    "full_name":name, "birth_date":birth_date.isoformat(), "age":payload.get("age", ""),
                    "diagnosis":"Диагноз пока не установлен",
                    "therapy":"Не назначена", "dosage":"—", "started_at":date.today().isoformat(),
                    "allergies":[], "chronic_conditions":[], "reminders":[], "prescriptions":[], "medical_history":[]
                }, status="active")
                insert_secure(db, entity_id, "consent", consent_document, status="active")
            user_cursor = db.execute("INSERT INTO users(role,email,password_hash,entity_id,created_at) VALUES(?,?,?,?,?)", (role,email,generate_password_hash(password),entity_id,now))
            token = issue_session(db, user_cursor.lastrowid)
            user = db.execute("SELECT * FROM users WHERE id=?", (user_cursor.lastrowid,)).fetchone()
            return jsonify({"token":token,"user":user_payload(db,user)}), 201
    except sqlite3.IntegrityError:
        return jsonify({"error":"Этот email уже зарегистрирован"}), 409


@app.post("/api/auth/login")
def login():
    payload = request.get_json(silent=True) or {}
    with get_db() as db:
        user = db.execute("SELECT * FROM users WHERE email=?", (str(payload.get("email", "")).strip().lower(),)).fetchone()
        if not user or not check_password_hash(user["password_hash"], str(payload.get("password", ""))):
            return jsonify({"error":"Неверный email или пароль"}), 401
        token = issue_session(db, user["id"])
        return jsonify({"token":token,"user":user_payload(db,user)})


@app.get("/api/auth/me")
@require_auth()
def me():
    with get_db() as db:
        user = db.execute("SELECT * FROM users WHERE id=?", (g.user["id"],)).fetchone()
        return jsonify(user_payload(db,user))


@app.post("/api/auth/logout")
@require_auth()
def logout():
    value = request.headers.get("Authorization", "")[7:]
    with get_db() as db:
        db.execute("DELETE FROM sessions WHERE token_hash=?", (token_hash(value),))
    return jsonify({"status":"logged_out"})


@app.get("/api/doctors")
def doctors():
    with get_db() as db:
        result = []
        for row in db.execute("SELECT * FROM doctors ORDER BY name").fetchall():
            item = dict(row)
            item["available_slots"] = available_slots(db, item["id"], 3)
            result.append(item)
        return jsonify(result)


def available_slots(db, doctor_id, days=7):
    booked = {(row["appointment_date"],row["appointment_time"]) for row in db.execute("SELECT appointment_date,appointment_time FROM appointment_slots WHERE doctor_id=?", (doctor_id,)).fetchall()}
    output = []
    for offset in range(1, days + 1):
        target = (date.today() + timedelta(days=offset)).isoformat()
        for slot in SLOTS:
            output.append({"date":target,"time":slot,"available":(target,slot) not in booked})
    return output


def patient_summary(db, patient_id):
    profile = latest(db, patient_id, "profile")
    if not profile:
        return None
    checkins = records(db, patient_id, "checkin")
    for item in checkins:
        if item.get("scale_version",1) < 2:
            item["anxiety"] = max(0,min(10,10-int(item["anxiety"])))
    assessments = records(db,patient_id,"assessment",True)
    prescriptions = records(db,patient_id,"prescription",True)
    diagnoses = records(db,patient_id,"diagnosis",True)
    consents = records(db,patient_id,"consent",True)
    current_consent = next((item for item in consents if item.get("version") == LEGAL_DOCUMENT_VERSION and item.get("status") == "active"), None)
    active_prescriptions = [item for item in prescriptions if item.get("status") == "active"]
    linked_doctors = [dict(row) for row in db.execute("""SELECT d.* FROM doctors d
        JOIN patient_doctors pd ON pd.doctor_id=d.id WHERE pd.patient_id=? ORDER BY d.name""", (patient_id,)).fetchall()]
    stats_row = db.execute("SELECT * FROM patient_stats WHERE patient_id=?", (patient_id,)).fetchone()
    stats = dict(stats_row) if stats_row else {"points":0,"streak":0,"last_checkin_date":None}
    stats["discount_rubles"] = (stats["points"] // 100) * 100
    if active_prescriptions:
        profile["therapy"] = ", ".join(item["name"] for item in active_prescriptions)
        profile["dosage"] = "; ".join(f"{item['name']}: {item['dose']}" for item in active_prescriptions)
    if diagnoses:
        profile["diagnosis"] = ", ".join(item["name"] for item in diagnoses)
    profile.update({
        "patient_id":patient_id, "checkins":checkins, "latest_checkin":checkins[-1] if checkins else None,
        "alerts":records(db,patient_id,"alert",True), "alert_events":records(db,patient_id,"alert_event",True), "messages":records(db,patient_id,"message"),
        "appointments":records(db,patient_id,"appointment",True), "side_effect_reports":records(db,patient_id,"side_effect",True),
        "assessments":assessments, "visits":records(db,patient_id,"visit",True),
        "prescriptions":prescriptions, "diagnoses":diagnoses, "doctors":linked_doctors, "stats":stats,
        "needs_initial_assessment":not assessments,
        "needs_consent":current_consent is None,
        "consent_summary":({"version":current_consent["version"],"accepted_at":current_consent["accepted_at"],"subject_is_minor":current_consent.get("subject_is_minor",False)} if current_consent else None),
    })
    return profile


@app.get("/api/doctor/dashboard")
@require_auth("doctor")
def doctor_dashboard():
    doctor_id = g.user["entity_id"]
    with get_db() as db:
        doctor = dict(db.execute("SELECT * FROM doctors WHERE id=?", (doctor_id,)).fetchone())
        patient_ids = [row[0] for row in db.execute("SELECT patient_id FROM patient_doctors WHERE doctor_id=? ORDER BY patient_id", (doctor_id,)).fetchall()]
        patients = [patient_summary(db, item) for item in patient_ids]
        for patient in patients:
            patient["messages"] = [item for item in patient["messages"] if item.get("doctor_id")==doctor_id]
        alerts = [alert | {"patient_id":patient["patient_id"],"patient_name":patient["full_name"]} for patient in patients for alert in patient["alerts"] if alert.get("status") in {"new","acknowledged"}]
        return jsonify({"doctor":doctor,"patients":patients,"alerts":alerts,"metrics":{"patients":len(patients),"need_attention":len(alerts),"appointments":db.execute("SELECT count(*) FROM appointment_slots WHERE doctor_id=? AND appointment_date>=?",(doctor_id,date.today().isoformat())).fetchone()[0]}})


@app.post("/api/doctor/alerts/<int:alert_id>/resolve")
@require_auth("doctor")
def resolve_alert(alert_id):
    payload = request.get_json(silent=True) or {}
    note = str(payload.get("note", "")).strip()
    if not note:
        return jsonify({"error":"Укажите, как был обработан сигнал"}),400
    with get_db() as db:
        row = db.execute(
            """SELECT sr.* FROM secure_records sr
               JOIN patient_doctors pd ON pd.patient_id=sr.patient_id
               WHERE sr.id=? AND sr.record_type='alert' AND pd.doctor_id=?""",
            (alert_id, g.user["entity_id"]),
        ).fetchone()
        if not row:
            return jsonify({"error":"Сигнал не найден"}),404
        if row["status"] != "resolved":
            db.execute("UPDATE secure_records SET status='resolved' WHERE id=?", (alert_id,))
            doctor = db.execute("SELECT name FROM doctors WHERE id=?", (g.user["entity_id"],)).fetchone()
            insert_secure(db, row["patient_id"], "alert_event", {
                "alert_id": alert_id, "action": "resolved", "doctor_id": g.user["entity_id"],
                "doctor_name": doctor["name"], "note": note,
            })
        return jsonify({"id":alert_id,"status":"resolved"})


@app.post("/api/doctor/alerts/<int:alert_id>/acknowledge")
@require_auth("doctor")
def acknowledge_alert(alert_id):
    with get_db() as db:
        row = db.execute(
            """SELECT sr.* FROM secure_records sr
               JOIN patient_doctors pd ON pd.patient_id=sr.patient_id
               WHERE sr.id=? AND sr.record_type='alert' AND pd.doctor_id=?""",
            (alert_id, g.user["entity_id"]),
        ).fetchone()
        if not row:
            return jsonify({"error":"Сигнал не найден"}),404
        if row["status"] == "new":
            db.execute("UPDATE secure_records SET status='acknowledged' WHERE id=?", (alert_id,))
            doctor = db.execute("SELECT name FROM doctors WHERE id=?", (g.user["entity_id"],)).fetchone()
            insert_secure(db, row["patient_id"], "alert_event", {
                "alert_id": alert_id, "action": "acknowledged", "doctor_id": g.user["entity_id"],
                "doctor_name": doctor["name"], "note": "Сигнал принят в работу",
            })
        return jsonify({"id":alert_id,"status":"acknowledged"})


@app.get("/api/patient/home")
@require_auth("patient")
def patient_home():
    with get_db() as db:
        patient = patient_summary(db, g.user["entity_id"])
        patient["checked_in_today"] = any(item["created_at"].startswith(date.today().isoformat()) for item in patient["checkins"])
        return jsonify(patient)


@app.post("/api/patient/consents")
@require_auth("patient")
def accept_patient_consents():
    payload = request.get_json(silent=True) or {}
    patient_id = g.user["entity_id"]
    with get_db() as db:
        profile = latest(db, patient_id, "profile")
        if not profile:
            return jsonify({"error":"Профиль пациента не найден"}),404
        try:
            birth_date = date.fromisoformat(profile["birth_date"])
        except (KeyError, ValueError):
            return jsonify({"error":"В профиле не указана корректная дата рождения"}),400
        document, error = validate_consent(payload, birth_date)
        if error:
            return jsonify({"error":error}),400
        db.execute("UPDATE secure_records SET status='superseded' WHERE patient_id=? AND record_type='consent' AND status='active'", (patient_id,))
        record_id = insert_secure(db, patient_id, "consent", document, status="active")
        insert_secure(db, patient_id, "consent_event", {"consent_id":record_id,"action":"accepted","version":LEGAL_DOCUMENT_VERSION})
        return jsonify({"id":record_id,"status":"active","version":LEGAL_DOCUMENT_VERSION}),201


@app.post("/api/patient/consents/withdraw")
@require_auth("patient")
def withdraw_patient_consents():
    payload = request.get_json(silent=True) or {}
    if str(payload.get("confirmation", "")).strip().upper() != "ОТОЗВАТЬ":
        return jsonify({"error":"Введите слово ОТОЗВАТЬ для подтверждения"}),400
    patient_id = g.user["entity_id"]
    with get_db() as db:
        row = db.execute("SELECT * FROM secure_records WHERE patient_id=? AND record_type='consent' AND status='active' ORDER BY id DESC LIMIT 1", (patient_id,)).fetchone()
        if not row:
            return jsonify({"error":"Действующее согласие не найдено"}),404
        db.execute("UPDATE secure_records SET status='withdrawn' WHERE id=?", (row["id"],))
        insert_secure(db, patient_id, "consent_event", {
            "consent_id":row["id"], "action":"withdrawn", "requested_at":datetime.now(MOSCOW_TZ).isoformat(timespec="seconds"),
            "notice":"Отзыв зарегистрирован. Оператор должен определить применимые сроки блокирования, удаления и обязательного хранения.",
        })
        return jsonify({"status":"withdrawn","message":"Отзыв зарегистрирован. Для удаления данных оператор проверит обязательные сроки хранения."})


@app.patch("/api/doctor/profile")
@require_auth("doctor")
def update_doctor_profile():
    payload = request.get_json(silent=True) or {}
    allowed = {"name", "specialty", "experience", "clinic", "price", "about"}
    values = {key: payload[key] for key in allowed if key in payload}
    if not values:
        return jsonify({"error":"Нет данных для обновления"}),400
    if "name" in values and len(str(values["name"]).strip()) < 2:
        return jsonify({"error":"Укажите имя"}),400
    try:
        if "experience" in values: values["experience"] = max(0, int(values["experience"]))
        if "price" in values: values["price"] = max(2500, int(values["price"] or 2500))
    except (TypeError, ValueError):
        return jsonify({"error":"Стаж и цена должны быть числами"}),400
    with get_db() as db:
        assignments = ",".join(f"{key}=?" for key in values)
        db.execute(f"UPDATE doctors SET {assignments} WHERE id=?", (*values.values(),g.user["entity_id"]))
        doctor = db.execute("SELECT * FROM doctors WHERE id=?", (g.user["entity_id"],)).fetchone()
        return jsonify(dict(doctor))


@app.get("/api/schedule/doctor/<int:doctor_id>")
@require_auth()
def schedule(doctor_id):
    with get_db() as db:
        if not db.execute("SELECT id FROM doctors WHERE id=?", (doctor_id,)).fetchone():
            return jsonify({"error":"Врач не найден"}),404
        flat = available_slots(db,doctor_id,7)
        days=[]
        for day in sorted({item["date"] for item in flat}):
            slots=[]
            for item in [slot for slot in flat if slot["date"]==day]:
                booked = db.execute("SELECT patient_id,appointment_record_id FROM appointment_slots WHERE doctor_id=? AND appointment_date=? AND appointment_time=?",(doctor_id,day,item["time"])).fetchone()
                slot=dict(item)
                if booked and g.user["role"]=="doctor" and g.user["entity_id"]==doctor_id:
                    profile=latest(db,booked["patient_id"],"profile")
                    slot["patient_name"]=profile["full_name"]
                    slot["patient_id"]=booked["patient_id"]
                    slot["appointment_id"]=booked["appointment_record_id"]
                    appointment_row=db.execute("SELECT status FROM secure_records WHERE id=?",(booked["appointment_record_id"],)).fetchone()
                    slot["status"]=appointment_row["status"] if appointment_row else "confirmed"
                slots.append(slot)
            days.append({"date":day,"slots":slots})
        return jsonify({"doctor_id":doctor_id,"days":days})


@app.post("/api/appointments")
@require_auth()
def add_appointment():
    payload=request.get_json(silent=True) or {}
    doctor_id=int(payload.get("doctor_id",0)); patient_id=int(payload.get("patient_id",0))
    target=str(payload.get("date","")); time=str(payload.get("time",""))
    if time not in SLOTS:
        return jsonify({"error":"Недопустимый временной слот"}),400
    try:
        if date.fromisoformat(target) <= date.today():
            return jsonify({"error":"Выберите будущую дату"}),400
    except ValueError:
        return jsonify({"error":"Некорректная дата"}),400
    if g.user["role"]=="patient" and g.user["entity_id"]!=patient_id:
        return jsonify({"error":"Нельзя записать другого пациента"}),403
    with get_db() as db:
        patient=db.execute("SELECT * FROM patients WHERE id=?",(patient_id,)).fetchone()
        if not patient or (g.user["role"]=="doctor" and g.user["entity_id"]!=doctor_id):
            return jsonify({"error":"Нет доступа к этой записи"}),403
        if g.user["role"]=="doctor" and not db.execute("SELECT 1 FROM patient_doctors WHERE patient_id=? AND doctor_id=?",(patient_id,doctor_id)).fetchone():
            return jsonify({"error":"Пациент ещё не обращался к вам"}),403
        doctor=db.execute("SELECT name FROM doctors WHERE id=?",(doctor_id,)).fetchone()
        if not doctor:
            return jsonify({"error":"Врач не найден"}),404
        status = "pending_patient" if g.user["role"]=="doctor" else "confirmed"
        try:
            record_id=insert_secure(db,patient_id,"appointment",{"doctor_id":doctor_id,"doctor_name":doctor["name"],"date":target,"time":time,"format":payload.get("format","Онлайн"),"reason":payload.get("reason","Консультация"),"created_by":g.user["role"]},status=status)
            db.execute("INSERT INTO appointment_slots(doctor_id,patient_id,appointment_record_id,appointment_date,appointment_time) VALUES(?,?,?,?,?)",(doctor_id,patient_id,record_id,target,time))
            db.execute("INSERT OR IGNORE INTO patient_doctors(patient_id,doctor_id,created_at) VALUES(?,?,?)",(patient_id,doctor_id,datetime.now().isoformat(timespec="seconds")))
        except sqlite3.IntegrityError:
            db.rollback()
            return jsonify({"error":"Этот слот уже занят. Выберите другое время."}),409
        return jsonify({"id":record_id,"status":status}),201


@app.post("/api/appointments/<int:appointment_id>/confirm")
@require_auth("patient")
def confirm_appointment(appointment_id):
    patient_id = g.user["entity_id"]
    with get_db() as db:
        row = db.execute("SELECT * FROM secure_records WHERE id=? AND patient_id=? AND record_type='appointment'",(appointment_id,patient_id)).fetchone()
        if not row:
            return jsonify({"error":"Приём не найден"}),404
        if row["status"] != "pending_patient":
            return jsonify({"error":"Приём уже подтверждён"}),409
        item=decrypt_record(row)
        db.execute("UPDATE secure_records SET status='confirmed' WHERE id=?",(appointment_id,))
        insert_secure(db,patient_id,"appointment_event",{"appointment_id":appointment_id,"action":"confirmed","actor":"patient","doctor_id":item["doctor_id"],"doctor_name":item["doctor_name"],"date":item["date"],"time":item["time"]})
        return jsonify({"id":appointment_id,"status":"confirmed"})


def change_appointment_status(appointment_id, target_status, patient_only=False):
    with get_db() as db:
        row=db.execute("SELECT * FROM secure_records WHERE id=? AND record_type='appointment'",(appointment_id,)).fetchone()
        if not row: return jsonify({"error":"Приём не найден"}),404
        item=decrypt_record(row)
        is_patient=g.user["role"]=="patient" and g.user["entity_id"]==row["patient_id"]
        is_doctor=g.user["role"]=="doctor" and g.user["entity_id"]==item.get("doctor_id")
        if not is_patient and (patient_only or not is_doctor): return jsonify({"error":"Нет доступа к приёму"}),403
        if row["status"] in {"cancelled","declined"}: return jsonify({"error":"Приём уже отменён"}),409
        if target_status=="declined" and row["status"]!="pending_patient": return jsonify({"error":"Отказ доступен только для неподтверждённого приёма"}),409
        db.execute("UPDATE secure_records SET status=? WHERE id=?",(target_status,appointment_id))
        db.execute("DELETE FROM appointment_slots WHERE appointment_record_id=?",(appointment_id,))
        insert_secure(db,row["patient_id"],"appointment_event",{"appointment_id":appointment_id,"action":target_status,"actor":g.user["role"],"doctor_id":item["doctor_id"],"doctor_name":item["doctor_name"],"date":item["date"],"time":item["time"]})
        return jsonify({"id":appointment_id,"status":target_status})


@app.post("/api/appointments/<int:appointment_id>/cancel")
@require_auth()
def cancel_appointment(appointment_id):
    return change_appointment_status(appointment_id,"cancelled")


@app.post("/api/appointments/<int:appointment_id>/decline")
@require_auth("patient")
def decline_appointment(appointment_id):
    return change_appointment_status(appointment_id,"declined",patient_only=True)


@app.get("/api/chat/<int:patient_id>")
@require_auth()
def get_chat(patient_id):
    with get_db() as db:
        doctor_id = g.user["entity_id"] if g.user["role"]=="doctor" else request.args.get("doctor_id",type=int)
        patient=db.execute("SELECT * FROM patients WHERE id=?",(patient_id,)).fetchone()
        linked = doctor_id and db.execute("SELECT 1 FROM patient_doctors WHERE patient_id=? AND doctor_id=?",(patient_id,doctor_id)).fetchone()
        if not patient or not linked or (g.user["role"]=="patient" and g.user["entity_id"]!=patient_id):
            return jsonify({"error":"Нет доступа к чату"}),403
        return jsonify([item for item in records(db,patient_id,"message") if item.get("doctor_id")==doctor_id])


@app.post("/api/chat/<int:patient_id>")
@require_auth()
def post_chat(patient_id):
    payload=request.get_json(silent=True) or {}; body=str(payload.get("body","")).strip()
    if not body:
        return jsonify({"error":"Введите сообщение"}),400
    with get_db() as db:
        doctor_id = g.user["entity_id"] if g.user["role"]=="doctor" else int(payload.get("doctor_id",0))
        patient=db.execute("SELECT * FROM patients WHERE id=?",(patient_id,)).fetchone()
        linked = doctor_id and db.execute("SELECT 1 FROM patient_doctors WHERE patient_id=? AND doctor_id=?",(patient_id,doctor_id)).fetchone()
        if not patient or not linked or (g.user["role"]=="patient" and g.user["entity_id"]!=patient_id):
            return jsonify({"error":"Нет доступа к чату"}),403
        record_id=insert_secure(db,patient_id,"message",{"sender":g.user["role"],"body":body,"doctor_id":doctor_id})
        return jsonify({"id":record_id,"status":"sent"}),201


def notification_items(db, user):
    patient_ids=[user["entity_id"]] if user["role"]=="patient" else [row[0] for row in db.execute("SELECT patient_id FROM patient_doctors WHERE doctor_id=?",(user["entity_id"],)).fetchall()]
    read={row[0] for row in db.execute("SELECT event_key FROM notification_reads WHERE user_id=?",(user["id"],)).fetchall()}
    output=[]
    for patient_id in patient_ids:
        profile=latest(db,patient_id,"profile")
        if not profile: continue
        if user["role"]=="doctor":
            for item in records(db,patient_id,"alert",True):
                if item["title"]!="Жалоба на переносимость": output.append({"key":f"alert:{item['id']}","title":item["title"],"text":f"{profile['full_name']}: {item['description']}","created_at":item["created_at"]})
            for item in records(db,patient_id,"message",True):
                if item["sender"]=="patient" and item.get("doctor_id")==user["entity_id"]: output.append({"key":f"message:{item['id']}","title":"Новое сообщение","text":f"{profile['full_name']}: {item['body']}","created_at":item["created_at"]})
            for item in records(db,patient_id,"side_effect",True):
                output.append({"key":f"side_effect:{item['id']}","title":"Новая жалоба на побочный эффект","text":f"{profile['full_name']}: {item['text']}","created_at":item["created_at"]})
            for item in records(db,patient_id,"appointment",True):
                if item.get("doctor_id")==user["entity_id"] and item.get("created_by")=="patient" and item.get("status") not in {"cancelled","declined"}:
                    output.append({"key":f"appointment:{item['id']}","title":"Новая запись пациента","text":f"{profile['full_name']}: {item['date']} в {item['time']}","created_at":item["created_at"]})
            for item in records(db,patient_id,"appointment_event",True):
                if item.get("doctor_id")!=user["entity_id"] or item.get("actor")!="patient": continue
                title="Пациент подтвердил приём" if item["action"]=="confirmed" else "Пациент отказался от приёма" if item["action"]=="declined" else "Пациент отменил запись"
                output.append({"key":f"appointment_event:{item['id']}","title":title,"text":f"{profile['full_name']}: {item['date']} в {item['time']}","created_at":item["created_at"]})
        else:
            for item in records(db,patient_id,"message",True):
                if item["sender"]=="doctor": output.append({"key":f"message:{item['id']}","title":"Сообщение врача","text":item["body"],"created_at":item["created_at"]})
            for item in records(db,patient_id,"appointment",True):
                if item.get("status") in {"cancelled","declined"}: continue
                title = "Подтвердите приём" if item.get("status")=="pending_patient" else "Запись подтверждена"
                output.append({"key":f"appointment:{item['id']}","title":title,"text":f"{item['doctor_name']}: {item['date']} в {item['time']}","created_at":item["created_at"]})
                if item.get("status")=="pending_patient":
                    try:
                        appointment_at=datetime.fromisoformat(f"{item['date']}T{item['time']}:00").replace(tzinfo=MOSCOW_TZ)
                        reminder_at=appointment_at-timedelta(days=1)
                        if reminder_at <= datetime.now(MOSCOW_TZ) < appointment_at:
                            output.append({
                                "key":f"appointment_reminder:{item['id']}:{item['date']}",
                                "title":"Приём меньше чем через сутки",
                                "text":f"Подтвердите запись к {item['doctor_name']}: {item['date']} в {item['time']}",
                                "created_at":reminder_at.isoformat(timespec="seconds"),
                            })
                    except (KeyError, TypeError, ValueError):
                        pass
            for item in records(db,patient_id,"appointment_event",True):
                if item.get("actor")!="doctor": continue
                output.append({"key":f"appointment_event:{item['id']}","title":"Врач отменил приём","text":f"{item['doctor_name']}: {item['date']} в {item['time']}","created_at":item["created_at"]})
    for item in output: item["read"]=item["key"] in read
    return sorted(output,key=lambda x:x["created_at"],reverse=True)[:30]


@app.get("/api/notifications")
@require_auth()
def notifications():
    with get_db() as db: return jsonify(notification_items(db,g.user))


@app.post("/api/notifications/read")
@require_auth()
def read_notifications():
    keys=(request.get_json(silent=True) or {}).get("keys",[])
    now=datetime.now().isoformat(timespec="seconds")
    with get_db() as db:
        db.executemany("INSERT OR REPLACE INTO notification_reads(user_id,event_key,read_at) VALUES(?,?,?)",[(g.user["id"],key,now) for key in keys])
    return jsonify({"status":"read"})


@app.post("/api/patient/checkins")
@require_auth("patient")
def checkin():
    payload=request.get_json(silent=True) or {}
    try: mood,anxiety,sleep=int(payload["mood"]),int(payload["anxiety"]),float(payload["sleep"])
    except (KeyError,ValueError,TypeError): return jsonify({"error":"Проверьте значения"}),400
    if not (0 <= mood <= 10 and 0 <= anxiety <= 10 and 0 <= sleep <= 24):
        return jsonify({"error":"Настроение и тревога — от 0 до 10, сон — от 0 до 24 часов"}),400
    safety_fields=("immediate_danger","recent_self_harm","self_harm_thoughts","suicide_plan","means_access","sudden_worsening","severe_physical_symptoms")
    if any(not isinstance(payload.get(key), bool) for key in safety_fields):
        return jsonify({"error":"Ответьте «да» или «нет» на все вопросы безопасности"}),400
    patient_id=g.user["entity_id"]
    with get_db() as db:
        previous_checkin=latest(db,patient_id,"checkin")
        risk=evaluate_safety_risk(payload,previous_checkin)
        safety_answers=risk.pop("answers")
        record_id=insert_secure(db,patient_id,"checkin",{"mood":mood,"anxiety":anxiety,"sleep":sleep,"medication_taken":bool(payload.get("medication_taken")),"side_effects":str(payload.get("side_effects","Нет")),"note":str(payload.get("note","")),"safety":safety_answers,"risk_level":risk["level"],"risk_ruleset":risk["ruleset_version"],"scale_version":2})
        stats=db.execute("SELECT * FROM patient_stats WHERE patient_id=?",(patient_id,)).fetchone()
        today=date.today(); awarded=0
        if not stats or stats["last_checkin_date"] != today.isoformat():
            last=date.fromisoformat(stats["last_checkin_date"]) if stats and stats["last_checkin_date"] else None
            streak=(stats["streak"]+1) if last==today-timedelta(days=1) else 1
            db.execute("INSERT INTO patient_stats(patient_id,points,streak,last_checkin_date) VALUES(?,?,?,?) ON CONFLICT(patient_id) DO UPDATE SET points=points+20,streak=excluded.streak,last_checkin_date=excluded.last_checkin_date",(patient_id,20,streak,today.isoformat()))
            awarded=20
        alert_id=None
        if risk["level"] != "none":
            titles={"critical":"Критический сигнал безопасности","urgent":"Требуется срочная оценка","observation":"Нужно наблюдение"}
            alert_id=insert_secure(db,patient_id,"alert",{
                "title":titles[risk["level"]], "description":"; ".join(risk["reasons"]),
                "recommendation":risk["recommendation"], "rule_codes":risk["rule_codes"],
                "ruleset_version":risk["ruleset_version"], "source_record_id":record_id,
            },severity=risk["level"],status="new")
        recipient_count=db.execute("SELECT count(*) FROM patient_doctors WHERE patient_id=?",(patient_id,)).fetchone()[0]
        total=db.execute("SELECT points FROM patient_stats WHERE patient_id=?",(patient_id,)).fetchone()[0]
        return jsonify({"id":record_id,"status":"saved","points_awarded":awarded,"total_points":total,"risk":risk,"alert_id":alert_id,"notified_doctors":recipient_count}),201


@app.post("/api/patient/assessment")
@require_auth("patient")
def assessment():
    answers=(request.get_json(silent=True) or {}).get("answers")
    try: answers=[int(item) for item in answers]
    except (TypeError,ValueError): return jsonify({"error":"Нужно 7 ответов"}),400
    if len(answers)!=7 or any(item not in range(4) for item in answers): return jsonify({"error":"Каждый ответ должен быть от 0 до 3"}),400
    score=sum(answers); level="Минимальный" if score<=4 else "Умеренный" if score<=9 else "Средний" if score<=14 else "Высокий"
    patient_id=g.user["entity_id"]
    with get_db() as db:
        first=not db.execute("SELECT 1 FROM secure_records WHERE patient_id=? AND record_type='assessment'",(patient_id,)).fetchone()
        record_id=insert_secure(db,patient_id,"assessment",{"scale":"GAD-7","answers":answers,"score":score,"level":level})
        if first: db.execute("UPDATE patient_stats SET points=points+50 WHERE patient_id=?",(patient_id,))
    return jsonify({"id":record_id,"score":score,"level":level,"points_awarded":50 if first else 0,"message":"Скрининг не является диагнозом."}),201


@app.post("/api/doctor/patients/<int:patient_id>/prescriptions")
@require_auth("doctor")
def prescribe(patient_id):
    payload=request.get_json(silent=True) or {}
    doctor_id=g.user["entity_id"]
    try: medicine_id=int(payload.get("medicine_id",0))
    except (TypeError,ValueError): return jsonify({"error":"Выберите препарат"}),400
    dose=str(payload.get("dose","")).strip(); frequency=str(payload.get("frequency","")).strip()
    if not dose or not frequency: return jsonify({"error":"Укажите дозировку и режим приёма"}),400
    with get_db() as db:
        if not db.execute("SELECT 1 FROM patient_doctors WHERE patient_id=? AND doctor_id=?",(patient_id,doctor_id)).fetchone():
            return jsonify({"error":"Нет доступа к пациенту"}),403
        medicine=db.execute("SELECT * FROM medicines WHERE id=?",(medicine_id,)).fetchone()
        doctor=db.execute("SELECT name FROM doctors WHERE id=?",(doctor_id,)).fetchone()
        if not medicine: return jsonify({"error":"Препарат не найден"}),404
        document={"medicine_id":medicine_id,"name":medicine["name"],"ingredient":medicine["ingredient"],"dose":dose,"frequency":frequency,
            "doctor_id":doctor_id,"doctor_name":doctor["name"],"started_at":date.today().isoformat(),
            "common_effects":medicine["common_effects"].split("|"),"urgent_effects":medicine["urgent_effects"].split("|"),"monitoring":medicine["monitoring"]}
        record_id=insert_secure(db,patient_id,"prescription",document,status="active")
        return jsonify(document|{"id":record_id,"status":"active"}),201


@app.post("/api/doctor/patients/<int:patient_id>/diagnoses")
@require_auth("doctor")
def add_diagnoses(patient_id):
    payload = request.get_json(silent=True) or {}
    submitted = payload.get("diagnoses")
    if not isinstance(submitted, list) or not submitted or len(submitted) > 10:
        return jsonify({"error":"Добавьте от одного до десяти диагнозов"}),400
    diagnoses = []
    for item in submitted:
        if not isinstance(item, dict):
            return jsonify({"error":"Проверьте список диагнозов"}),400
        name = str(item.get("name", "")).strip()
        note = str(item.get("note", "")).strip()
        if len(name) < 2 or len(name) > 200:
            return jsonify({"error":"Название диагноза должно содержать от 2 до 200 символов"}),400
        if len(note) > 1000:
            return jsonify({"error":"Комментарий должен быть короче 1000 символов"}),400
        diagnoses.append({"name":name, "note":note})
    doctor_id = g.user["entity_id"]
    with get_db() as db:
        linked = db.execute(
            "SELECT 1 FROM patient_doctors WHERE patient_id=? AND doctor_id=?",
            (patient_id, doctor_id),
        ).fetchone()
        if not linked:
            return jsonify({"error":"Нет доступа к пациенту"}),403
        doctor = db.execute("SELECT name,specialty FROM doctors WHERE id=?", (doctor_id,)).fetchone()
        created = []
        for item in diagnoses:
            document = item | {
                "doctor_id":doctor_id,
                "doctor_name":doctor["name"],
                "doctor_specialty":doctor["specialty"],
            }
            record_id = insert_secure(db, patient_id, "diagnosis", document, status="active")
            created.append(document | {"id":record_id, "status":"active"})
        return jsonify({"diagnoses":created}),201


@app.post("/api/patient/side-effects")
@require_auth("patient")
def side_effect():
    payload=request.get_json(silent=True) or {}; text=str(payload.get("text","")).strip(); severity=payload.get("severity","mild")
    if not text: return jsonify({"error":"Опишите жалобу"}),400
    with get_db() as db:
        record_id=insert_secure(db,g.user["entity_id"],"side_effect",{"text":text,"medicine":payload.get("medicine","Не указан")},severity=severity,status="new")
        if severity!="mild": insert_secure(db,g.user["entity_id"],"alert",{"title":"Жалоба на переносимость","description":text,"recommendation":"Оценить связь с лечением."},severity="critical" if severity=="critical" else "attention",status="new")
    return jsonify({"id":record_id,"status":"sent"}),201


@app.get("/api/medicines")
def medicines():
    with get_db() as db:
        output=[]
        for row in db.execute("SELECT * FROM medicines ORDER BY name").fetchall():
            item=dict(row); item["common_effects"]=item["common_effects"].split("|"); item["urgent_effects"]=item["urgent_effects"].split("|"); item["contraindications"]=[value for value in item["contraindications"].split("|") if value]; output.append(item)
        return jsonify(output)


create_schema()

if __name__=="__main__": app.run(host="0.0.0.0",port=5000,debug=True)
